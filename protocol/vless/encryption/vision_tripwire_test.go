package encryption

import (
	"bytes"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The CI-visible tripwire for the Vision private ABI.
//
// vision.go reaches into sing-vmess's UNEXPORTED vless.tlsRegistry with
// //go:linkname and drives its reflection-based field access; Vision then reads
// CommonConn's `input` and `rawInput` fields by NAME and by OFFSET
// (`unsafe.Pointer(reflectPointer + field.Offset)`). Nothing in the compiler or
// the runtime checks that contract across a module boundary. A sing-vmess bump
// can therefore produce (a) a bare linker error, (b) a func value called through
// the wrong signature, or (c) — the dangerous one — Vision reading or writing
// unrelated memory with no error at all, because a renamed field reflects as a
// zero StructField whose Offset is 0.
//
// These tests are deliberately several small checks instead of one clever one,
// so a failure names the input that moved. Every failure carries the same
// instruction after the specific complaint.
const (
	singVMessModulePath = "github.com/sagernet/sing-vmess"

	// repoGoMod is reached from this package directory. `go test` runs the test
	// binary with the package directory as its working directory, the same
	// assumption protocol/tun's consumer-contract test makes.
	repoGoMod = "../../../go.mod"

	// visionAuditInstruction is appended to every failure here. A maintainer who
	// bumps sing-vmess without reading this file should be told what to do by the
	// test output alone.
	visionAuditInstruction = "sing-vmess changed; re-audit the Vision encryption bridge before updating this dependency: " +
		"check protocol/vless/encryption/vision.go (the go:linkname pull of vless.tlsRegistry and its callback signature) " +
		"and protocol/vless/encryption/common.go (the CommonConn input/rawInput field names, types and offsets Vision reflects). " +
		"Re-run TestVisionTripwire and TestVisionAcceptsCommonConn against the new version, then update expectedSingVMessVersion " +
		"and this tripwire deliberately."
)

// TestVisionTripwireSingVMessVersion pins the dependency itself: the version
// recorded in expectedSingVMessVersion must be the version go.mod requires, and
// the module must not be replaced. It reads go.mod rather than
// runtime/debug.ReadBuildInfo because a test binary for a non-main package
// carries no dependency list in its build info (verified: Deps is empty), so the
// go.mod pin is the only place the version of the build under test is visible
// from inside a test.
//
// This check is what makes a dependency bump a deliberate act. `go get
// github.com/sagernet/sing-vmess@latest` alone turns CI red here.
func TestVisionTripwireSingVMessVersion(t *testing.T) {
	t.Parallel()

	goMod, err := os.ReadFile(repoGoMod)
	require.NoError(t, err, "cannot read go.mod to verify the sing-vmess pin; "+visionAuditInstruction)

	version, replacement := parseGoModSingVMessPin(t, string(goMod))
	require.Empty(t, replacement, "sing-vmess is replaced by "+replacement+
		"; the Vision ABI is audited against the module version required by go.mod only; "+visionAuditInstruction)
	require.Equal(t, expectedSingVMessVersion, version, visionAuditInstruction)
}

// parseGoModSingVMessPin extracts the require version of singVMessModulePath and
// any replace directive for it. It handles both the block form and the
// single-line form; comments are stripped first so an inline `// indirect`
// marker cannot be mistaken for the version.
func parseGoModSingVMessPin(t *testing.T, goMod string) (version, replacement string) {
	t.Helper()

	block := ""
	for _, rawLine := range strings.Split(goMod, "\n") {
		if comment := strings.Index(rawLine, "//"); comment >= 0 {
			rawLine = rawLine[:comment]
		}
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			fields := strings.Fields(line)
			switch block {
			case "require":
				if len(fields) >= 2 && fields[0] == singVMessModulePath {
					version = fields[1]
				}
			case "replace":
				if fields[0] == singVMessModulePath {
					replacement = line
				}
			}
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "require", "replace":
			if len(fields) >= 2 && fields[1] == "(" {
				block = fields[0]
				continue
			}
			if fields[0] == "require" && len(fields) >= 3 && fields[1] == singVMessModulePath {
				version = fields[2]
			}
			if fields[0] == "replace" && len(fields) >= 4 && fields[1] == singVMessModulePath {
				replacement = strings.TrimSpace(strings.TrimPrefix(line, "replace"))
			}
		}
	}
	require.NotEmpty(t, version, "go.mod does not require "+singVMessModulePath+"; "+visionAuditInstruction)
	return version, replacement
}

// singVMessModuleDir locates the pinned sing-vmess source in the module cache.
// If the cache does not hold it the source-shape test below is skipped rather
// than failed — but the runtime behaviour test and the CommonConn ABI test still
// run, so a missing cache weakens the tripwire without silencing it.
func singVMessModuleDir(t *testing.T) string {
	t.Helper()

	goMod, err := os.ReadFile(repoGoMod)
	require.NoError(t, err, "cannot read go.mod to locate the pinned sing-vmess source; "+visionAuditInstruction)
	version, replacement := parseGoModSingVMessPin(t, string(goMod))
	require.Empty(t, replacement, "sing-vmess is replaced by "+replacement+"; "+visionAuditInstruction)

	roots := []string{}
	if moduleCache := os.Getenv("GOMODCACHE"); moduleCache != "" {
		roots = append(roots, moduleCache)
	}
	if build.Default.GOPATH != "" {
		roots = append(roots, filepath.Join(build.Default.GOPATH, "pkg", "mod"))
	}
	for _, root := range roots {
		dir := filepath.Join(root, "github.com", "sagernet", "sing-vmess@"+version)
		if _, statErr := os.Stat(dir); statErr == nil {
			return dir
		}
	}
	t.Skipf("the pinned sing-vmess source is not in the module cache (%v); the runtime tripwire checks still run, "+
		"but the source-shape check is skipped", roots)
	return ""
}

// TestVisionTripwireDependencySourceShape reads the pinned dependency's own
// source and asserts the exact declaration and the exact reflective lookups this
// bridge depends on. The runtime tests can only observe what a wrong signature
// or a missing field does when it is CALLED; this check names the broken
// declaration directly, and it catches a changed field name even when the
// resulting memory access happens to be harmless.
//
// It is a text/AST check on a pinned version on purpose: there is no exported
// Go API that exposes an unexported package variable's declaration, and this is
// the same technique protocol/tun's consumer-contract test uses for sing-tun.
func TestVisionTripwireDependencySourceShape(t *testing.T) {
	t.Parallel()

	sourcePath := filepath.Join(singVMessModuleDir(t), "vless", "vision.go")
	source, err := os.ReadFile(sourcePath)
	require.NoError(t, err, "cannot read the pinned sing-vmess vless/vision.go; "+visionAuditInstruction)

	fileSet := token.NewFileSet()
	parsed, parseErr := parser.ParseFile(fileSet, sourcePath, source, parser.SkipObjectResolution)
	require.NoError(t, parseErr, "cannot parse the pinned sing-vmess vless/vision.go; "+visionAuditInstruction)

	// 1. The registry variable and its exact declared type, whitespace-normalised.
	declaredType := ""
	ast.Inspect(parsed, func(node ast.Node) bool {
		declaration, ok := node.(*ast.GenDecl)
		if !ok || declaration.Tok != token.VAR {
			return true
		}
		for _, specification := range declaration.Specs {
			valueSpec, ok := specification.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range valueSpec.Names {
				if name.Name != "tlsRegistry" || valueSpec.Type == nil {
					continue
				}
				expression := valueSpec.Type
				declaredType = normaliseSpace(string(source[fileSet.Position(expression.Pos()).Offset:fileSet.Position(expression.End()).Offset]))
			}
		}
		return true
	})
	require.Equal(t,
		normaliseSpace("[]func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)"),
		declaredType,
		"sing-vmess vless.tlsRegistry's declaration changed; the go:linkname pull in vision.go must be re-declared to match; "+visionAuditInstruction)

	// 2. The field names Vision reflects. A rename here is the silent failure
	// mode: reflect.FieldByName returns a zero StructField with Offset 0 and
	// Vision reads the wrong memory without an error.
	reflectedFields := map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "FieldByName" || len(call.Args) != 1 {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		name, unquoteErr := strconv.Unquote(literal.Value)
		if unquoteErr == nil {
			reflectedFields[name] = true
		}
		return true
	})
	require.True(t, reflectedFields["input"],
		"sing-vmess Vision no longer reflects CommonConn.input by that name; the field in common.go was renamed or Vision now looks elsewhere; "+visionAuditInstruction)
	require.True(t, reflectedFields["rawInput"],
		"sing-vmess Vision no longer reflects CommonConn.rawInput by that name; the field in common.go was renamed or Vision now looks elsewhere; "+visionAuditInstruction)

	// 3. The exact reinterpretation of those two fields. The pointer type on
	// each cast is the field type CommonConn must keep, at the offset Vision
	// derives from the reflect metadata.
	normalisedSource := normaliseSpace(string(source))
	require.Contains(t, normalisedSource, "(*bytes.Reader)(unsafe.Pointer(reflectPointer + input.Offset))",
		"sing-vmess Vision no longer casts the input offset to *bytes.Reader; "+visionAuditInstruction)
	require.Contains(t, normalisedSource, "(*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInput.Offset))",
		"sing-vmess Vision no longer casts the rawInput offset to *bytes.Buffer; "+visionAuditInstruction)

	// 4. The registry must still be populated by the dependency's own init and
	// iterated by NewVisionConn; an empty or unused slice would make our
	// appended entry unreachable while every other check still passed.
	require.Contains(t, normalisedSource, "tlsRegistry = append(tlsRegistry,",
		"sing-vmess Vision no longer appends its built-in entries to tlsRegistry; "+visionAuditInstruction)
	require.Contains(t, normalisedSource, "for _, tlsCreator := range tlsRegistry {",
		"sing-vmess NewVisionConn no longer iterates tlsRegistry; "+visionAuditInstruction)
}

// normaliseSpace collapses every run of whitespace to one space and trims the
// ends, so a source check does not depend on the dependency's formatting.
func normaliseSpace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// visionRegistrySignature is a second, independent declaration of the callback
// shape sing-vmess vless.tlsRegistry is declared with. It is an UNNAMED func
// type: Go type identity makes two unnamed func types with identical structure
// the same type, so this compares equal to the linkname declaration's element
// type only while the signatures really match.
var visionRegistrySignature = reflect.TypeOf((func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr))(nil))

// TestVisionTripwireRegistryShape pins the shape of the linked registry: that it
// exists (the go:linkname pull resolved, which is really a link-time assertion —
// see the note in vision.go), that it is a slice of the expected callback type,
// and that the callback signature matches position by position so a failure
// names the parameter or result that moved.
func TestVisionTripwireRegistryShape(t *testing.T) {
	t.Parallel()

	require.NotNil(t, visionTLSRegistry, "the linked vless.tlsRegistry is nil, so the go:linkname pull no longer reaches the dependency's storage; "+visionAuditInstruction)

	registryType := reflect.TypeOf(visionTLSRegistry)
	require.Equal(t, reflect.Slice, registryType.Kind(), "vless.tlsRegistry is no longer a slice; "+visionAuditInstruction)

	signature := registryType.Elem()
	require.Equal(t, visionRegistrySignature, signature,
		"vless.tlsRegistry's element type is no longer the callback shape this package declares; "+visionAuditInstruction)
	require.Equal(t, reflect.Func, signature.Kind(), "vless.tlsRegistry does not hold functions; "+visionAuditInstruction)

	require.Equal(t, 1, signature.NumIn(),
		"vless.tlsRegistry's callback no longer takes exactly one argument; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf((*net.Conn)(nil)).Elem(), signature.In(0),
		"vless.tlsRegistry's callback argument is no longer net.Conn; "+visionAuditInstruction)

	require.Equal(t, 4, signature.NumOut(),
		"vless.tlsRegistry's callback no longer returns four values; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf(false), signature.Out(0),
		"vless.tlsRegistry's callback result 0 is no longer bool loaded; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf((*net.Conn)(nil)).Elem(), signature.Out(1),
		"vless.tlsRegistry's callback result 1 is no longer net.Conn; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf((*reflect.Type)(nil)).Elem(), signature.Out(2),
		"vless.tlsRegistry's callback result 2 is no longer reflect.Type; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf(uintptr(0)), signature.Out(3),
		"vless.tlsRegistry's callback result 3 is no longer uintptr; "+visionAuditInstruction)

	// The built-in crypto/tls entry is registered by the dependency's own init,
	// and utls adds a second under with_utls. Fewer than two means the slice this
	// package appends to is not the dependency's registry any more.
	require.GreaterOrEqual(t, len(visionTLSRegistry), 2,
		"the linked vless.tlsRegistry lost the dependency's built-in entries; "+visionAuditInstruction)
}

// TestVisionTripwireRegistryEntryBehaviour drives this package's entry THROUGH
// the linked slice, with the exact callback signature above, and checks the
// tuple Vision consumes. It proves both halves of the bridge at once: our init
// really appended to the dependency's slice (not to a copy), and the values the
// entry produces still name the conn beneath the encryption layer, the
// *CommonConn reflect type, and the struct address Vision adds the field offset
// to.
func TestVisionTripwireRegistryEntryBehaviour(t *testing.T) {
	t.Parallel()

	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()
	commonConn := NewCommonConn(inner, false)

	recognized := false
	for _, entry := range visionTLSRegistry {
		loaded, netConn, reflectType, reflectPointer := entry(commonConn)
		if !loaded {
			continue
		}
		recognized = true
		require.Equal(t, net.Conn(inner), netConn,
			"the Vision registry entry no longer hands Vision the conn beneath the encryption layer; "+visionAuditInstruction)
		require.Equal(t, reflect.TypeOf(commonConn).Elem(), reflectType,
			"the Vision registry entry no longer hands Vision *CommonConn's reflect type; "+visionAuditInstruction)
		require.Equal(t, uintptr(unsafe.Pointer(commonConn)), reflectPointer,
			"the Vision registry entry no longer hands Vision *CommonConn's address; "+visionAuditInstruction)
	}
	require.True(t, recognized,
		"no entry in the linked vless.tlsRegistry recognises *CommonConn; "+visionAuditInstruction)
}

// commonConnVisionTail is the projection of CommonConn's last two fields that
// Vision cares about. Comparing offsets against it — rather than hardcoding
// absolute offsets everywhere — keeps the check correct on 32-bit targets:
// bytes.Buffer/bytes.Reader sizes and alignment are whatever the target uses,
// and the invariant that matters is that input DIRECTLY follows rawInput with
// those two types and nothing inserted between them.
type commonConnVisionTail struct {
	rawInput bytes.Buffer
	input    bytes.Reader
}

// TestVisionTripwireCommonConnABI freezes the CommonConn struct Vision reflects
// into. The dependency looks the fields up by name and then reads the memory at
// reflectPointer+Offset as *bytes.Reader / *bytes.Buffer, so a rename, a retype,
// an insertion or a reorder all silently reinterpret memory instead of failing.
//
// The expected field list is written out in full, in order. A rename or retype
// also breaks the test-only references to CommonConn{}.input/.rawInput at compile
// time, which is the strongest form of this check; the runtime comparison below
// exists so the failure carries the instruction rather than a bare compile error.
func TestVisionTripwireCommonConnABI(t *testing.T) {
	t.Parallel()

	commonType := reflect.TypeOf(CommonConn{})
	require.Equal(t, "encryption.CommonConn", commonType.String(),
		"the type Vision reflects is no longer encryption.CommonConn; "+visionAuditInstruction)

	expectedFields := []struct {
		name string
		typ  reflect.Type
	}{
		{"Conn", reflect.TypeOf((*net.Conn)(nil)).Elem()},
		{"UseAES", reflect.TypeOf(false)},
		{"Client", reflect.TypeOf((*ClientInstance)(nil))},
		{"UnitedKey", reflect.TypeOf([]byte(nil))},
		{"PreWrite", reflect.TypeOf([]byte(nil))},
		{"AEAD", reflect.TypeOf((*AEAD)(nil))},
		{"PeerAEAD", reflect.TypeOf((*AEAD)(nil))},
		{"PeerPadding", reflect.TypeOf([]byte(nil))},
		{"rawInput", reflect.TypeOf(bytes.Buffer{})},
		{"input", reflect.TypeOf(bytes.Reader{})},
	}
	require.Equal(t, len(expectedFields), commonType.NumField(),
		"CommonConn gained or lost a field, which shifts every offset Vision reads; "+visionAuditInstruction)
	for index, expected := range expectedFields {
		field := commonType.Field(index)
		require.Equalf(t, expected.name, field.Name,
			"CommonConn field %d was renamed from %q to %q; "+visionAuditInstruction, index, expected.name, field.Name)
		require.Equalf(t, expected.typ, field.Type,
			"CommonConn.%s changed type from %v to %v; "+visionAuditInstruction, expected.name, expected.typ, field.Type)
	}

	// unsafe.Offsetof sentinels: the two fields Vision reinterprets must keep
	// their relative layout, and on 64-bit their absolute offsets are the Xray
	// ABI every Xray-compatible Vision implementation assumes.
	rawInputOffset := unsafe.Offsetof(CommonConn{}.rawInput)
	inputOffset := unsafe.Offsetof(CommonConn{}.input)
	require.Less(t, rawInputOffset, inputOffset,
		"CommonConn.input no longer follows CommonConn.rawInput (the reference ABI's order changed); "+visionAuditInstruction)
	require.Equal(t,
		unsafe.Offsetof(commonConnVisionTail{}.input)-unsafe.Offsetof(commonConnVisionTail{}.rawInput),
		inputOffset-rawInputOffset,
		"a field was inserted, removed or resized between CommonConn.rawInput and CommonConn.input; "+visionAuditInstruction)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		require.Equal(t, uintptr(120), rawInputOffset,
			"CommonConn.rawInput moved on a 64-bit target; "+visionAuditInstruction)
		require.Equal(t, uintptr(160), inputOffset,
			"CommonConn.input moved on a 64-bit target; "+visionAuditInstruction)
	}
}
