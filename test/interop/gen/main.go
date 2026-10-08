// Command gen writes the interop configuration pair for every scenario to a
// directory, so a maintainer can read, edit and replay them by hand.
//
// It is the manual half of the stand: the tests generate the same files into an
// artifact directory, and this command exists so that "show me the config for
// the REALITY + encryption + Vision + XHTTP scenario" has an answer that does not
// require reading Go. The files it writes use SYNTHETIC encryption key material,
// because a Go program cannot mint the reference's server half; the command says
// so on stdout, and a live run refuses that material (see keymaterial.go).
//
// Run it from the repository's `test` module:
//
//	cd test && go run ./interop/gen -out /tmp/sing-box-interop
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/uuid/v5"

	"test/interop"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "interop/gen:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		outputDir      = flag.String("out", "", "directory to write the configuration pairs into (required)")
		names          = flag.String("scenario", "", "comma-separated scenario names (default: every scenario)")
		serverAddress  = flag.String("server-address", "127.0.0.1", "the reference's listen address")
		serverPort     = flag.Uint("server-port", 24443, "the reference's listen port")
		clientAddress  = flag.String("client-address", "127.0.0.1", "the box client's mixed inbound address")
		clientPort     = flag.Uint("client-port", 24080, "the box client's mixed inbound port")
		targetAddress  = flag.String("target-address", "127.0.0.1", "the local echo/HTTP target address")
		targetPort     = flag.Uint("target-port", 24081, "the local echo/HTTP target port")
		camouflagePort = flag.Uint("camouflage-port", 24444, "the REALITY camouflage server port")
		serverName     = flag.String("server-name", "interop.local", "the TLS server name (SNI)")
	)
	flag.Parse()

	if *outputDir == "" {
		return fmt.Errorf("-out is required")
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return err
	}

	scenarios := interop.Scenarios()
	if *names != "" {
		scenarios = nil
		for _, name := range strings.Split(*names, ",") {
			scenario, err := interop.ScenarioByName(strings.TrimSpace(name))
			if err != nil {
				return err
			}
			scenarios = append(scenarios, scenario)
		}
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios selected")
	}

	// One REALITY key pair per invocation would be reused across scenarios, which
	// would make every scenario share a public key. That is legal, but a leaked
	// generated file would then identify the whole set, and — more importantly for
	// a debugging tool — a per-scenario pair makes it obvious from two files
	// whether they belong together.
	written := 0
	for _, scenario := range scenarios {
		publicKey, privateKey, err := interop.GenerateRealityKeyPair()
		if err != nil {
			return err
		}
		userUUID, err := uuid.NewV4()
		if err != nil {
			return err
		}
		input := interop.Input{
			Scenario:          scenario,
			ArtifactDir:       *outputDir,
			ServerAddress:     *serverAddress,
			ServerPort:        uint16(*serverPort),
			ClientAddress:     *clientAddress,
			ClientPort:        uint16(*clientPort),
			TargetAddress:     *targetAddress,
			TargetPort:        uint16(*targetPort),
			ServerName:        *serverName,
			CamouflageAddress: fmt.Sprintf("127.0.0.1:%d", *camouflagePort),
			RealityPublicKey:  publicKey,
			RealityPrivateKey: privateKey,
			ShortID:           interop.GenerateShortID(),
			UUID:              userUUID.String(),
			TLSCertFile:       filepath.Join(*outputDir, "camouflage.crt"),
			TLSKeyFile:        filepath.Join(*outputDir, "camouflage.key"),
			ClientLogPath:     filepath.Join(*outputDir, "box-client.log"),
			ServerLogPath:     filepath.Join(*outputDir, "xray-server.log"),
		}
		if scenario.EncryptionEnabled() {
			material, err := interop.NewSyntheticEncryptionKeyMaterial(scenario)
			if err != nil {
				return err
			}
			input.Encryption = material
		}
		pair, err := input.Generate()
		if err != nil {
			return err
		}
		fmt.Printf("%-48s client %s\n", scenario.Name, pair.ClientConfigPath)
		fmt.Printf("%-48s server %s\n", "", pair.ServerConfigPath)
		written++
	}

	// The TLS certificate is only referenced by path in the generated files; the
	// files themselves are the ones a real run mints, so a hand replay needs one
	// generated here too.
	if _, _, err := interop.WriteSelfSignedCertificate(*outputDir, *serverName); err != nil {
		return err
	}

	fmt.Printf("\nwrote %d configuration pairs to %s\n", written, *outputDir)
	fmt.Printf("The camouflage certificate and key are %s/{camouflage.crt,camouflage.key}.\n",
		strings.TrimRight(*outputDir, "/"))
	fmt.Println("Encryption scenarios use SYNTHETIC key material: valid for inspecting and for")
	fmt.Println("parsing, NOT usable against a real reference, which owns the decryption half.")
	fmt.Println("For a live pair, run `xray vlessenc` and export XRAY_VLESS_ENCRYPTION and")
	fmt.Println("XRAY_VLESS_DECRYPTION (see test/interop/README.md).")
	return nil
}
