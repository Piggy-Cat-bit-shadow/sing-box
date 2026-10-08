package v2raygrpc

import "testing"

// The gun stream's HTTP/2 path.
//
// # Why this is worth a test of its own
//
// The service name is not a name, it is a PATH: the `:path` of a gun stream is
// `"/" + serviceName + "/Tun"`, assembled by concatenation and never escaped. Xray's client does
// the same (`encoding.TunCustomName`: `c.cc.NewStream(ctx, desc, "/"+name+"/"+tun)`), grpc-go
// writes the method string into the `:path` pseudo-header unchanged, and the server side - also
// grpc-go, in Xray too - splits the RAW path at its LAST slash and looks the leading part up as a
// literal service name. A `/` inside the configured name is therefore another path segment and a
// `%2F` inside it is still three literal characters.
//
// transport/v2raygrpclite's client reaches the same string through net/http's URL type, where an
// escaping step is easy to add by accident; the two transports are asserted against each other in
// custom_service_name_test.go there, which is also where the end-to-end check against a grpc-go
// server lives. This test pins the reference formula on THIS side, with the expected strings
// transcribed by hand rather than computed with streamPath, so a change of policy fails instead of
// agreeing with itself.
func TestStreamPathIsTheReferencePath(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		service  string
		expected string
	}{
		{name: "plain", service: "GunService", expected: "/GunService/Tun"},
		{name: "multi-segment", service: "pkg.Service/v1", expected: "/pkg.Service/v1/Tun"},
		{name: "slash", service: "a/b", expected: "/a/b/Tun"},
		{name: "pre-escaped", service: "a%2Fb", expected: "/a%2Fb/Tun"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := streamPath(testCase.service, grpcTunStreamName); got != testCase.expected {
				t.Fatalf("streamPath(%q) = %q, want %q", testCase.service, got, testCase.expected)
			}
			// The declaration the server registers has to agree with the path the client asks for,
			// or the two halves of this transport disagree with each other.
			if desc := ServerDesc(testCase.service); desc.ServiceName != testCase.service {
				t.Fatalf("ServerDesc(%q).ServiceName = %q", testCase.service, desc.ServiceName)
			}
		})
	}
}
