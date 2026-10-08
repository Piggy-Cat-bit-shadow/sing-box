package constant

const ACMETLS1Protocol = "acme-tls/1"

const (
	TLSEngineDefault = ""
	TLSEngineGo      = "go"
	TLSEngineApple   = "apple"
	TLSEngineWindows = "windows"
)

// REALITY key_share policy. It selects whether the REALITY ClientHello carries the
// X25519MLKEM768 (post-quantum hybrid) key share, which is a property of the *content* of the
// greeting rather than of its shape - the uTLS fingerprint still decides the shape.
//
// The default (the empty value) means "as the fingerprint carries it", which is why it is a
// three-value string rather than a bool: a bool would have no way to express "do not override the
// fingerprint", and applications that rebuild a config from a model collapse a missing field into
// the zero value.
const (
	// RealityKeyShareDefault sends whatever the configured fingerprint sends. Chrome, Firefox and
	// Safari carry the hybrid share; Edge, iOS, Android, 360 and QQ do not.
	RealityKeyShareDefault = ""
	// RealityKeyShareClassical removes X25519MLKEM768 from both supported_groups and key_share, so
	// the ClientHello is the single-segment classical greeting. It exists because some paths silently
	// drop the two-segment ~1.7KB hybrid greeting; it is only accepted by Xray < v26.9.8.
	RealityKeyShareClassical = "classical"
	// RealityKeyShareHybrid requires the hybrid share. A fingerprint that cannot carry one is a
	// configuration error rather than a silent downgrade, because a silent downgrade is
	// indistinguishable from a wrong public key at the server.
	RealityKeyShareHybrid = "hybrid"
)
