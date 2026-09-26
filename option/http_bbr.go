package option

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// BBRProfile names accepted by the HTTP/3 inbound `bbr_profile` option. They
// mirror exactly the profiles exported by
// github.com/sagernet/sing-quic/congestion_meta2; no other value is accepted,
// and this fork never invents a profile the dependency does not define.
//
// These live here rather than in a "server profile" file because they are an
// explicit per-inbound option, not a named bundle of defaults. The former
// http_server_profile.go also held them, which made a congestion-control choice
// look like part of the removed resource-profile mechanism.
const (
	BBRProfileConservative = "conservative"
	BBRProfileStandard     = "standard"
	BBRProfileAggressive   = "aggressive"
)

// BBRProfileNames lists the accepted bbr_profile values.
func BBRProfileNames() []string {
	return []string{BBRProfileConservative, BBRProfileStandard, BBRProfileAggressive}
}

// ValidateBBRProfile rejects unknown profile names.
//
// An EMPTY name is valid, and it means "leave quic-go's congestion control
// unchanged" - it does NOT mean "use the standard BBR profile". That distinction
// is the whole reason the value is carried as a string rather than as a
// congestion_meta2.Profile: there is no zero value in that enum that stands for
// "unset", so resolving "" to ProfileStandard here would make BBR the protocol
// default rather than an explicit operator choice. Neither quic-go/masque-go nor
// quic-go/connect-ip-go sets a congestion control, so the library default (CUBIC)
// is what the references get.
func ValidateBBRProfile(name string) error {
	switch name {
	case "", BBRProfileConservative, BBRProfileStandard, BBRProfileAggressive:
		return nil
	default:
		return E.New("unsupported bbr_profile: ", name, " (supported: conservative, standard, aggressive)")
	}
}

// ServerBBRProfile carries the resolved HTTP/3 server congestion profile from
// the inbound to the HTTP/3 listener without changing the shared
// ConfigureHTTP3ListenerFunc signature.
type ServerBBRProfile struct {
	Name string
}

// BBRProfileValue resolves the configured name.
//
// An unset name stays EMPTY, and the HTTP/3 listener reads that as "leave
// quic-go's congestion control in place". It previously returned
// BBRProfileStandard, which made BBR the protocol default rather than an explicit
// choice - and neither quic-go/masque-go nor quic-go/connect-ip-go sets a
// congestion control, so the library default is what the references get.
//
// The returned value is always either empty or a name the dependency defines, so
// a caller can validate it without a second compatibility check.
func (o ServerBBRProfile) BBRProfileValue() string {
	return o.Name
}
