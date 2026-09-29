package masque

import (
	"github.com/sagernet/sing-box/transport/masque"
)

// oneConfiguration wraps a single configuration for the transport's apply, which takes the
// whole assignment because the configuration boundaries are part of the state.
func oneConfiguration(configuration masque.DNSConfiguration) []masque.DNSConfiguration {
	return []masque.DNSConfiguration{configuration}
}
