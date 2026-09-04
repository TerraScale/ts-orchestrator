// Package protocol owns the signed command envelope, NATS subject grammar and
// taxonomy, checked-in manifest, and messaging contract tables. It knows
// subjects and policy, not NATS clients.
package protocol

// ProtocolVersion exposes the one admitted control protocol version.
var ProtocolVersion protocolVersionStatic

type protocolVersionStatic struct{}

// Current returns the admitted major version.
func (protocolVersionStatic) Current() int { return 1 }
