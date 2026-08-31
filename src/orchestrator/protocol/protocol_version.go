// Package protocol defines the signed command envelope, NATS subject grammar,
// checked-in manifest, and frozen messaging contracts. It knows policy and
// subjects, not NATS clients.
package protocol

// ProtocolVersion exposes the current wire version and compatibility check.
var ProtocolVersion protocolVersionStatic

type protocolVersionStatic struct{}

// Current mirrors ProtocolVersion.Current.
func (protocolVersionStatic) Current() int { return 1 }
