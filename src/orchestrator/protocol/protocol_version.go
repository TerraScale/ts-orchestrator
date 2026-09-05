// Package protocol owns signed command and messaging envelopes, codecs,
// delivery semantics, and durable work contracts. Subject policy lives in natspolicy.
package protocol

// ProtocolVersion exposes the one admitted control protocol version.
var ProtocolVersion protocolVersionStatic

type protocolVersionStatic struct{}

// Current returns the admitted major version.
func (protocolVersionStatic) Current() int { return 1 }
