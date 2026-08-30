// Package protocol ports TerraScale.Orchestrator.Protocol: the signed command
// envelope and its validation core, the NATS subject grammar and taxonomy, the
// checked-in protocol manifest, and the frozen messaging contract tables. The
// package is infrastructure-free: it knows subjects and policy, not NATS
// clients.
//
// Port of src/TerraScale.Orchestrator/Protocol/ProtocolVersion.cs.
package protocol

// ProtocolVersion mirrors the C# static class ProtocolVersion; call sites read
// protocol.ProtocolVersion.Current().
var ProtocolVersion protocolVersionStatic

type protocolVersionStatic struct{}

// Current mirrors ProtocolVersion.Current.
func (protocolVersionStatic) Current() int { return 1 }
