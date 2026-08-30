// Port of src/TerraScale.Orchestrator/Protocol/ProtocolTechnicalInputLimits.cs.
package protocol

// ProtocolTechnicalInputLimits mirrors the C# static class: technical
// acquisition limits for caller-provided protocol inputs. These are
// denial-of-service bounds, not protocol-version compatibility policy.
var ProtocolTechnicalInputLimits protocolTechnicalInputLimitsStatic

type protocolTechnicalInputLimitsStatic struct{}

// MaximumAcceptedProtocolVersionCount mirrors the C# const: the maximum number
// of accepted-version items captured from a caller enumerable. N/N-1 policy
// normally needs two entries; this higher ceiling leaves ample compatibility
// headroom without permitting non-terminating acquisition.
func (protocolTechnicalInputLimitsStatic) MaximumAcceptedProtocolVersionCount() int {
	return 4096
}
