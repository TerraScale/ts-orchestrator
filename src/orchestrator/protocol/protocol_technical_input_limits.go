package protocol

// ProtocolTechnicalInputLimits holds the technical acquisition limits for
// caller-provided protocol inputs. These are denial-of-service bounds, not
// protocol-version compatibility policy.
var ProtocolTechnicalInputLimits protocolTechnicalInputLimitsStatic

type protocolTechnicalInputLimitsStatic struct{}

// MaximumAcceptedProtocolVersionCount is the maximum number of accepted-version
// items captured from a caller-provided list. N/N-1 policy normally needs two
// entries; this higher ceiling leaves ample compatibility headroom without
// permitting non-terminating acquisition.
func (protocolTechnicalInputLimitsStatic) MaximumAcceptedProtocolVersionCount() int {
	return 4096
}
