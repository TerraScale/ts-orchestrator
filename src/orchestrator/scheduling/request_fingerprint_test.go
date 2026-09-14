package scheduling

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func availabilityAcceptedRequestFingerprint(decision AvailabilityDecision) string {
	if decision.AcceptedRequest == nil {
		return "denied"
	}

	request := decision.AcceptedRequest
	policy := &request.Policy
	var builder strings.Builder
	builder.WriteString("availability-accepted-request/v1|")
	fingerprintText(&builder, policy.ServiceId.Value)
	fingerprintNumber(&builder, policy.Desired.Value)
	fingerprintNumber(&builder, policy.MinimumAvailable.Value)
	fingerprintNumber(&builder, policy.Quorum.Value)
	fingerprintNumber(&builder, policy.MaximumConcurrentDisruptions.Value)
	fingerprintNumber(&builder, uint64(policy.Criticality))
	fingerprintNumber(&builder, boolToUint64(policy.OnePerHost))
	fingerprintNumber(&builder, policy.RequiredDistinctFailureDomains.Value)
	fingerprintResources(&builder, policy.Reserve)
	fingerprintNumber(&builder, uint64(policy.ReserveDisposition))
	fingerprintChange(&builder, request.Change)
	fingerprintNumber(&builder, uint64(request.ObservationCompleteness))
	fingerprintNumber(&builder, request.ObservationGeneration.Value)
	fingerprintNumber(&builder, request.CurrentAcceptedObservationGeneration.Value)

	observations := append([]ReplicaObservation{}, request.Observations...)
	sort.SliceStable(observations, func(left, right int) bool {
		if observations[left].ReplicaId.Value != observations[right].ReplicaId.Value {
			return strings.Compare(observations[left].ReplicaId.Value, observations[right].ReplicaId.Value) < 0
		}
		if observations[left].ServiceId.Value != observations[right].ServiceId.Value {
			return strings.Compare(observations[left].ServiceId.Value, observations[right].ServiceId.Value) < 0
		}
		leftNode, rightNode := "-", "-"
		if observations[left].NodeId != nil {
			leftNode = observations[left].NodeId.Value
		}
		if observations[right].NodeId != nil {
			rightNode = observations[right].NodeId.Value
		}
		if leftNode != rightNode {
			return strings.Compare(leftNode, rightNode) < 0
		}
		leftDomain, rightDomain := "-", "-"
		if observations[left].FailureDomainId != nil {
			leftDomain = observations[left].FailureDomainId.Value
		}
		if observations[right].FailureDomainId != nil {
			rightDomain = observations[right].FailureDomainId.Value
		}
		if leftDomain != rightDomain {
			return strings.Compare(leftDomain, rightDomain) < 0
		}
		return observations[left].State < observations[right].State
	})
	fingerprintNumber(&builder, uint64(len(observations)))
	for _, observation := range observations {
		fingerprintText(&builder, observation.ReplicaId.Value)
		fingerprintText(&builder, observation.ServiceId.Value)
		node := "-"
		if observation.NodeId != nil {
			node = observation.NodeId.Value
		}
		fingerprintText(&builder, node)
		domain := "-"
		if observation.FailureDomainId != nil {
			domain = observation.FailureDomainId.Value
		}
		fingerprintText(&builder, domain)
		fingerprintNumber(&builder, uint64(observation.State))
	}
	return builder.String()
}

func fingerprintChange(builder *strings.Builder, change AvailabilityChange) {
	switch typed := change.(type) {
	case PlaceReplicaChange:
		fingerprintText(builder, "place")
		fingerprintText(builder, typed.ReplicaId.Value)
		fingerprintText(builder, typed.TargetNodeId.Value)
		fingerprintText(builder, typed.TargetFailureDomainId.Value)
		fingerprintResources(builder, typed.RequestedResources)
		fingerprintResources(builder, typed.AvailableResources)
	case MaintainReplicaChange:
		fingerprintText(builder, "maintain")
		fingerprintText(builder, typed.ReplicaId.Value)
	case DrainNodeChange:
		fingerprintText(builder, "drain")
		fingerprintText(builder, typed.NodeId.Value)
	default:
		panic("The availability change vocabulary is closed.")
	}
}

func fingerprintResources(builder *strings.Builder, resources ResourceVector) {
	fingerprintNumber(builder, uint64(resources.Cpu))
	fingerprintNumber(builder, uint64(resources.Memory))
	fingerprintNumber(builder, uint64(resources.BlockIo))
	fingerprintNumber(builder, uint64(resources.EphemeralDisk))
	fingerprintNumber(builder, uint64(resources.Bandwidth))
	fingerprintNumber(builder, uint64(resources.Pids))
	fingerprintNumber(builder, uint64(resources.FileDescriptors))
	fingerprintNumber(builder, uint64(resources.HugePages))
}

func fingerprintText(builder *strings.Builder, value string) {
	builder.WriteString(strconv.Itoa(len(value)))
	builder.WriteByte(':')
	builder.WriteString(value)
	builder.WriteByte('|')
}

func fingerprintNumber(builder *strings.Builder, value uint64) {
	builder.WriteString(formatUint(value))
	builder.WriteByte('|')
	_ = fmt.Sprint()
}
