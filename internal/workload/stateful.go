package workload

import (
	"cmp"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

// StatefulMember is one TerraBase member as placement and its latest verified
// serving proof describe it.
type StatefulMember struct {
	Observation placement.MemberObservation
	Kind        placement.MemberKind
	// Replication is the member's latest verified replication proof; nil
	// means the lag is unknown, which blocks every scale-in.
	Replication *memberstatus.ReplicationProof
}

// ReplicationLag is the source sequence the peer has not yet applied.
func ReplicationLag(proof memberstatus.ReplicationProof) uint64 {
	if proof.PeerAppliedSequence >= proof.LocalSourceSequence {
		return 0
	}
	return proof.LocalSourceSequence - proof.PeerAppliedSequence
}

// StatefulScaleDownInput describes one proposed TerraBase scale-in. Intent is
// the admitted intent that no longer desires the candidate seat.
type StatefulScaleDownInput struct {
	Policy                StatefulPolicy
	Intent                placement.Intent
	Members               []StatefulMember
	ManagedUpdateInFlight bool
	BackupInFlight        bool
	LastTopologyChange    time.Time
	Cooldown              time.Duration
	Now                   time.Time
}

// StatefulVerdict names the member that may begin retirement, or why none may.
type StatefulVerdict struct {
	Allowed   bool
	Candidate string
	Reason    string
}

// StatefulScaleDown chooses at most one elastic member that may begin the
// cordon/drain path. It never selects a permanent seat, refuses while another
// topology change, managed update or backup is in flight, requires every
// member's replication lag to be known and within MaxLagForScaleDown, keeps
// QuorumFloorPerRegion serving members on distinct failure domains, and
// finally requires placement.CanBeginRetirement to agree.
func StatefulScaleDown(in StatefulScaleDownInput) StatefulVerdict {
	if err := in.Policy.validate(); err != nil {
		return StatefulVerdict{Reason: "invalid-stateful-policy"}
	}
	if in.ManagedUpdateInFlight {
		return StatefulVerdict{Reason: "managed-update-in-flight"}
	}
	if in.BackupInFlight {
		return StatefulVerdict{Reason: "backup-in-flight"}
	}
	if in.Cooldown > 0 && !in.LastTopologyChange.IsZero() && in.Now.Sub(in.LastTopologyChange) < in.Cooldown {
		return StatefulVerdict{Reason: "topology-cooldown"}
	}
	inFlight := 0
	for _, member := range in.Members {
		if member.Observation.Stage != placement.StageServing && member.Observation.Stage != placement.StageRemoved {
			inFlight++
		}
	}
	if inFlight >= in.Policy.MaxConcurrentChanges {
		return StatefulVerdict{Reason: "topology-change-in-flight"}
	}
	for _, member := range in.Members {
		if member.Observation.Stage != placement.StageServing {
			continue
		}
		if member.Replication == nil || !member.Replication.CurrentAuthenticated {
			return StatefulVerdict{Reason: "replication-lag-unverified"}
		}
		if ReplicationLag(*member.Replication) > in.Policy.MaxLagForScaleDown {
			return StatefulVerdict{Reason: "replication-lag-exceeds-limit"}
		}
	}
	survivors := make([]placement.MemberObservation, 0, len(in.Members))
	for _, member := range in.Members {
		survivors = append(survivors, member.Observation)
	}
	candidates := slices.Clone(in.Members)
	// Highest member ID first keeps victim selection deterministic and leaves
	// the lowest elastic ordinals, which the two-seat schema still names.
	slices.SortFunc(candidates, func(a, b StatefulMember) int {
		return cmp.Compare(b.Observation.MemberID, a.Observation.MemberID)
	})
	// The first refusal is reported when no candidate qualifies.
	refusal := ""
	for _, candidate := range candidates {
		if candidate.Kind != placement.MemberElastic {
			continue
		}
		reason := "quorum-floor-not-met"
		if quorumFloorKept(in.Policy.QuorumFloorPerRegion, in.Intent, candidate, in.Members) {
			observation := candidate.Observation
			// Lag and quorum floor were verified above for every member.
			evidence := placement.RetirementEvidence{
				DatabaseID: observation.DatabaseID, PartitionID: observation.PartitionID, MemberID: observation.MemberID,
				InstanceID: observation.InstanceID, VolumeID: observation.VolumeID,
				ReplicationHealthy: true, QuorumSafe: true,
			}
			var allowed bool
			allowed, reason = placement.CanBeginRetirement(in.Intent, observation, survivors, evidence)
			if allowed {
				return StatefulVerdict{Allowed: true, Candidate: observation.MemberID, Reason: reason}
			}
		}
		if refusal == "" {
			refusal = reason
		}
	}
	if refusal == "" {
		refusal = "no-elastic-candidate"
	}
	return StatefulVerdict{Reason: refusal}
}

// quorumFloorKept requires floor serving, healthy, current-session members on
// distinct failure domains in every region the intent keeps active once the
// candidate leaves. A region the intent removes has no floor.
func quorumFloorKept(floor int, intent placement.Intent, candidate StatefulMember, members []StatefulMember) bool {
	for _, region := range intent.ActiveRegions {
		domains := make(map[string]struct{})
		for _, member := range members {
			o := member.Observation
			if o.Region != region || o.MemberID == candidate.Observation.MemberID ||
				o.Stage != placement.StageServing || !o.Healthy || !o.CurrentSession || o.FailureDomain == "" {
				continue
			}
			domains[o.FailureDomain] = struct{}{}
		}
		if len(domains) < floor {
			return false
		}
	}
	return true
}

// StatefulCanRetire is the provider-removal gate after drain. It reports a
// drain that exceeded the policy timeout so an operator can intervene; it
// never forces removal, and placement.CanRetire must still agree.
func StatefulCanRetire(policy StatefulPolicy, intent placement.Intent, candidate placement.MemberObservation,
	survivors []placement.MemberObservation, evidence placement.RetirementEvidence, drainStarted, now time.Time,
) (bool, string) {
	if err := policy.validate(); err != nil {
		return false, "invalid-stateful-policy"
	}
	if allowed, reason := placement.CanRetire(intent, candidate, survivors, evidence); !allowed {
		if !evidence.HostDrained && !drainStarted.IsZero() &&
			now.Sub(drainStarted) > time.Duration(policy.DrainTimeoutSeconds)*time.Second {
			return false, "drain-timeout-exceeded"
		}
		return false, reason
	}
	return true, "safe-to-retire"
}
