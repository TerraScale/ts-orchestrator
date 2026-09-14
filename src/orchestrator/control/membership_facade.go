package control

import (
	"context"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/membership"
)

type RegionalRuntimeMember = membership.RegionalRuntimeMember
type RegionalRuntimeMembershipCondition = membership.RegionalRuntimeMembershipCondition
type RegionalRuntimeMembershipHealth = membership.RegionalRuntimeMembershipHealth
type RegionalRuntimeMembershipSnapshot = membership.RegionalRuntimeMembershipSnapshot
type RegionalRuntimeMembership = membership.RegionalRuntimeMembership
type RegionalRuntimeMembershipIdentity = membership.RegionalRuntimeMembershipIdentity
type RegionalRuntimeMembershipRecordClass = membership.RegionalRuntimeMembershipRecordClass
type RegionalRuntimeMembershipMutationClass = membership.RegionalRuntimeMembershipMutationClass

const (
	RegionalRuntimeMembershipConditionUnavailable = membership.RegionalRuntimeMembershipConditionUnavailable
	RegionalRuntimeMembershipConditionDegraded    = membership.RegionalRuntimeMembershipConditionDegraded
	RegionalRuntimeMembershipConditionHealthy     = membership.RegionalRuntimeMembershipConditionHealthy

	RegionalRuntimeMembershipRecordClassUnspecified        = membership.RegionalRuntimeMembershipRecordClassUnspecified
	RegionalRuntimeMembershipRecordClassHealthy            = membership.RegionalRuntimeMembershipRecordClassHealthy
	RegionalRuntimeMembershipRecordClassStale              = membership.RegionalRuntimeMembershipRecordClassStale
	RegionalRuntimeMembershipRecordClassMissing            = membership.RegionalRuntimeMembershipRecordClassMissing
	RegionalRuntimeMembershipRecordClassUnexpected         = membership.RegionalRuntimeMembershipRecordClassUnexpected
	RegionalRuntimeMembershipRecordClassWrongCell          = membership.RegionalRuntimeMembershipRecordClassWrongCell
	RegionalRuntimeMembershipRecordClassConflictingSession = membership.RegionalRuntimeMembershipRecordClassConflictingSession
	RegionalRuntimeMembershipRecordClassStaleEpoch         = membership.RegionalRuntimeMembershipRecordClassStaleEpoch
	RegionalRuntimeMembershipRecordClassInvalidSignature   = membership.RegionalRuntimeMembershipRecordClassInvalidSignature
	RegionalRuntimeMembershipRecordClassMalformed          = membership.RegionalRuntimeMembershipRecordClassMalformed

	RegionalRuntimeMembershipMutationClassUnspecified             = membership.RegionalRuntimeMembershipMutationClassUnspecified
	RegionalRuntimeMembershipMutationClassCreateOwnRecord         = membership.RegionalRuntimeMembershipMutationClassCreateOwnRecord
	RegionalRuntimeMembershipMutationClassRenewOwnRecord          = membership.RegionalRuntimeMembershipMutationClassRenewOwnRecord
	RegionalRuntimeMembershipMutationClassTakeOverExpiredLease    = membership.RegionalRuntimeMembershipMutationClassTakeOverExpiredLease
	RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease = membership.RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease
	RegionalRuntimeMembershipMutationClassRejectStaleEpoch        = membership.RegionalRuntimeMembershipMutationClassRejectStaleEpoch
	RegionalRuntimeMembershipMutationClassRejectWrongBinding      = membership.RegionalRuntimeMembershipMutationClassRejectWrongBinding
)

var (
	RegionalRuntimeMembershipReader   = membership.RegionalRuntimeMembershipReader
	RegionalRuntimeMembershipMutation = membership.RegionalRuntimeMembershipMutation
)

func RegionalRuntimeMembershipHealthEvaluate(
	cell string,
	expectedControllers int,
	records []RegionalRuntimeMember,
	rejectedRecords int64,
	observedAt time.Time,
	conflictingControllers int,
) (RegionalRuntimeMembershipHealth, error) {
	return membership.RegionalRuntimeMembershipHealthEvaluate(
		cell, expectedControllers, records, rejectedRecords, observedAt, conflictingControllers)
}

func RegionalRuntimeMembershipIdentityCreate() (*RegionalRuntimeMembershipIdentity, error) {
	return membership.RegionalRuntimeMembershipIdentityCreate()
}

func RegionalRuntimeMembershipIdentityVerify(member RegionalRuntimeMember) bool {
	return membership.RegionalRuntimeMembershipIdentityVerify(member)
}

func isOrdinallySortedAndDistinct(values []string) bool {
	return membership.IsOrdinallySortedAndDistinct(values)
}

func RegionalRuntimeMembershipStartAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	topology *NatsTopology,
	build string,
	capabilities []string,
	startedAt time.Time,
	authority func() RegionalAuthoritySnapshot,
	identity *RegionalRuntimeMembershipIdentity,
) (*RegionalRuntimeMembership, error) {
	var membershipTopology *membership.Topology
	if topology != nil {
		membershipTopology = membership.NewTopology(
			topology.Cell, topology.Replicas, topology.Instance, topology.Runtime().Bucket)
	}
	var membershipAuthority func() membership.AuthoritySnapshot
	if authority != nil {
		membershipAuthority = func() membership.AuthoritySnapshot {
			snapshot := authority()
			return membership.AuthoritySnapshot{
				State:          snapshot.State,
				IsLeader:       snapshot.IsLeader,
				Epoch:          snapshot.Epoch,
				KvRevision:     snapshot.KvRevision,
				LeaseExpiresAt: snapshot.LeaseExpiresAt,
				ObservedAt:     snapshot.ObservedAt,
				Error:          snapshot.Error,
			}
		}
	}
	return membership.RegionalRuntimeMembershipStartAsync(
		ctx, store, membershipTopology, build, capabilities, startedAt, membershipAuthority, identity)
}
