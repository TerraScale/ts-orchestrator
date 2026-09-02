package control

import (
	"context"
	"crypto/ecdsa"

	"github.com/nats-io/nats.go/jetstream"

	journalcore "terrascale.tech/orchestrator/src/orchestrator/journal"
)

// These aliases keep the control API stable while the contracts and proof
// implementation live in the focused journal package.
type NatsOperationJournalCreateRequest = journalcore.NatsOperationJournalCreateRequest
type NatsOperationJournalUpdateRequest = journalcore.NatsOperationJournalUpdateRequest
type NatsOperationJournalMutationReply = journalcore.NatsOperationJournalMutationReply
type NatsRuntimeLifecycleJournalReply = journalcore.NatsRuntimeLifecycleJournalReply
type NatsOperationJournalMutationAuthorityProof = journalcore.NatsOperationJournalMutationAuthorityProof
type NatsOperationJournalMutationAuthoritySigner = journalcore.NatsOperationJournalMutationAuthoritySigner
type NatsOperationJournalMutationAuthorityVerifier = journalcore.NatsOperationJournalMutationAuthorityVerifier
type NatsOperationJournalMutationReplySigner = journalcore.NatsOperationJournalMutationReplySigner
type NatsOperationJournalMutationReplyVerifier = journalcore.NatsOperationJournalMutationReplyVerifier
type NatsOperationJournalMutationProofConsumptionResult = journalcore.NatsOperationJournalMutationProofConsumptionResult

const (
	RuntimeLifecycleNatsProtocolSchemaVersion                         = journalcore.RuntimeLifecycleNatsProtocolSchemaVersion
	NatsOperationJournalMutationProofConsumptionResultConsumed        = journalcore.NatsOperationJournalMutationProofConsumptionResultConsumed
	NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed = journalcore.NatsOperationJournalMutationProofConsumptionResultAlreadyConsumed
	NatsOperationJournalMutationProofConsumptionResultUnavailable     = journalcore.NatsOperationJournalMutationProofConsumptionResultUnavailable
)

var (
	NatsOperationJournalMutationProofConsumption = journalcore.NatsOperationJournalMutationProofConsumption
	NatsOperationJournalMutationRequestDigest    = journalcore.NatsOperationJournalMutationRequestDigest
)

func NewNatsOperationJournalMutationAuthoritySigner(
	callerIdentity string,
	key *ecdsa.PrivateKey,
) *NatsOperationJournalMutationAuthoritySigner {
	return journalcore.NewNatsOperationJournalMutationAuthoritySigner(callerIdentity, key)
}

func NewNatsOperationJournalMutationAuthorityVerifier(
	publicKey []byte,
) *NatsOperationJournalMutationAuthorityVerifier {
	return journalcore.NewNatsOperationJournalMutationAuthorityVerifier(publicKey)
}

func NewNatsOperationJournalMutationReplySigner(
	key *ecdsa.PrivateKey,
) *NatsOperationJournalMutationReplySigner {
	return journalcore.NewNatsOperationJournalMutationReplySigner(key)
}

func NewNatsOperationJournalMutationReplyVerifier(
	publicKey []byte,
) *NatsOperationJournalMutationReplyVerifier {
	return journalcore.NewNatsOperationJournalMutationReplyVerifier(publicKey)
}

func NatsOperationJournalMutationRequestDigestCreate(
	proof NatsOperationJournalMutationAuthorityProof,
) string {
	return journalcore.NatsOperationJournalMutationRequestDigestCreate(proof)
}

func NatsOperationJournalMutationProofConsumptionTryConsumeAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	proof NatsOperationJournalMutationAuthorityProof,
) (bool, error) {
	return journalcore.NatsOperationJournalMutationProofConsumptionTryConsumeAsync(ctx, store, proof)
}

func NatsOperationJournalMutationProofConsumptionConsumeAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	proof NatsOperationJournalMutationAuthorityProof,
) (NatsOperationJournalMutationProofConsumptionResult, error) {
	return journalcore.NatsOperationJournalMutationProofConsumptionConsumeAsync(ctx, store, proof)
}

func NatsOperationJournalMutationProofConsumptionKey(
	proof NatsOperationJournalMutationAuthorityProof,
) (string, error) {
	return journalcore.NatsOperationJournalMutationProofConsumptionKey(proof)
}

func natsOperationJournalIsValid(key, value string) bool {
	return journalcore.IsValidMutation(key, value)
}
