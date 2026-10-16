package memberstatus

import "github.com/TerraScale/ts-orchestrator/internal/entityid"

// VerifyReportedServing checks a current, signed host report against the
// expected member process, accepted authority, and named signed survivor. A
// controller must additionally verify the host session and report freshness.
func VerifyReportedServing(proof ServingProof, expected Identity, survivor Survivor) error {
	if !expected.Process.valid() || !expected.Scope.valid() || !expected.Authority.valid() ||
		!survivor.valid() || survivor.MemberID == expected.Scope.MemberID ||
		proof.SchemaVersion != 1 || proof.Process != expected.Process ||
		proof.Scope != expected.Scope || proof.Authority != expected.Authority ||
		!proof.Serving || !proof.Listeners.Client || !proof.Listeners.Replication ||
		!lowerHex(proof.Nonce, 32) || !lowerHex(proof.Object.RootSHA256, 64) ||
		!lowerHex(proof.Object.TargetSHA256, 64) ||
		!lowerHex(proof.Object.InboxArchiveSHA256AtRecovery, 64) ||
		proof.Object.RemoteAppliedSequence > proof.Object.RemoteInboxDurableSequence ||
		proof.Replication.PeerMemberID != survivor.MemberID ||
		proof.Replication.PeerIncarnation != survivor.Incarnation ||
		!proof.Replication.CurrentAuthenticated ||
		proof.Replication.LocalSourceSequence != proof.Object.LocalSourceSequence ||
		proof.Replication.PeerAppliedSequence < proof.Replication.LocalSourceSequence ||
		!proof.Replication.ordered() {
		return ErrNotServing
	}
	return nil
}

// VerifyReportedDrain checks a host-published completed receipt against the
// signed old process, scope, authority, and survivor. The host must separately
// reconcile the original request nonce from its durable FileStore.
func VerifyReportedDrain(envelope DrainEnvelope, operationID string, expected Identity, survivor Survivor, minimumSourceSequence uint64) error {
	if !entityid.Valid(operationID) || !expected.Process.valid() || !expected.Scope.valid() ||
		!expected.Authority.valid() || !survivor.valid() || envelope.SchemaVersion != 1 ||
		!lowerHex(envelope.Nonce, 32) || !envelope.Process.valid() ||
		envelope.OperationID != operationID || envelope.State != "complete" ||
		envelope.Receipt == nil || envelope.ReceiptSHA256 == nil ||
		!lowerHex(*envelope.ReceiptSHA256, 64) {
		return ErrStaleBinding
	}
	receipt := envelope.Receipt
	digest, err := receipt.digest()
	if err != nil || digest != *envelope.ReceiptSHA256 || receipt.SchemaVersion != 1 ||
		receipt.OperationID != operationID || !lowerHex(receipt.RequestNonce, 32) ||
		receipt.RequestedProcess != expected.Process || !receipt.DrainedProcess.valid() ||
		receipt.Scope != expected.Scope || receipt.Authority != expected.Authority ||
		receipt.LocalSourceOrigin != (Origin{MemberID: expected.Scope.MemberID, Incarnation: expected.Scope.Incarnation}) ||
		receipt.LocalSourceDurableSequence < minimumSourceSequence ||
		receipt.ArchivedSourceSequence != receipt.LocalSourceDurableSequence ||
		!lowerHex(receipt.ObjectRootSHA256, 64) ||
		receipt.Peer.Origin != (Origin{MemberID: survivor.MemberID, Incarnation: survivor.Incarnation}) ||
		receipt.Peer.DurableSequence < receipt.LocalSourceDurableSequence ||
		receipt.Peer.AppliedSequence < receipt.LocalSourceDurableSequence ||
		receipt.Peer.AppliedSequence > receipt.Peer.DurableSequence ||
		receipt.Peer.LocalInboxAppliedSequence > receipt.Peer.LocalInboxDurableSequence ||
		!receipt.ReplicationQuiesced {
		return ErrStaleBinding
	}
	return nil
}
