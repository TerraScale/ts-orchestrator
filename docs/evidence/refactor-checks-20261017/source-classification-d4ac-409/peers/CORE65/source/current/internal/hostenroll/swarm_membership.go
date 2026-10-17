package hostenroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// SwarmMembership retains the original dual-key admission inside the existing
// instance enrollment grant. Its short admission expiry is not a runtime lease.
type SwarmMembership struct {
	Transport   WorkerTransport  `json:"transport"`
	Binding     SwarmNodeBinding `json:"binding"`
	Certificate []byte           `json:"certificate"`
}

// VerifySwarmMembership authenticates historical admission only. Current
// registration, retirement, OCI state and the actual live node remain mandatory.
func VerifySwarmMembership(record SwarmMembership, public ed25519.PublicKey) (VerifiedSwarmWorker, error) {
	fail := func(err error) (VerifiedSwarmWorker, error) { return VerifiedSwarmWorker{}, err }
	at := record.Binding.IssuedAt
	if at.IsZero() || at.After(time.Now().Add(5*time.Second)) || len(record.Certificate) > 32<<10 {
		return fail(errors.New("invalid retained worker admission time or certificate"))
	}
	request, descriptor, err := ParseRetainedWorkerRequest(record.Transport.Request, at)
	if err != nil {
		return fail(err)
	}
	response, err := verifyResponseAt(record.Transport.Response, public, request, record.Transport.Request, descriptor, at)
	if err != nil || response.Swarm == nil {
		return fail(errors.New("retained worker admission has no signed projection"))
	}
	wire, err := protocol.EncodeJSON(record.Transport)
	if err != nil {
		return fail(err)
	}
	verified, err := verifyWorkerTransportAt(wire, public, InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, response.Swarm.Architecture, at, at)
	if err != nil {
		return fail(err)
	}
	hostPublic, err := base64.StdEncoding.DecodeString(request.IdentityPublicKey)
	if err != nil {
		return fail(err)
	}
	if err := VerifyWorkerBinding(record.Binding, verified, hostPublic, record.Certificate, at); err != nil {
		return fail(err)
	}
	return verified, nil
}

// RecordSwarmMembership CAS-publishes independently verified admission before
// a manager grants placement labels; callers must verify both signatures first.
func (store *GrantStore) RecordSwarmMembership(ctx context.Context, expected Grant, revision uint64, record SwarmMembership) (Grant, error) {
	if store == nil || store.kv == nil || store.js == nil || revision == 0 || expected.SchemaVersion != 1 || expected.InstanceID == "" ||
		expected.Disabled || expected.TerminalOperationID != "" || expected.IdentityResetOperationID != "" ||
		record.Binding.NodeID == "" || !time.Now().Before(record.Binding.ExpiresAt) ||
		!expected.MatchesCompletedWorkerEnrollment(record.Transport) {
		return Grant{}, mutationNotApplied(errors.New("worker admission differs from current completed instance enrollment"))
	}
	current, currentRevision, err := ReadCurrentGrant(ctx, store.js, expected.InstanceID)
	if err != nil || currentRevision != revision || !sameGrant(current, expected) {
		return Grant{}, mutationNotApplied(errors.New("worker enrollment changed before membership publication"))
	}
	expected.SwarmMembership = &record
	wire, err := json.Marshal(expected)
	if err != nil || len(wire) > MaxGrantBytes {
		return Grant{}, mutationNotApplied(errors.New("worker membership grant is oversized"))
	}
	if _, err := store.kv.Update(ctx, grantKey(expected.InstanceID), wire, revision); err != nil {
		return Grant{}, err
	}
	return expected, nil
}

// MatchesCompletedWorkerEnrollment permits a newly signed worker projection
// while preserving every immutable field of the completed credential response.
// Callers must independently authenticate the request and projected response.
func (grant Grant) MatchesCompletedWorkerEnrollment(transport WorkerTransport) bool {
	return bytes.Equal(transport.Request, grant.Request) && sameWorkerCredentialResponse(transport.Response, grant.Response) ||
		bytes.Equal(transport.Request, grant.RenewalRequest) && sameWorkerCredentialResponse(transport.Response, grant.RenewalResponse)
}

func sameWorkerCredentialResponse(projectedWire, completedWire []byte) bool {
	var projected, completed Response
	if protocol.DecodeStrict(projectedWire, &projected, MaxResponseBytes) != nil || protocol.DecodeStrict(completedWire, &completed, MaxResponseBytes) != nil ||
		projected.Signature == "" || completed.Signature == "" {
		return false
	}
	projected.Swarm, completed.Swarm = nil, nil
	projected.Signature, completed.Signature = "", ""
	left, err := json.Marshal(projected, json.Deterministic(true))
	right, otherErr := json.Marshal(completed, json.Deterministic(true))
	return err == nil && otherErr == nil && bytes.Equal(left, right)
}

func sameSwarmMembership(left, right *SwarmMembership) bool {
	if left == nil || right == nil {
		return left == right
	}
	l, err := json.Marshal(left, json.Deterministic(true))
	r, otherErr := json.Marshal(right, json.Deterministic(true))
	return err == nil && otherErr == nil && bytes.Equal(l, r)
}
