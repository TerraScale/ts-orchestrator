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
	request, descriptor, err := ParseRequest(record.Transport.Request, at)
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
	if store == nil || store.kv == nil || revision == 0 || expected.SchemaVersion != 1 || expected.InstanceID == "" ||
		expected.Disabled || expected.TerminalOperationID != "" || expected.IdentityResetOperationID != "" ||
		record.Binding.NodeID == "" || !time.Now().Before(record.Binding.ExpiresAt) ||
		!(bytes.Equal(record.Transport.Request, expected.Request) && bytes.Equal(record.Transport.Response, expected.Response) && len(expected.Response) != 0 ||
			bytes.Equal(record.Transport.Request, expected.RenewalRequest) && bytes.Equal(record.Transport.Response, expected.RenewalResponse) && len(expected.RenewalResponse) != 0) {
		return Grant{}, mutationNotApplied(errors.New("worker admission differs from current completed instance enrollment"))
	}
	current, currentRevision, err := store.Read(ctx, expected.InstanceID)
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

func sameSwarmMembership(left, right *SwarmMembership) bool {
	if left == nil || right == nil {
		return left == right
	}
	l, err := json.Marshal(left, json.Deterministic(true))
	r, otherErr := json.Marshal(right, json.Deterministic(true))
	return err == nil && otherErr == nil && bytes.Equal(l, r)
}
