package hostenroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

type WorkerMembershipQuery struct {
	NodeID         string           `json:"node_id"`
	RegistrationID string           `json:"registration_id"`
	InstanceID     string           `json:"instance_id"`
	Admission      *SwarmMembership `json:"admission,omitempty"`
}

type WorkerMembershipSnapshot struct {
	Registration             host.Registration `json:"registration"`
	Sequence                 uint64            `json:"sequence"`
	Retired                  bool              `json:"retired"`
	GrantInstanceID          string            `json:"grant_instance_id"`
	GrantRevision            uint64            `json:"grant_revision"`
	Disabled                 bool              `json:"disabled"`
	TerminalOperationID      string            `json:"terminal_operation_id"`
	IdentityResetOperationID string            `json:"identity_reset_operation_id"`
	Admission                *SwarmMembership  `json:"admission,omitempty"`
}

// WorkerMembershipSource reads ordered registration and retirement plus the
// existing enrollment grant. It never treats retained admission as currentness.
type WorkerMembershipSource struct {
	mutations *authority.Reader
	hosts     *host.Reader
	grants    *GrantStore
	stream    jetstream.Stream
	cell      string
	public    ed25519.PublicKey
}

func NewWorkerMembershipSource(ctx context.Context, mutations *authority.Reader, hosts *host.Reader, grants *GrantStore,
	js jetstream.JetStream, cell string, public ed25519.PublicKey,
) (*WorkerMembershipSource, error) {
	if mutations == nil || hosts == nil || grants == nil || grants.kv == nil || js == nil || cell == "" || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("worker membership requires concrete current readers and pinned response authority")
	}
	stream, err := js.Stream(ctx, "KV_"+GrantBucket)
	if err != nil {
		return nil, err
	}
	return &WorkerMembershipSource{mutations: mutations, hosts: hosts, grants: grants, stream: stream, cell: cell, public: bytes.Clone(public)}, nil
}

func (source *WorkerMembershipSource) Read(ctx context.Context, query WorkerMembershipQuery) (WorkerMembershipSnapshot, error) {
	fail := func(err error) (WorkerMembershipSnapshot, error) { return WorkerMembershipSnapshot{}, err }
	if source == nil || query.NodeID == "" || !entityid.Valid(query.RegistrationID) || query.InstanceID == "" {
		return fail(errors.New("worker membership locators are invalid"))
	}
	grant, revision, err := source.readGrant(ctx, query.InstanceID)
	if err != nil {
		return fail(err)
	}
	record := grant.SwarmMembership
	if query.Admission != nil {
		record = query.Admission
	}
	if record == nil {
		return fail(errors.New("worker membership has no retained dual-key admission"))
	}
	verified, err := VerifySwarmMembership(*record, source.public)
	if err != nil {
		return fail(err)
	}
	worker := verified.Worker()
	request, descriptor, err := ParseRetainedWorkerRequest(record.Transport.Request, record.Binding.IssuedAt)
	if err != nil || record.Binding.NodeID != query.NodeID || worker.RegistrationID != query.RegistrationID || worker.InstanceID != query.InstanceID ||
		worker.Cell != source.cell || descriptor.Cell != source.cell || entityid.Derive("host", descriptor.Cell, descriptor.Node) != query.RegistrationID {
		return fail(errors.New("worker membership locators differ from authenticated admission"))
	}
	snapshot, err := source.readSnapshot(ctx, descriptor.Node, grant, revision)
	if err != nil {
		return fail(err)
	}
	if query.Admission != nil {
		registration := snapshot.Registration
		role := "container"
		if slices.Contains(registration.Roles, "function-worker") {
			if len(registration.Roles) != 1 {
				return fail(errors.New("function worker registration must be dedicated"))
			}
			role = "wasm"
		}
		if snapshot.Retired || grant.Disabled || grant.TerminalOperationID != "" || grant.IdentityResetOperationID != "" ||
			!time.Now().Before(record.Binding.ExpiresAt) || registration.ID != worker.RegistrationID || registration.Generation != worker.Generation ||
			snapshot.Sequence != worker.Revision || registration.Environment != worker.Environment || registration.PublicKey != request.IdentityPublicKey ||
			registration.NATSUserPublicKey != request.NATSUserPublicKey || len(registration.Roles) == 0 || role != worker.Role {
			return fail(errors.New("worker admission differs from current registered recipient"))
		}
		if !grant.MatchesCompletedWorkerEnrollment(record.Transport) {
			return fail(errors.New("worker admission differs from the current completed enrollment"))
		}
		if !sameSwarmMembership(grant.SwarmMembership, record) {
			if _, err := source.grants.RecordSwarmMembership(ctx, grant, revision, *record); err != nil {
				return fail(err)
			}
		}
	}
	// Leader reads are required: two follower reads can both miss revocation.
	grant, revision, err = source.readGrant(ctx, query.InstanceID)
	if err != nil {
		return fail(err)
	}
	current, err := source.readSnapshot(ctx, descriptor.Node, grant, revision)
	if err != nil || !sameSwarmMembership(grant.SwarmMembership, record) || current.Sequence != snapshot.Sequence || !sameMembershipValue(current.Registration, snapshot.Registration) || current.Retired != snapshot.Retired {
		return fail(errors.New("worker membership changed during admission observation"))
	}
	confirmedGrant, confirmedRevision, err := source.readGrant(ctx, query.InstanceID)
	if err != nil || confirmedRevision != revision || !sameMembershipValue(confirmedGrant, grant) {
		return fail(errors.New("worker enrollment changed during ordered host reads"))
	}
	confirmed, err := source.readSnapshot(ctx, descriptor.Node, confirmedGrant, confirmedRevision)
	if err != nil || !sameMembershipValue(current, confirmed) {
		return fail(errors.New("worker registration or retirement changed during grant observation"))
	}
	return confirmed, nil
}

func (source *WorkerMembershipSource) readGrant(ctx context.Context, instanceID string) (Grant, uint64, error) {
	return readCurrentGrant(ctx, source.stream, instanceID)
}

// ReadCurrentGrant bypasses follower-local KV reads when revocation matters.
func ReadCurrentGrant(ctx context.Context, js jetstream.JetStream, instanceID string) (Grant, uint64, error) {
	if js == nil || instanceID == "" {
		return Grant{}, 0, errors.New("current enrollment grant reader is unavailable")
	}
	stream, err := js.Stream(ctx, "KV_"+GrantBucket)
	if err != nil {
		return Grant{}, 0, err
	}
	return readCurrentGrant(ctx, stream, instanceID)
}

func readCurrentGrant(ctx context.Context, stream jetstream.Stream, instanceID string) (Grant, uint64, error) {
	subject := "$KV." + GrantBucket + "." + grantKey(instanceID)
	entry, err := stream.GetLastMsgForSubject(ctx, subject)
	if err != nil {
		return Grant{}, 0, err
	}
	var grant Grant
	if entry == nil || entry.Subject != subject || entry.Sequence == 0 || entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" ||
		protocol.DecodeStrict(entry.Data, &grant, MaxGrantBytes) != nil || grant.SchemaVersion != 1 || grant.InstanceID != instanceID {
		return Grant{}, 0, errors.New("worker enrollment grant is corrupt or deleted")
	}
	return grant, entry.Sequence, nil
}

func (source *WorkerMembershipSource) readSnapshot(ctx context.Context, node string, grant Grant, revision uint64) (WorkerMembershipSnapshot, error) {
	fail := func(err error) (WorkerMembershipSnapshot, error) { return WorkerMembershipSnapshot{}, err }
	subject := source.cell + "." + node
	entry, err := source.mutations.ReadHostMutation(ctx, authority.MutationRegistration, subject)
	if err != nil {
		return fail(err)
	}
	var registration host.Registration
	if protocol.DecodeStrict(entry.Payload, &registration, 64<<10) != nil || entry.Kind != authority.MutationRegistration || entry.SubjectKey != subject ||
		entry.Sequence == 0 || entry.Epoch == 0 || registration.ID != entityid.Derive("host", source.cell, node) || registration.Cell != source.cell || registration.Node != node {
		return fail(errors.New("worker registration log identity is invalid"))
	}
	statuses, err := source.hosts.ListHosts(ctx)
	if err != nil {
		return fail(err)
	}
	found, retired := false, true
	for _, status := range statuses {
		if status.Registration.ID != registration.ID {
			continue
		}
		if found || !sameMembershipValue(status.Registration, registration) {
			return fail(errors.New("worker registration changed during current host read"))
		}
		found, retired = true, status.Retired
	}
	if !found {
		return fail(errors.New("worker has no current registered host"))
	}
	confirmed, err := source.mutations.ReadHostMutation(ctx, authority.MutationRegistration, subject)
	if err != nil || confirmed.Sequence != entry.Sequence || !bytes.Equal(confirmed.Payload, entry.Payload) {
		return fail(errors.New("worker registration changed during retirement observation"))
	}
	return WorkerMembershipSnapshot{Registration: registration, Sequence: entry.Sequence, Retired: retired, GrantInstanceID: grant.InstanceID,
		GrantRevision: revision, Disabled: grant.Disabled, TerminalOperationID: grant.TerminalOperationID, IdentityResetOperationID: grant.IdentityResetOperationID, Admission: grant.SwarmMembership}, nil
}

func sameMembershipValue(left, right any) bool {
	expected, err := json.Marshal(left, json.Deterministic(true))
	actual, actualErr := json.Marshal(right, json.Deterministic(true))
	return err == nil && actualErr == nil && bytes.Equal(expected, actual)
}
