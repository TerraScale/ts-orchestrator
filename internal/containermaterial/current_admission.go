//go:build linux

package containermaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// CurrentTaskSources are root-owned concrete readers, never ordinary-process
// callbacks. The genesis and candidate lease come from independent admission.
type CurrentTaskSources struct {
	Client         api.ControlReader
	JS             jetstream.JetStream
	Delivery       *delivery.Service
	Mutations      *authority.Reader
	Genesis        trust.Keyring
	RootIdentity   trust.ChainIdentity
	RootHead       string
	ResponsePublic ed25519.PublicKey
	Lease          *authority.LeaseAdmission
	Credentials    ControllerCredentials
}

// ControllerCredentials is supplied only by the private root producer.
type ControllerCredentials interface {
	Context() context.Context
	Guard(context.Context) error
}

type CurrentTask struct {
	Task       *api.Task
	Profile    Profile
	Release    release.VerifiedContainer
	Controller *bootstrapstart.ControllerHostRecipient
}

// Admission grants only exact signed-request material delivery.
type Admission struct{ state *currentTaskAdmission }

// GenerationAdmission grants metadata observation, never material delivery.
type GenerationAdmission struct{ state *currentTaskAdmission }

// TaskMaterial is checked output metadata, never an admission input.
type TaskMaterial struct {
	Binding      host.ContainerMaterialBinding
	OperationID  string
	ConfigDigest string
	Generation   uint64
	User         string
	ExpiresAt    time.Time
}

type currentTaskAdmission struct {
	sources           CurrentTaskSources
	original          context.Context
	credentials       context.Context
	task              *api.Task
	profile           Profile
	verified          release.VerifiedContainer
	controller        *bootstrapstart.ControllerHostRecipient
	materialSession   *host.ContainerMaterialSession
	generationSession *host.ContainerGenerationSession
	binding           host.ContainerMaterialBinding
	specRevision      uint64
	deadline          time.Time
	sealed            bool
	enrollmentSHA256  string
}

func (a Admission) Profile() Profile                          { return admittedProfile(a.state) }
func (a Admission) Deadline() time.Time                       { return admittedDeadline(a.state) }
func (a Admission) Guard(ctx context.Context) error           { return a.state.guard(ctx) }
func (a Admission) Task() TaskMaterial                        { return admittedTask(a.state) }
func (a GenerationAdmission) Profile() Profile                { return admittedProfile(a.state) }
func (a GenerationAdmission) Deadline() time.Time             { return admittedDeadline(a.state) }
func (a GenerationAdmission) Guard(ctx context.Context) error { return a.state.guard(ctx) }
func (a GenerationAdmission) Task() TaskMaterial              { return admittedTask(a.state) }

func admittedTask(a *currentTaskAdmission) TaskMaterial {
	if a == nil {
		return TaskMaterial{}
	}
	expected, err := ServiceIntent(a.profile, a.verified.Claim().Architecture)
	if err != nil {
		return TaskMaterial{}
	}
	return TaskMaterial{Binding: a.binding, OperationID: a.profile.intent.OperationID, ConfigDigest: a.profile.intent.ConfigDigest,
		Generation: a.task.Spec.ForceUpdate, User: expected.Container.User, ExpiresAt: a.deadline}
}

func admittedProfile(a *currentTaskAdmission) Profile {
	if a == nil {
		return Profile{}
	}
	return a.profile
}

func admittedDeadline(a *currentTaskAdmission) time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.deadline
}

func AdmitMaterialTask(ctx context.Context, sources CurrentTaskSources, task CurrentTask, session *host.ContainerMaterialSession) (Admission, error) {
	if session == nil {
		return Admission{}, ErrPending
	}
	state, err := newCurrentTaskAdmission(ctx, sources, task, session.Binding(), session.Deadline())
	if err != nil {
		return Admission{}, err
	}
	state.materialSession = session
	if err := state.guard(ctx); err != nil {
		return Admission{}, err
	}
	state.sealed = true
	return Admission{state: state}, nil
}

func AdmitGenerationTask(ctx context.Context, sources CurrentTaskSources, task CurrentTask, session *host.ContainerGenerationSession, binding host.ContainerMaterialBinding) (GenerationAdmission, error) {
	if session == nil {
		return GenerationAdmission{}, ErrPending
	}
	state, err := newCurrentTaskAdmission(ctx, sources, task, binding, session.Deadline())
	if err != nil {
		return GenerationAdmission{}, err
	}
	state.generationSession = session
	if err := state.guard(ctx); err != nil {
		return GenerationAdmission{}, err
	}
	state.sealed = true
	return GenerationAdmission{state: state}, nil
}

func newCurrentTaskAdmission(ctx context.Context, sources CurrentTaskSources, task CurrentTask, binding host.ContainerMaterialBinding, sessionDeadline time.Time) (*currentTaskAdmission, error) {
	if ctx == nil || ctx.Err() != nil || sources.Client == nil || sources.JS == nil || sources.JS.Conn() == nil || sources.Delivery == nil ||
		sources.Mutations == nil || sources.Lease == nil || sources.Credentials == nil || sources.RootHead == "" || task.Task == nil || task.Profile.fingerprint == "" ||
		task.Profile.intent.AuthorityEpoch != sources.Lease.Epoch() || !task.Release.Valid(time.Now()) {
		return nil, ErrPending
	}
	if sources.Credentials.Guard(ctx) != nil {
		return nil, ErrPending
	}
	credentials := sources.Credentials.Context()
	if credentials == nil || credentials.Done() == nil || credentials.Err() != nil {
		return nil, ErrPending
	}
	credentialDeadline, ok := credentials.Deadline()
	if !ok || !time.Now().Before(credentialDeadline) {
		return nil, ErrPending
	}
	for key := range task.Profile.profile.Secrets {
		if !vaultsecret.FileKey(key) || len(key) > 128 || key != strings.ToUpper(key) || key[0] < 'A' || key[0] > 'Z' {
			return nil, ErrPending
		}
	}
	genesis := make(trust.Keyring, len(sources.Genesis))
	for id, key := range sources.Genesis {
		genesis[id] = slices.Clone(key)
	}
	sources.Genesis, sources.ResponsePublic = genesis, slices.Clone(sources.ResponsePublic)
	deadline := earlier(credentialDeadline, earlier(sessionDeadline, earlier(sources.Lease.Deadline(), task.Release.ExpiresAt())))
	if original, ok := ctx.Deadline(); ok {
		deadline = earlier(deadline, original)
	}
	if task.Controller != nil {
		deadline = earlier(deadline, task.Controller.Deadline())
	}
	return &currentTaskAdmission{sources: sources, original: ctx, credentials: credentials, task: proto.Clone(task.Task).(*api.Task), profile: task.Profile,
		verified: task.Release, controller: task.Controller, binding: binding, deadline: deadline}, nil
}

func (a *currentTaskAdmission) guard(ctx context.Context) error {
	if a == nil || a.original == nil || a.credentials == nil || ctx == nil || a.original.Err() != nil || a.credentials.Err() != nil || ctx.Err() != nil || !time.Now().Before(a.deadline) {
		return ErrPending
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.original, cancel)
	defer cancel()
	defer stop()
	credentialStop := context.AfterFunc(a.credentials, cancel)
	defer credentialStop()
	if a.sources.Credentials.Guard(ctx) != nil {
		return ErrPending
	}
	if err := a.sources.Lease.Guard(ctx); err != nil {
		return err
	}
	var registration host.Registration
	var err error
	switch {
	case a.materialSession != nil && a.generationSession == nil:
		if err := a.materialSession.Guard(ctx); err != nil {
			return err
		}
		registration, err = a.materialSession.Registration()
	case a.generationSession != nil && a.materialSession == nil:
		if err := a.generationSession.Guard(ctx); err != nil {
			return err
		}
		registration, err = a.generationSession.Registration()
	default:
		return ErrPending
	}
	if err != nil || registration.ID != a.binding.HostID {
		return ErrPending
	}
	roots, revision, err := a.currentProfile(ctx)
	if err != nil {
		return err
	}
	if a.specRevision == 0 {
		a.specRevision = revision
	} else if a.specRevision != revision {
		return ErrPending
	}
	binding := a.binding
	if a.controller != nil {
		if err := a.currentControllerEnrollment(ctx, registration); err != nil {
			return err
		}
		binding.HostID = a.controller.ControllerSlot()
	}
	expected, err := ServiceIntent(a.profile, a.verified.Claim().Architecture)
	if err != nil {
		return err
	}
	if err := VerifyCurrentMaterialTask(ctx, a.sources.Client, a.task, expected, a.verified, roots, a.profile, registration, binding, a.controller); err != nil {
		return err
	}
	if err := a.sources.Lease.Guard(ctx); err != nil {
		return err
	}
	if _, revision, err := a.currentProfile(ctx); err != nil || revision != a.specRevision || !time.Now().Before(a.deadline) || a.original.Err() != nil {
		return ErrPending
	}
	if a.materialSession != nil {
		err = a.materialSession.Guard(ctx)
	} else {
		err = a.generationSession.Guard(ctx)
	}
	if err != nil {
		return err
	}
	if a.sources.Credentials.Guard(ctx) != nil || !time.Now().Before(a.deadline) || a.original.Err() != nil || a.credentials.Err() != nil {
		return ErrPending
	}
	return ctx.Err()
}

func (a *currentTaskAdmission) currentProfile(ctx context.Context) (trust.Keyring, uint64, error) {
	reader, err := currentLeaderReader(a.sources.JS)
	if err != nil {
		return nil, 0, err
	}
	chain := trust.RootChain{Version: 1}
	rootEntry, err := reader.GetLastMsg("KV_TS_TRUST_ROOTS", "$KV.TS_TRUST_ROOTS.chain", nats.Context(ctx))
	if err == nil {
		if rootEntry.Subject != "$KV.TS_TRUST_ROOTS.chain" || rootEntry.Sequence == 0 || rootEntry.Header.Get("KV-Operation") != "" || rootEntry.Header.Get(jetstream.MarkerReasonHeader) != "" {
			return nil, 0, ErrPending
		}
		chain, err = trust.DecodeRootChain(rootEntry.Data)
	}
	if err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
		return nil, 0, err
	}
	roots, err := trust.VerifyRootChain(a.sources.Genesis, a.sources.RootIdentity, chain)
	if err != nil || roots.Head != a.sources.RootHead {
		return nil, 0, ErrPending
	}
	entry, err := reader.GetLastMsg("KV_TS_SERVICE_SET", "$KV.TS_SERVICE_SET.current", nats.Context(ctx))
	if err != nil {
		return nil, 0, err
	}
	digest := sha256.Sum256(entry.Data)
	if entry.Subject != "$KV.TS_SERVICE_SET.current" || entry.Sequence == 0 || len(entry.Data) == 0 || len(entry.Data) > cellspec.MaxSignedBytes ||
		entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" || hex.EncodeToString(digest[:]) != a.profile.specSHA256 {
		return nil, 0, ErrPending
	}
	intent, err := a.sources.Delivery.ContainerIntent(ctx, a.profile.intent.OperationID)
	if err != nil {
		return nil, 0, err
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil || fingerprint != a.profile.fingerprint || intent.AuthorityEpoch != a.sources.Lease.Epoch() {
		return nil, 0, ErrPending
	}
	if _, err := VerifyProfile(entry.Data, roots.Current, a.profile.identity, intent); err != nil {
		return nil, 0, err
	}
	return roots.Current, entry.Sequence, nil
}

func currentLeaderReader(js jetstream.JetStream) (nats.JetStreamContext, error) {
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	return js.Conn().JetStream(opts...)
}

func (a *currentTaskAdmission) currentControllerEnrollment(ctx context.Context, registration host.Registration) error {
	if len(a.sources.ResponsePublic) != ed25519.PublicKeySize {
		return ErrPending
	}
	grant, _, err := hostenroll.ReadCurrentGrant(ctx, a.sources.JS, a.binding.InstanceID)
	if err != nil || grant.Disabled || grant.TerminalOperationID != "" || grant.IdentityResetOperationID != "" {
		return ErrPending
	}
	transport := hostenroll.WorkerTransport{Request: grant.Request, Response: grant.Response}
	if len(grant.RenewalResponse) != 0 {
		transport = hostenroll.WorkerTransport{Request: grant.RenewalRequest, Response: grant.RenewalResponse}
	}
	if !grant.MatchesCompletedWorkerEnrollment(transport) {
		return ErrPending
	}
	digest := sha256.Sum256(transport.Response)
	responseSHA256 := hex.EncodeToString(digest[:])
	if a.enrollmentSHA256 == "" && !a.sealed {
		a.enrollmentSHA256 = responseSHA256
	} else if responseSHA256 != a.enrollmentSHA256 {
		return ErrPending
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(transport.Request, time.Now().UTC())
	if err != nil || !descriptor.IsController() || request.InstanceID != a.binding.InstanceID || descriptor.Node != registration.Node ||
		request.IdentityPublicKey != registration.PublicKey || request.NATSUserPublicKey != registration.NATSUserPublicKey {
		return ErrPending
	}
	response, err := hostenroll.VerifyResponse(transport.Response, a.sources.ResponsePublic, request, transport.Request, descriptor)
	if err != nil || response.Swarm != nil || response.RegistrationReceipt.Generation != registration.Generation || !slices.Equal(response.Roles, registration.Roles) {
		return ErrPending
	}
	entry, err := a.sources.Mutations.ReadHostMutation(ctx, authority.MutationRegistration, registration.Cell+"."+registration.Node)
	if err != nil || entry.Sequence != response.RegistrationReceipt.Revision {
		return ErrPending
	}
	wire, err := protocol.EncodeJSON(registration)
	var canonical host.Registration
	if err != nil || protocol.DecodeStrict(entry.Payload, &canonical, 64<<10) != nil {
		return ErrPending
	}
	canonicalWire, err := protocol.EncodeJSON(canonical)
	if err != nil || !bytes.Equal(wire, canonicalWire) || !time.Now().Before(response.ExpiresAt) {
		return ErrPending
	}
	if !a.sealed {
		a.deadline = earlier(a.deadline, response.ExpiresAt)
	} else if response.ExpiresAt.Before(a.deadline) {
		return ErrPending
	}
	return nil
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
