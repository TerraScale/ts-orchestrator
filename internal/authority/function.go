package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go/jetstream"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var functionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var functionSwarmID = regexp.MustCompile(`^[a-z0-9]{25}$`)

// FunctionIntent is the current signed desired release. Claim.Digest is its
// object key in the existing delivery artifact store; module bytes stay there.
type FunctionIntent struct {
	Claim          release.FunctionClaim `json:"claim"`
	EnvelopeSHA256 string                `json:"envelope_sha256"`
	Envelope       []byte                `json:"envelope"`
	Delegation     []byte                `json:"delegation"`
}

// FunctionBinding fixes a grant to the actual scheduler task and host, and the
// exact Vault material inventory delivered to that recipient.
type FunctionBinding struct {
	TaskID                 string `json:"task_id"`
	ServiceID              string `json:"service_id"`
	NodeID                 string `json:"node_id"`
	InstanceID             string `json:"instance_id"`
	Region                 string `json:"region"`
	HostID                 string `json:"host_id"`
	Fingerprint            string `json:"fingerprint"`
	MaterialManifestSHA256 string `json:"material_manifest_sha256"`
}

func (binding FunctionBinding) Validate() error {
	if !functionSwarmID.MatchString(binding.TaskID) || !functionSwarmID.MatchString(binding.ServiceID) ||
		!functionSwarmID.MatchString(binding.NodeID) || !entityid.Valid(binding.HostID) ||
		!catalog.IsOCIRegion(binding.Region) || !strings.HasPrefix(binding.InstanceID, "ocid1.instance.") ||
		len(binding.InstanceID) <= len("ocid1.instance.") || len(binding.InstanceID) > 255 ||
		strings.ContainsFunc(binding.InstanceID, unicode.IsSpace) ||
		!validTerminalDigest(binding.Fingerprint) || !validTerminalDigest(binding.MaterialManifestSHA256) {
		return errors.New("function grant recipient or material identity is invalid")
	}
	return nil
}

// FunctionGrant admits one task's material without advancing its signed release
// sequence. Its stream revision is CAS ordered with the current function intent.
type FunctionGrant struct {
	TenantID       string          `json:"tenant_id"`
	FunctionID     string          `json:"function_id"`
	Sequence       uint64          `json:"sequence"`
	EnvelopeSHA256 string          `json:"envelope_sha256"`
	Binding        FunctionBinding `json:"binding"`
}

func functionIntentKey(tenantID, functionID string) (string, error) {
	if !entityid.Valid(tenantID) || !functionName.MatchString(functionID) {
		return "", errors.New("function intent tenant or function identity is invalid")
	}
	return tenantID + "." + functionID, nil
}

// CommitFunctionIntent advances the durable function floor. The same signed
// sequence may only repeat its exact envelope and delegation.
func (r *Runtime) CommitFunctionIntent(ctx context.Context, epoch uint64, operationID string,
	expectedSequence uint64, proof release.VerifiedFunction,
) (uint64, error) {
	if !proof.Valid() {
		return 0, trust.ErrExpired
	}
	intent := FunctionIntent{Claim: proof.Claim(), EnvelopeSHA256: proof.EnvelopeSHA256(),
		Envelope: proof.Envelope(), Delegation: proof.Delegation()}
	key, err := functionIntentKey(intent.Claim.TenantID, intent.Claim.FunctionID)
	if err != nil {
		return 0, err
	}
	if r == nil || strings.ToLower(intent.Claim.Cell) != r.config.Scope {
		return 0, release.ErrExpectationMismatch
	}
	payload, err := json.Marshal(intent, json.FormatNilSliceAsNull(true))
	if err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, epoch, MutationFunctionIntent, key, operationID,
		expectedSequence, payload, func(ctx context.Context) error {
			if !proof.Valid() {
				return trust.ErrExpired
			}
			prior, err := r.ReadFunctionIntent(ctx, intent.Claim.TenantID, intent.Claim.FunctionID)
			if !proof.Valid() {
				return trust.ErrExpired
			}
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			current, err := DecodeFunctionIntent(prior)
			if err != nil {
				return err
			}
			if intent.Claim.Sequence < current.Claim.Sequence ||
				intent.Claim.Sequence == current.Claim.Sequence && !bytes.Equal(payload, prior.Payload) {
				return ErrConflict
			}
			return nil
		})
}

func (r *Runtime) ReadFunctionIntent(ctx context.Context, tenantID, functionID string) (LogEntry, error) {
	key, err := functionIntentKey(tenantID, functionID)
	if err != nil {
		return LogEntry{}, err
	}
	return r.ReadHostMutation(ctx, MutationFunctionIntent, key)
}

func (r *Reader) ReadFunctionIntent(ctx context.Context, tenantID, functionID string) (LogEntry, error) {
	key, err := functionIntentKey(tenantID, functionID)
	if err != nil {
		return LogEntry{}, err
	}
	return r.ReadHostMutation(ctx, MutationFunctionIntent, key)
}

func DecodeFunctionIntent(entry LogEntry) (FunctionIntent, error) {
	var intent FunctionIntent
	if err := json.Unmarshal(entry.Payload, &intent, json.RejectUnknownMembers(true)); err != nil {
		return intent, err
	}
	key, err := functionIntentKey(intent.Claim.TenantID, intent.Claim.FunctionID)
	if err != nil || entry.Kind != MutationFunctionIntent || entry.SubjectKey != key || entry.Sequence == 0 {
		return FunctionIntent{}, errors.New("function intent control-log identity is invalid")
	}
	if err := intent.Claim.Validate(); err != nil {
		return FunctionIntent{}, err
	}
	envelope, err := trust.DecodeEnvelope(intent.Envelope)
	if err != nil {
		return FunctionIntent{}, err
	}
	claim, err := trust.EncodePayload(intent.Claim)
	if err != nil {
		return FunctionIntent{}, err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil || fingerprint != intent.EnvelopeSHA256 || !bytes.Equal(claim, envelope.Payload) ||
		envelope.Scope != release.FunctionScope(intent.Claim) {
		return FunctionIntent{}, errors.New("function intent does not match its signed envelope")
	}
	if _, err := trust.DecodeEnvelope(intent.Delegation); err != nil {
		return FunctionIntent{}, err
	}
	return intent, nil
}

// VerifyFunctionIntent compares an already verified, still-current signature
// against the durable floor. Readers must separately verify retained wire with
// their trusted roots and module bytes before producing a sealed proof.
func (r *Runtime) VerifyFunctionIntent(ctx context.Context, proof release.VerifiedFunction) error {
	return verifyFunctionIntent(ctx, r, proof)
}

func (r *Reader) VerifyFunctionIntent(ctx context.Context, proof release.VerifiedFunction) error {
	return verifyFunctionIntent(ctx, r, proof)
}

type functionIntentReader interface {
	ReadFunctionIntent(context.Context, string, string) (LogEntry, error)
}

func verifyFunctionIntent(ctx context.Context, reader functionIntentReader, proof release.VerifiedFunction) error {
	if !proof.Valid() {
		return trust.ErrExpired
	}
	claim := proof.Claim()
	entry, err := reader.ReadFunctionIntent(ctx, claim.TenantID, claim.FunctionID)
	if err != nil {
		return err
	}
	current, err := DecodeFunctionIntent(entry)
	if err != nil {
		return err
	}
	if current.Claim.Sequence != claim.Sequence || current.EnvelopeSHA256 != proof.EnvelopeSHA256() ||
		!bytes.Equal(current.Envelope, proof.Envelope()) || !bytes.Equal(current.Delegation, proof.Delegation()) {
		return ErrConflict
	}
	if !proof.Valid() {
		return trust.ErrExpired
	}
	return nil
}

func (r *Runtime) CommitFunctionGrant(ctx context.Context, epoch uint64, operationID string,
	expectedSequence uint64, proof release.VerifiedFunction, binding FunctionBinding,
) (uint64, error) {
	if err := binding.Validate(); err != nil {
		return 0, err
	}
	if !proof.Valid() {
		return 0, trust.ErrExpired
	}
	claim := proof.Claim()
	if catalog.OCIRegion(claim.Cell) != binding.Region {
		return 0, release.ErrExpectationMismatch
	}
	grant := FunctionGrant{TenantID: claim.TenantID, FunctionID: claim.FunctionID,
		Sequence: claim.Sequence, EnvelopeSHA256: proof.EnvelopeSHA256(), Binding: binding}
	payload, err := json.Marshal(grant)
	if err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, epoch, MutationFunctionGrant, binding.TaskID, operationID,
		expectedSequence, payload, func(ctx context.Context) error {
			if err := r.VerifyFunctionIntent(ctx, proof); err != nil {
				return err
			}
			prior, err := r.ReadFunctionGrant(ctx, binding.TaskID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if !bytes.Equal(prior.Payload, payload) {
				return ErrConflict
			}
			return nil
		})
}

func (r *Runtime) ReadFunctionGrant(ctx context.Context, taskID string) (LogEntry, error) {
	if !functionSwarmID.MatchString(taskID) {
		return LogEntry{}, errors.New("function grant task ID is invalid")
	}
	return r.ReadHostMutation(ctx, MutationFunctionGrant, taskID)
}

func (r *Reader) ReadFunctionGrant(ctx context.Context, taskID string) (LogEntry, error) {
	if !functionSwarmID.MatchString(taskID) {
		return LogEntry{}, errors.New("function grant task ID is invalid")
	}
	return r.ReadHostMutation(ctx, MutationFunctionGrant, taskID)
}

func DecodeFunctionGrant(entry LogEntry) (FunctionGrant, error) {
	var grant FunctionGrant
	if err := json.Unmarshal(entry.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return grant, err
	}
	if _, err := functionIntentKey(grant.TenantID, grant.FunctionID); err != nil {
		return FunctionGrant{}, err
	}
	if entry.Kind != MutationFunctionGrant || entry.Sequence == 0 || entry.SubjectKey != grant.Binding.TaskID ||
		grant.Sequence == 0 || !validTerminalDigest(grant.EnvelopeSHA256) {
		return FunctionGrant{}, errors.New("function grant control-log identity is invalid")
	}
	return grant, grant.Binding.Validate()
}

func (r *Runtime) VerifyFunctionGrant(ctx context.Context, proof release.VerifiedFunction, binding FunctionBinding) error {
	return verifyFunctionGrant(ctx, r, proof, binding)
}

func (r *Reader) VerifyFunctionGrant(ctx context.Context, proof release.VerifiedFunction, binding FunctionBinding) error {
	return verifyFunctionGrant(ctx, r, proof, binding)
}

type functionGrantReader interface {
	functionIntentReader
	ReadFunctionGrant(context.Context, string) (LogEntry, error)
}

func verifyFunctionGrant(ctx context.Context, reader functionGrantReader, proof release.VerifiedFunction, binding FunctionBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	entry, err := reader.ReadFunctionGrant(ctx, binding.TaskID)
	if err != nil {
		return err
	}
	grant, err := DecodeFunctionGrant(entry)
	if err != nil {
		return err
	}
	claim := proof.Claim()
	if grant.TenantID != claim.TenantID || grant.FunctionID != claim.FunctionID || grant.Sequence != claim.Sequence ||
		grant.EnvelopeSHA256 != proof.EnvelopeSHA256() || grant.Binding != binding {
		return ErrConflict
	}
	return verifyFunctionIntent(ctx, reader, proof)
}

// ListFunctionIntents returns each current function head from the existing log.
func (r *Runtime) ListFunctionIntents(ctx context.Context) ([]LogEntry, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return listFunctionIntents(ctx, r.readStream, r.config.Scope)
}

func (r *Reader) ListFunctionIntents(ctx context.Context) ([]LogEntry, error) {
	if r == nil || r.stream == nil {
		return nil, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return listFunctionIntents(ctx, r.stream, r.scope)
}

func listFunctionIntents(ctx context.Context, stream jetstream.Stream, scope string) ([]LogEntry, error) {
	prefix := fmt.Sprintf("%s.%s.function.%s.", controlSubjectRoot, scope, MutationFunctionIntent)
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(prefix+">"))
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
		return nil, err
	}
	if len(info.State.Subjects) > 10000 {
		return nil, ErrListTooLarge
	}
	keys := make([]string, 0, len(info.State.Subjects))
	for subject := range info.State.Subjects {
		key, ok := strings.CutPrefix(subject, prefix)
		if !ok || validateMutationKey(MutationFunctionIntent, key) != nil {
			return nil, errors.New("function log subject is invalid")
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	entries := make([]LogEntry, 0, len(keys))
	for _, key := range keys {
		entry, err := readMutation(ctx, stream, scope, MutationFunctionIntent, key)
		if err != nil {
			return nil, err
		}
		if _, err := DecodeFunctionIntent(entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
