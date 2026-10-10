package identityrekey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nkeys"
)

const (
	HostStateHandoffDomain = "terrascale.identity-rekey.host-state-handoff"
	MaxHostStatePlanBytes  = 512 << 10
	HostStateQuiescence    = 32 * time.Second // Host execution lease plus clock skew.
	hostStateBucket        = "TS_HOST_STATE"
)

var ErrHostStateHandoff = errors.New("host state handoff is invalid")

type HostStateAction = authority.IdentityResetAction

const (
	HostStateDelete     HostStateAction = authority.IdentityResetDeleteKV
	HostStateReplaceKV  HostStateAction = authority.IdentityResetReplaceKV
	HostStateAppendHead HostStateAction = authority.IdentityResetAppendHostHead
)

// HostStatePrecondition is an independently observed leader-backed predecessor.
// Revision zero means absent; tombstones also pin the exact KV-Operation header.
type HostStatePrecondition struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	Revision  uint64 `json:"revision"`
	SHA256    string `json:"sha256"`
	Operation string `json:"operation,omitempty"`
}

type HostStateDesired struct {
	Target              host.Desired `json:"target"`
	GenerationFloor     uint64       `json:"generation_floor"`
	AuthorityEpochFloor uint64       `json:"authority_epoch_floor"`
}

// HostStateVolume pins an existing mount and local consumption marker. Neither
// is a mutation target: this plan can only recreate a CLOSED confirmation.
type HostStateVolume struct {
	VolumeID             string `json:"volume_id"`
	UUID                 string `json:"uuid"`
	FileSystemType       string `json:"filesystem_type"`
	DataPath             string `json:"data_path"`
	NativeClusterID      string `json:"native_cluster_id"`
	StateRoot            string `json:"state_root"`
	ConsumedMarkerSHA256 string `json:"consumed_marker_sha256"`
	Mounted              bool   `json:"mounted"`
}

// HostStateHost includes inactive registrations as well as running hosts.
// Registration and desired targets are independently verified current facts,
// never decoded from the obsolete predecessor bytes.
// A retired static orphan may omit instance/request evidence; it receives no grant.
type HostStateHost struct {
	InstanceOCID                string             `json:"instance_ocid"`
	Registration                host.Registration  `json:"registration"`
	RegistrationGenerationFloor uint64             `json:"registration_generation_floor"`
	Retired                     bool               `json:"retired"`
	EnrollmentRequest           []byte             `json:"enrollment_request"`
	Desired                     []HostStateDesired `json:"desired"`
	Volume                      *HostStateVolume   `json:"volume,omitempty"`
}

// HostStateObservation must inventory every host registration/desired head and
// host/enrollment KV key in this cell, including absence at new destinations.
// The installer establishes inventory completeness and writer shutdown before
// supplying these facts; a signed plan cannot establish either by itself.
type HostStateObservation struct {
	OperationID         string                  `json:"operation_id"`
	DeploymentID        string                  `json:"deployment_id"`
	ClusterID           string                  `json:"cluster_id"`
	Cell                string                  `json:"cell"`
	Environment         string                  `json:"environment"`
	CheckpointSHA256    string                  `json:"checkpoint_sha256"`
	EpochFloor          uint64                  `json:"epoch_floor"`
	Epoch               uint64                  `json:"epoch"`
	PreviousResponseKey string                  `json:"previous_response_key"`
	ResponseKey         string                  `json:"response_key"`
	AgentsStoppedAt     time.Time               `json:"agents_stopped_at"`
	ObservedAt          time.Time               `json:"observed_at"`
	Hosts               []HostStateHost         `json:"hosts"`
	Preconditions       []HostStatePrecondition `json:"preconditions"`
}

// HostStateRecord supplies typed root pins and exact successor bytes.
type HostStateRecord struct {
	Action HostStateAction               `json:"action"`
	Pin    authority.IdentityResetRecord `json:"pin"`
	Value  []byte                        `json:"value,omitempty"`
}

type HostStateHandoffPlan struct {
	Version     int                  `json:"version"`
	Observation HostStateObservation `json:"observation"`
	Records     []HostStateRecord    `json:"records"`
}

// VerifiedHostStateHandoffPlan exposes no caller-editable mutation authority.
type VerifiedHostStateHandoffPlan struct {
	plan        HostStateHandoffPlan
	fingerprint string
	verified    bool
}

func (verified VerifiedHostStateHandoffPlan) IsVerified() bool    { return verified.verified }
func (verified VerifiedHostStateHandoffPlan) Fingerprint() string { return verified.fingerprint }

// MatchIdentityReset binds these additional pins to the parent's transaction.
// The reset keeps its three shared singletons first, followed by these pins.
// Callers must match the independently verified plan before any reset effects.
func (verified VerifiedHostStateHandoffPlan) MatchIdentityReset(reset authority.IdentityReset) error {
	if err := reset.Validate(); err != nil {
		return fmt.Errorf("%w: identity reset: %w", ErrHostStateHandoff, err)
	}
	o := verified.plan.Observation
	if !verified.verified || reset.Version != 1 || reset.OperationID != o.OperationID ||
		reset.DeploymentID != o.DeploymentID || reset.ClusterID != o.ClusterID || reset.Scope != strings.ToLower(o.Cell) ||
		reset.Environment != o.Environment || reset.CheckpointSHA256 != o.CheckpointSHA256 ||
		reset.HostStatePlanSHA256 != verified.fingerprint ||
		reset.Epoch != o.Epoch || reset.EpochFloor != o.EpochFloor || len(reset.Records) != 3+len(verified.plan.Records) {
		return fmt.Errorf("%w: identity reset target or record count", ErrHostStateHandoff)
	}
	for i, pin := range verified.IdentityResetRecords() {
		if reset.Records[i+3] != pin {
			return fmt.Errorf("%w: identity reset host pin", ErrHostStateHandoff)
		}
	}
	return nil
}

func (verified VerifiedHostStateHandoffPlan) Records() []HostStateRecord {
	if !verified.verified {
		return nil
	}
	records := slices.Clone(verified.plan.Records)
	for i := range records {
		records[i].Value = bytes.Clone(records[i].Value)
	}
	return records
}

func (verified VerifiedHostStateHandoffPlan) IdentityResetRecords() []authority.IdentityResetRecord {
	var pins []authority.IdentityResetRecord
	for _, record := range verified.Records() {
		pins = append(pins, record.Pin)
	}
	return pins
}

func (verified VerifiedHostStateHandoffPlan) Values() [][]byte {
	var values [][]byte
	for _, record := range verified.Records() {
		values = append(values, record.Value)
	}
	return values
}

// BuildHostStateHandoffPlan derives all destinations and bytes from typed facts.
// It accepts no caller-supplied replacement bytes or arbitrary mutation keys.
func BuildHostStateHandoffPlan(observed HostStateObservation, now time.Time) (HostStateHandoffPlan, error) {
	if !validIdentity(observed.OperationID, observed.DeploymentID, observed.ClusterID, observed.Environment, observed.Cell) ||
		!digestRE.MatchString(observed.CheckpointSHA256) || observed.EpochFloor == 0 ||
		observed.Epoch <= observed.EpochFloor || observed.Epoch == ^uint64(0) ||
		observed.AgentsStoppedAt.IsZero() || observed.ObservedAt.Before(observed.AgentsStoppedAt.Add(HostStateQuiescence)) ||
		observed.ObservedAt.After(now) || len(observed.Hosts) > 128 ||
		!hostStatePublicKey(observed.PreviousResponseKey) || !hostStatePublicKey(observed.ResponseKey) ||
		observed.PreviousResponseKey == observed.ResponseKey {
		return HostStateHandoffPlan{}, fmt.Errorf("%w: identity, fresh signer, epoch or regional quiescence", ErrHostStateHandoff)
	}
	cell := strings.ToLower(observed.Cell)
	plan := HostStateHandoffPlan{Version: 1, Observation: observed}
	allowed := map[string]HostStateRecord{}
	required := map[string]bool{}
	add := func(bucket, key string, action HostStateAction, value []byte, mandatory bool) error {
		id := bucket + "/" + key
		if _, exists := allowed[id]; exists {
			return fmt.Errorf("%w: duplicate host destination %s", ErrHostStateHandoff, id)
		}
		pin := authority.IdentityResetRecord{Action: action, Bucket: bucket, Key: key}
		if action != HostStateDelete {
			pin.SHA256 = sha256Hex(value)
		}
		allowed[id] = HostStateRecord{Action: action, Pin: pin, Value: value}
		if mandatory {
			required[id] = true
		}
		return nil
	}
	addHead := func(kind authority.HostMutationKind, key string, payload any) error {
		data, err := protocol.EncodeJSON(payload)
		if err != nil || len(data) > 64<<10 {
			return fmt.Errorf("%w: host payload size or encoding", ErrHostStateHandoff)
		}
		wire, err := protocol.EncodeJSON(struct {
			Version     int                        `json:"version"`
			Kind        authority.HostMutationKind `json:"kind"`
			Scope       string                     `json:"scope"`
			SubjectKey  string                     `json:"subject_key"`
			OperationID string                     `json:"operation_id"`
			Epoch       uint64                     `json:"epoch"`
			Payload     []byte                     `json:"payload"`
		}{1, kind, cell, key, entityid.Derive("host-mutation", sha256Hex(data)), observed.Epoch, data})
		if err != nil {
			return err
		}
		return add(authority.ControlStreamName, protocol.Control(cell, "host", string(kind), key), HostStateAppendHead, wire, true)
	}
	seenNodes, seenInstances := map[string]bool{}, map[string]bool{}
	orphanHeads := map[string]bool{}
	for _, facts := range observed.Hosts {
		if err := validateHostStateFacts(facts, observed, now); err != nil {
			return HostStateHandoffPlan{}, err
		}
		r := facts.Registration
		if seenNodes[r.Node] || facts.InstanceOCID != "" && seenInstances[facts.InstanceOCID] {
			return HostStateHandoffPlan{}, fmt.Errorf("%w: duplicate node or instance", ErrHostStateHandoff)
		}
		seenNodes[r.Node], seenInstances[facts.InstanceOCID] = true, true
		r.ID, r.Generation = entityid.Derive("host", cell, r.Node), facts.RegistrationGenerationFloor+1
		if err := addHead(authority.MutationRegistration, cell+"."+r.Node, r); err != nil {
			return HostStateHandoffPlan{}, err
		}
		if facts.InstanceOCID == "" {
			orphanHeads[authority.ControlStreamName+"/"+protocol.Control(cell, "host", "registration", cell+"."+r.Node)] = true
		}
		if err := addHead(authority.MutationRetirement, cell+"."+r.Node, struct {
			Retired bool `json:"retired"`
		}{facts.Retired}); err != nil {
			return HostStateHandoffPlan{}, err
		}
		for _, target := range facts.Desired {
			d := target.Target
			d.Generation, d.AuthorityEpoch = target.GenerationFloor+1, observed.Epoch
			if err := addHead(authority.MutationDesired, cell+"."+r.Node+"."+d.Role, d); err != nil {
				return HostStateHandoffPlan{}, err
			}
			if facts.InstanceOCID == "" {
				orphanHeads[authority.ControlStreamName+"/"+protocol.Control(cell, "host", "desired", cell+"."+r.Node+"."+d.Role)] = true
			}
			for _, prefix := range []string{"cycle", "report", "desired"} {
				if err := add(hostStateBucket, prefix+"."+cell+"."+r.Node+"."+d.Role, HostStateDelete, nil, false); err != nil {
					return HostStateHandoffPlan{}, err
				}
			}
		}
		for _, prefix := range []string{"session", "retired", "retirement-quarantine"} {
			if err := add(hostStateBucket, prefix+"."+cell+"."+r.Node, HostStateDelete, nil, true); err != nil {
				return HostStateHandoffPlan{}, err
			}
		}
		// Retiring an obsolete node must not revoke a surviving renamed instance.
		if facts.InstanceOCID == "" {
			continue
		}
		request, descriptor, _ := parseHostStateEnrollmentRequest(facts.EnrollmentRequest, now)
		descriptorDigest, _ := descriptor.Digest()
		grant := hostenroll.Grant{SchemaVersion: 1, InstanceID: request.InstanceID,
			CreateKey: entityid.Derive("static-enrollment", cell, r.Node), DescriptorSHA256: descriptorDigest,
			Request: bytes.Clone(facts.EnrollmentRequest), Disabled: facts.Retired}
		if facts.Retired {
			grant.TerminalOperationID = observed.OperationID
		} else {
			grant.IdentityResetOperationID = observed.OperationID
		}
		wire, err := protocol.EncodeJSON(grant)
		if err != nil {
			return HostStateHandoffPlan{}, err
		}
		if err := add(hostenroll.GrantBucket, sha256Hex([]byte(facts.InstanceOCID)), HostStateDelete, nil, true); err != nil {
			return HostStateHandoffPlan{}, err
		}
		if err := add(hostenroll.GrantBucket, entityid.Derive("host-enrollment", facts.InstanceOCID), HostStateReplaceKV, wire, true); err != nil {
			return HostStateHandoffPlan{}, err
		}
		if facts.Volume != nil {
			volume := facts.Volume
			closed, err := protocol.EncodeJSON(struct {
				UUID string `json:"uuid"`
			}{volume.UUID})
			if err != nil {
				return HostStateHandoffPlan{}, err
			}
			if err := add(hostStateBucket, "terrabase-format."+cell+"."+r.Node+"."+sha256Hex([]byte(volume.VolumeID)), HostStateDelete, nil, true); err != nil {
				return HostStateHandoffPlan{}, err
			}
			if err := add(hostStateBucket, entityid.Derive("terrabase-format", cell, r.Node, volume.VolumeID), HostStateReplaceKV, closed, true); err != nil {
				return HostStateHandoffPlan{}, err
			}
		}
	}
	if err := add(hostStateBucket, "retirement-cutover."+cell, HostStateDelete, nil, true); err != nil {
		return HostStateHandoffPlan{}, err
	}
	seen := map[string]bool{}
	for _, previous := range observed.Preconditions {
		id := previous.Bucket + "/" + previous.Key
		record, ok := allowed[id]
		if !ok || seen[id] || orphanHeads[id] && previous.Revision == 0 || previous.Revision == 0 && previous.SHA256 != "" || previous.Revision != 0 && !digestRE.MatchString(previous.SHA256) ||
			previous.Operation != "" && (record.Action == HostStateAppendHead || previous.Revision == 0 ||
				previous.SHA256 != sha256Hex(nil) || previous.Operation != "DEL" && previous.Operation != "PURGE") {
			return HostStateHandoffPlan{}, fmt.Errorf("%w: unknown, duplicate or invalid predecessor %s", ErrHostStateHandoff, id)
		}
		seen[id] = true
		delete(required, id)
		record.Pin.PreviousRevision, record.Pin.PreviousSHA256 = previous.Revision, previous.SHA256
		record.Pin.PreviousOperation = previous.Operation
		plan.Records = append(plan.Records, record)
	}
	if len(required) != 0 {
		return HostStateHandoffPlan{}, fmt.Errorf("%w: missing exact predecessor observations", ErrHostStateHandoff)
	}
	slices.SortFunc(plan.Records, func(a, b HostStateRecord) int {
		return strings.Compare(a.Pin.Bucket+"/"+a.Pin.Key, b.Pin.Bucket+"/"+b.Pin.Key)
	})
	wire, err := trust.EncodePayload(plan)
	if err != nil || len(wire) > MaxHostStatePlanBytes {
		return HostStateHandoffPlan{}, fmt.Errorf("%w: plan size or encoding", ErrHostStateHandoff)
	}
	return plan, nil
}

func hostStatePublicKey(value string) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(key) == ed25519.PublicKeySize && base64.StdEncoding.EncodeToString(key) == value
}

func validateHostStateFacts(facts HostStateHost, observed HostStateObservation, now time.Time) error {
	r := facts.Registration
	cell := strings.ToLower(observed.Cell)
	orphan := facts.Retired && facts.InstanceOCID == "" && len(facts.EnrollmentRequest) == 0 && r.TerraBaseDataVolumeID == "" && facts.Volume == nil
	if !orphan && !regionalOCID(facts.InstanceOCID, "instance", observed.Cell) || r.Cell != cell || !hostStateToken(r.Node) ||
		r.Environment != observed.Environment || r.ID != entityid.Derive("host", cell, r.Node) ||
		r.ManagedOCI != nil || r.ManagedPlacement != nil || r.ManagedMember != nil || r.SystemReserveBytes != 0 ||
		r.Generation == 0 || r.Generation > facts.RegistrationGenerationFloor || facts.RegistrationGenerationFloor == ^uint64(0) ||
		r.Capacity.CPU <= 0 || r.Capacity.MemoryBytes <= 0 || r.Capacity.DiskBytes <= 0 ||
		len(r.Roles) == 0 || len(r.Roles) > 32 || len(facts.Desired) != len(r.Roles) ||
		!hostStatePublicKey(r.PublicKey) || !nkeys.IsValidPublicUserKey(r.NATSUserPublicKey) || r.FailureDomain != "" && !hostStateToken(r.FailureDomain) {
		return fmt.Errorf("%w: host facts or unsupported managed registration", ErrHostStateHandoff)
	}
	if !orphan {
		request, descriptor, err := parseHostStateEnrollmentRequest(facts.EnrollmentRequest, now)
		if err != nil || !descriptor.IsStatic() || descriptor.Cell != cell || descriptor.Node != r.Node ||
			request.Operation != "enroll" || request.InstanceID != facts.InstanceOCID ||
			request.IdentityPublicKey != r.PublicKey || request.NATSUserPublicKey != r.NATSUserPublicKey {
			return fmt.Errorf("%w: exact validated static enrollment request", ErrHostStateHandoff)
		}
	}
	seen := map[string]bool{}
	for _, role := range r.Roles {
		if !hostStateToken(role) || seen[role] {
			return fmt.Errorf("%w: host roles", ErrHostStateHandoff)
		}
		seen[role] = true
	}
	for _, target := range facts.Desired {
		d := target.Target
		if !seen[d.Role] || d.Cell != cell || d.Node != r.Node || d.Environment != r.Environment || d.ManagedMember != nil ||
			d.Generation == 0 || d.Generation > target.GenerationFloor || target.GenerationFloor == ^uint64(0) ||
			d.AuthorityEpoch == 0 || d.AuthorityEpoch > target.AuthorityEpochFloor || observed.Epoch <= target.AuthorityEpochFloor ||
			facts.Retired && !d.Withdrawn || len(d.Args) > 64 || len(d.Env) > 64 ||
			d.Withdrawn && (d.Digest != "" || len(d.Args)+len(d.Env)+len(d.Secrets) != 0) ||
			!d.Withdrawn && !digestRE.MatchString(d.Digest) {
			return fmt.Errorf("%w: desired target, host, generation or authority floor", ErrHostStateHandoff)
		}
		delete(seen, d.Role)
		for _, arg := range d.Args {
			if len(arg) > 4096 {
				return fmt.Errorf("%w: desired argument", ErrHostStateHandoff)
			}
		}
		for key, value := range d.Env {
			if !hostStateEnvKey(key) || len(value) > 4096 || roleidentity.Reserved(d.Role, key) {
				return fmt.Errorf("%w: desired environment", ErrHostStateHandoff)
			}
		}
		for key := range d.Secrets {
			if roleidentity.Reserved(d.Role, key) || d.Role == terrabase.Role && !vaultsecret.FileKey(key) {
				return fmt.Errorf("%w: desired secret", ErrHostStateHandoff)
			}
		}
		if err := vaultsecret.ValidateRefs(d.Cell, d.Role, d.Secrets, d.Env); err != nil {
			return err
		}
		if d.Role == terrabase.Role && !d.Withdrawn {
			if _, err := terrabase.ParseProfile(d.Env); err != nil {
				return err
			}
		}
	}
	if orphan {
		return nil
	}
	if r.TerraBaseDataVolumeID == "" && facts.Volume != nil {
		return fmt.Errorf("%w: missing or foreign existing-volume proof", ErrHostStateHandoff)
	}
	if r.TerraBaseDataVolumeID != "" {
		v := facts.Volume
		if v == nil || v.VolumeID != r.TerraBaseDataVolumeID || !regionalOCID(v.VolumeID, "volume", observed.Cell) ||
			!slices.Contains(r.Roles, terrabase.Role) || !v.Mounted || v.FileSystemType != "ext4" ||
			!hostvolume.ValidUUID(v.UUID) || !hostStatePath(v.DataPath) || !hostStatePath(v.StateRoot) ||
			v.DataPath == v.StateRoot || strings.HasPrefix(v.DataPath, v.StateRoot+"/") || strings.HasPrefix(v.StateRoot, v.DataPath+"/") ||
			!nameRE.MatchString(v.NativeClusterID) || !digestRE.MatchString(v.ConsumedMarkerSHA256) {
			return fmt.Errorf("%w: exact mounted volume, native identity or consumed marker", ErrHostStateHandoff)
		}
		for _, target := range facts.Desired {
			if cluster := target.Target.Env["TERRABASE_CLUSTER_ID"]; cluster != "" && cluster != v.NativeClusterID {
				return fmt.Errorf("%w: native cluster differs from desired environment", ErrHostStateHandoff)
			}
		}
	}
	return nil
}

func hostStateToken(value string) bool {
	return len(value) > 0 && len(value) <= 63 && value[0] != '-' && value[len(value)-1] != '-' &&
		!strings.ContainsFunc(value, func(r rune) bool { return r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') })
}

func hostStateEnvKey(value string) bool {
	if value == "" || value[0] >= '0' && value[0] <= '9' {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
}

func hostStatePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && len(value) <= 1024 &&
		!strings.ContainsAny(value, "\x00\r\n\t ")
}

func (plan HostStateHandoffPlan) scope() trust.Scope {
	o := plan.Observation
	return trust.Scope{Domain: HostStateHandoffDomain, DeploymentID: o.DeploymentID, Cell: o.Cell,
		Environment: o.Environment, Role: "authority", Slot: o.OperationID}
}

func (plan HostStateHandoffPlan) Validate(now time.Time) error {
	expected, err := BuildHostStateHandoffPlan(plan.Observation, now)
	if err != nil {
		return err
	}
	want, err := trust.EncodePayload(expected)
	got, gotErr := trust.EncodePayload(plan)
	if err != nil || gotErr != nil || !bytes.Equal(want, got) {
		return fmt.Errorf("%w: plan must contain exactly the derived v1 records", ErrHostStateHandoff)
	}
	return nil
}

func SignHostStateHandoffPlan(plan HostStateHandoffPlan, issuedAt, expiresAt time.Time, root ed25519.PrivateKey) (trust.Envelope, error) {
	if err := plan.Validate(issuedAt); err != nil {
		return trust.Envelope{}, err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > time.Hour {
		return trust.Envelope{}, ErrHostStateHandoff
	}
	payload, err := trust.EncodePayload(plan)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.Sign(payload, plan.scope(), issuedAt, expiresAt, root)
}

func VerifyHostStateHandoffPlan(envelope trust.Envelope, currentRoots trust.Keyring, observed HostStateObservation, now time.Time) (VerifiedHostStateHandoffPlan, error) {
	expected, err := BuildHostStateHandoffPlan(observed, now)
	if err != nil {
		return VerifiedHostStateHandoffPlan{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, expected.scope(), currentRoots, now, trust.Policy{MaxLifetime: time.Hour})
	if err != nil {
		return VerifiedHostStateHandoffPlan{}, err
	}
	var plan HostStateHandoffPlan
	if err := protocol.DecodeStrict(payload, &plan, MaxHostStatePlanBytes); err != nil {
		return VerifiedHostStateHandoffPlan{}, err
	}
	want, err := trust.EncodePayload(expected)
	if err != nil || !bytes.Equal(payload, want) {
		return VerifiedHostStateHandoffPlan{}, fmt.Errorf("%w: root plan differs from independent facts or canonical bytes", ErrHostStateHandoff)
	}
	return VerifiedHostStateHandoffPlan{plan: plan, fingerprint: sha256Hex(payload), verified: true}, nil
}

// Retained enrollment evidence is verified at issuance, then bound to the
// independently observed registration before recreating its exact grant.
func parseHostStateEnrollmentRequest(wire []byte, now time.Time) (hostenroll.Request, hostboot.Descriptor, error) {
	var original hostenroll.Request
	if err := protocol.DecodeStrict(wire, &original, hostenroll.MaxRequestBytes); err != nil {
		return hostenroll.Request{}, hostboot.Descriptor{}, err
	}
	if original.IssuedAt.IsZero() || original.IssuedAt.After(now.Add(30*time.Second)) {
		return hostenroll.Request{}, hostboot.Descriptor{}, ErrHostStateHandoff
	}
	return hostenroll.ParseRequest(wire, original.IssuedAt)
}
