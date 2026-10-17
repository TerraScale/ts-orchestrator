package drainwire

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	MaxPoolDrains = 9
	MaxDrainTasks = 32
	PoolCaptured  = "captured"
	PoolStopped   = "stopped"
)

// PoolChild selects the original protected birth; none of these values grant
// authority without the root's independently loaded child and signed source.
type PoolChild struct {
	Cell               string `json:"cell"`
	BirthOperationID   string `json:"birth_operation_id"`
	RemovalOperationID string `json:"removal_operation_id"`
	InstanceID         string `json:"instance_id"`
	PoolID             string `json:"pool_id"`
	ConfigurationID    string `json:"configuration_id"`
	RecipeSHA256       string `json:"recipe_sha256"`
	GrantSHA256        string `json:"grant_sha256"`
	Generation         uint64 `json:"generation"`
}

// PoolSource records root's original accepted installation and regional lease.
// The home independently resolves the current signed source before consuming it.
type PoolSource struct {
	ControllerConfigSHA256 string    `json:"controller_config_sha256"`
	CellSpecSHA256         string    `json:"cell_spec_sha256"`
	CellSpecGeneration     uint64    `json:"cell_spec_generation"`
	RootSHA256             string    `json:"root_sha256"`
	ManagerInstanceID      string    `json:"manager_instance_id"`
	ManagerNodeID          string    `json:"manager_node_id"`
	DeploymentID           string    `json:"deployment_id"`
	CandidateID            string    `json:"candidate_id"`
	OwnerID                string    `json:"owner_id"`
	Epoch                  uint64    `json:"epoch"`
	LeaseRevision          uint64    `json:"lease_revision"`
	ExpiresAt              time.Time `json:"expires_at"`
}

type PoolTask struct {
	TaskID          string `json:"task_id"`
	ServiceID       string `json:"service_id"`
	TaskSHA256      string `json:"task_sha256"`
	ExecutionSHA256 string `json:"execution_sha256"`
}

// PoolReceipt is retained in the existing protected foundation CAS object.
// Captured tasks and holds never disappear when Swarm forgets a task.
type PoolReceipt struct {
	Child               PoolChild            `json:"child"`
	Source              PoolSource           `json:"source"`
	CellSpecWire        []byte               `json:"cell_spec_wire"`
	RootChainWire       []byte               `json:"root_chain_wire"`
	Host                HostSession          `json:"host"`
	NodeID              string               `json:"node_id"`
	ClusterID           string               `json:"cluster_id"`
	ClusterCAPEM        []byte               `json:"cluster_ca_pem"`
	ManagerCertificates [][]byte             `json:"manager_certificates"`
	WorkerCertificate   []byte               `json:"worker_certificate"`
	Tasks               []PoolTask           `json:"tasks"`
	Holds               []SignedHold         `json:"holds"`
	Challenges          []DrainStopChallenge `json:"challenges"`
	Stops               []SignedStop         `json:"stops,omitempty"`
	CapturedAt          time.Time            `json:"captured_at"`
	ExpiresAt           time.Time            `json:"expires_at"`
	Phase               string               `json:"phase"`
	StoppedAt           time.Time            `json:"stopped_at,omitzero"`
	BackendsCheckedAt   time.Time            `json:"backends_checked_at,omitzero"`
	DataCheckedAt       time.Time            `json:"data_checked_at,omitzero"`
}

func (c PoolChild) Validate() error {
	if c.Cell == "" || c.Cell != strings.ToUpper(c.Cell) || !entityid.Valid(c.BirthOperationID) ||
		!entityid.Valid(c.RemovalOperationID) || c.BirthOperationID == c.RemovalOperationID ||
		!strings.HasPrefix(c.InstanceID, "ocid1.instance.") || !strings.HasPrefix(c.PoolID, "ocid1.instancepool.") ||
		!strings.HasPrefix(c.ConfigurationID, "ocid1.instanceconfiguration.") || !digest(c.RecipeSHA256) ||
		!digest(c.GrantSHA256) || c.Generation == 0 {
		return errors.New("pool drain lacks the exact original child and removal identity")
	}
	return nil
}

func (r PoolReceipt) Validate() error {
	if err := r.Child.Validate(); err != nil {
		return err
	}
	source := r.Source
	if !digest(source.ControllerConfigSHA256) || !digest(source.CellSpecSHA256) || source.CellSpecGeneration == 0 ||
		!digest(source.RootSHA256) || !strings.HasPrefix(source.ManagerInstanceID, "ocid1.instance.") ||
		source.ManagerNodeID == "" || !entityid.Valid(source.DeploymentID) || !entityid.Valid(source.CandidateID) ||
		!entityid.Valid(source.OwnerID) || source.Epoch == 0 || source.LeaseRevision == 0 ||
		r.CapturedAt.IsZero() || !r.ExpiresAt.After(r.CapturedAt) || r.ExpiresAt.Sub(r.CapturedAt) > 30*time.Minute ||
		r.ExpiresAt.After(source.ExpiresAt) || r.ClusterID == "" || r.NodeID == "" || r.NodeID == source.ManagerNodeID ||
		len(r.ClusterCAPEM) == 0 || len(r.ClusterCAPEM) > 32<<10 || len(r.WorkerCertificate) == 0 || len(r.WorkerCertificate) > 16<<10 ||
		len(r.ManagerCertificates) == 0 || len(r.ManagerCertificates) > 3 ||
		len(r.CellSpecWire) == 0 || len(r.CellSpecWire) > 48<<10 || len(r.RootChainWire) == 0 || len(r.RootChainWire) > 64<<10 ||
		r.Host.Cell != strings.ToLower(r.Child.Cell) || r.Host.InstanceID != r.Child.InstanceID ||
		r.Host.HostNode == "" || !entityid.Valid(r.Host.RegistrationID) || !entityid.Valid(r.Host.HostSessionID) || r.Host.RegistrationGeneration == 0 ||
		r.Host.HostEpoch == 0 || r.ExpiresAt.After(r.Host.ExpiresAt) ||
		len(r.Tasks) > MaxDrainTasks || len(r.Holds) > MaxDrainTasks || len(r.Challenges) != len(r.Holds) || len(r.Stops) > len(r.Holds) {
		return errors.New("pool drain capture lacks bounded original root, session, lease or task evidence")
	}
	if fmt.Sprintf("%x", sha256.Sum256(r.CellSpecWire)) != source.CellSpecSHA256 ||
		fmt.Sprintf("%x", sha256.Sum256(r.RootChainWire)) != source.RootSHA256 {
		return errors.New("pool drain signed source differs from its retained exact bytes")
	}
	for _, certificate := range r.ManagerCertificates {
		if len(certificate) == 0 || len(certificate) > 16<<10 {
			return errors.New("pool drain manager certificate exceeds retained identity bounds")
		}
	}
	if r.Phase != PoolCaptured && r.Phase != PoolStopped ||
		r.Phase == PoolCaptured && !r.StoppedAt.IsZero() || r.Phase == PoolStopped &&
		(r.StoppedAt.Before(r.CapturedAt) || !r.StoppedAt.Before(r.ExpiresAt) || len(r.Stops) != len(r.Holds) ||
			r.BackendsCheckedAt.Before(r.CapturedAt) || r.BackendsCheckedAt.After(r.StoppedAt) ||
			r.DataCheckedAt.Before(r.CapturedAt) || r.DataCheckedAt.After(r.StoppedAt)) {
		return errors.New("pool drain phase has no complete stopped and fence observation")
	}
	seenTasks := make(map[string]bool, len(r.Tasks))
	for _, task := range r.Tasks {
		if task.TaskID == "" || task.ServiceID == "" || !digest(task.TaskSHA256) || !digest(task.ExecutionSHA256) || seenTasks[task.TaskID] {
			return errors.New("pool drain has an invalid or duplicate captured task")
		}
		seenTasks[task.TaskID] = true
		if !slices.ContainsFunc(r.Holds, func(hold SignedHold) bool {
			return hold.Hold.TaskID == task.TaskID && hold.Hold.ServiceID == task.ServiceID &&
				hold.Hold.TaskSHA256 == task.TaskSHA256 && hold.Hold.ExecutionSHA256 == task.ExecutionSHA256
		}) {
			return errors.New("captured task has no original possible-execution hold")
		}
	}
	seenExecutions := make(map[string]bool, len(r.Holds))
	for index, signed := range r.Holds {
		hold, challenge := signed.Hold, r.Challenges[index]
		if err := hold.Validate(); err != nil {
			return err
		}
		if hold.InstanceID != r.Child.InstanceID || hold.NodeID != r.NodeID || !hold.HostSession.SameIdentity(r.Host) ||
			hold.IssuedAt.After(r.CapturedAt) || hold.OriginalEpoch > source.Epoch ||
			seenExecutions[hold.ExecutionSessionID] || !seenTasks[hold.TaskID] || !challenge.Matches(hold) ||
			challenge.BirthOperationID != r.Child.BirthOperationID || challenge.RemovalOperationID != r.Child.RemovalOperationID ||
			challenge.Epoch != source.Epoch || !challenge.IssuedAt.Equal(r.CapturedAt) || !challenge.Deadline.Equal(r.ExpiresAt) ||
			!digest(challenge.Nonce) {
			return errors.New("pool drain changed or omitted its original possible execution")
		}
		seenExecutions[hold.ExecutionSessionID] = true
	}
	seenStops := make(map[string]bool, len(r.Stops))
	for _, stop := range r.Stops {
		index := slices.IndexFunc(r.Challenges, func(challenge DrainStopChallenge) bool { return challenge == stop.Challenge })
		if index < 0 || seenStops[stop.Challenge.ExecutionSessionID] || stop.ObservedAt.Before(r.CapturedAt) ||
			!stop.ObservedAt.Before(r.ExpiresAt) || len(stop.CertificateChain) == 0 || len(stop.CertificateChain) > 8 ||
			len(stop.Signature) == 0 || len(stop.Signature) > 1024 {
			return errors.New("pool drain stop differs from a retained exact execution challenge")
		}
		seenStops[stop.Challenge.ExecutionSessionID] = true
	}
	return nil
}

// SHA256 is a locator; only the actual protected object and independent root
// checks authorize retirement.
func (r PoolReceipt) SHA256() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	wire, err := json.Marshal(r, json.Deterministic(true))
	return fmt.Sprintf("%x", sha256.Sum256(wire)), err
}

// Retains forbids rewriting a capture or losing an accepted stop on a CAS.
func (r PoolReceipt) Retains(previous PoolReceipt) error {
	if err := r.Validate(); err != nil {
		return err
	}
	old, next := previous, r
	old.Stops, next.Stops = nil, nil
	old.Phase, next.Phase = "", ""
	old.StoppedAt, next.StoppedAt = time.Time{}, time.Time{}
	old.BackendsCheckedAt, next.BackendsCheckedAt = time.Time{}, time.Time{}
	old.DataCheckedAt, next.DataCheckedAt = time.Time{}, time.Time{}
	want, err := json.Marshal(old, json.Deterministic(true))
	if err != nil {
		return err
	}
	got, err := json.Marshal(next, json.Deterministic(true))
	if err != nil || string(got) != string(want) || previous.Phase == PoolStopped && r.Phase != PoolStopped ||
		!previous.StoppedAt.IsZero() && !previous.StoppedAt.Equal(r.StoppedAt) {
		return errors.New("pool drain cannot replace its original capture or stopped observation")
	}
	for _, stop := range previous.Stops {
		wire, err := json.Marshal(stop, json.Deterministic(true))
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(r.Stops, func(current SignedStop) bool {
			got, err := json.Marshal(current, json.Deterministic(true))
			return err == nil && string(got) == string(wire)
		}) {
			return errors.New("pool drain cannot discard an accepted stopped proof")
		}
	}
	return nil
}
