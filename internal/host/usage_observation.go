package host

import (
	"context"
	"encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

// UsageTask records resources independently verified against the manager's task
// and its signed release. Host-reported identity pins alone grant no authority.
type UsageTask struct {
	Role          string           `json:"role"`
	Task          hostload.TaskPin `json:"task"`
	Request       hostload.Request `json:"request"`
	ReleaseSHA256 string           `json:"release_sha256"`
	SpecSHA256    string           `json:"spec_sha256"`
}

// UsageObservation is a point observation in the existing host control log.
// PreviousSequence closes an interval only when the manager's actual versioned
// event history proves uninterrupted allocation identity through this commit.
type UsageObservation struct {
	Version          int                         `json:"version"`
	Registration     Registration                `json:"registration"`
	DeploymentID     string                      `json:"deployment_id"`
	Epoch            uint64                      `json:"epoch"`
	SessionID        string                      `json:"session_id"`
	ManagerVersion   uint64                      `json:"manager_version"`
	PreviousSequence uint64                      `json:"previous_sequence,omitzero"`
	Tasks            []UsageTask                 `json:"tasks,omitempty"`
	Requests         map[string]hostload.Request `json:"requests"`
	Report           hostload.Report             `json:"report"`
}

type CommittedUsage struct {
	Observation UsageObservation
	Entry       authority.LogEntry
}

// CommitUsageObservation accepts only a current signed host load request. Its
// verifier runs inside the same authority CAS retry as the durable append.
func (c *Controller) CommitUsageObservation(ctx context.Context, observation UsageObservation,
	verify func(context.Context) error,
) (CommittedUsage, error) {
	caller, ok := ctx.Value(loadObservationContextKey{}).(loadObservationCaller)
	if !ok || caller.controller != c || verify == nil || !reflect.DeepEqual(caller.registration, observation.Registration) {
		return CommittedUsage{}, errors.New("usage observation requires its authenticated host request")
	}
	observation.Version = 1
	observation.SessionID = caller.request.SessionID
	if err := validateUsageObservation(observation, c.cell); err != nil {
		return CommittedUsage{}, err
	}
	store, ok := c.mutations.(authority.VerifiedHostMutationStore)
	if !ok || c.controlLog == nil {
		return CommittedUsage{}, errors.New("usage observation requires the verified durable host journal")
	}
	key := registrationSubjectKey(c.cell, observation.Registration.Node)
	previous, err := c.mutations.ReadHostMutation(ctx, authority.MutationUsageObservation, key)
	if err != nil && !errors.Is(err, authority.ErrNotFound) {
		return CommittedUsage{}, err
	}
	if observation.PreviousSequence != 0 && observation.PreviousSequence != previous.Sequence {
		return CommittedUsage{}, errors.New("usage continuity differs from the committed predecessor")
	}
	data, err := json.Marshal(observation)
	if err != nil {
		return CommittedUsage{}, err
	}
	operation := entityid.New()
	sequence, err := store.CommitHostMutationVerified(ctx, observation.Epoch, authority.MutationUsageObservation,
		key, operation, previous.Sequence, data, func(ctx context.Context) error {
			if err := c.recheckReplyAuthority(ctx, observation.Epoch, caller.request, caller.registration, false); err != nil {
				return err
			}
			return verify(ctx)
		})
	if err != nil {
		return CommittedUsage{}, err
	}
	// Read this exact acknowledged sequence; a newer report must not substitute
	// its receive timestamp or resource requests for this sample.
	raw, err := c.controlLog.GetMsg(ctx, sequence)
	if err != nil {
		return CommittedUsage{}, err
	}
	entry, err := authority.DecodeUsageObservationEntry(raw, c.cell)
	if err != nil || entry.OperationID != operation || !slices.Equal(entry.Payload, data) {
		return CommittedUsage{}, errors.Join(err, errors.New("committed usage observation differs from its acknowledgement"))
	}
	return CommittedUsage{Observation: observation, Entry: entry}, nil
}

func validateUsageObservation(value UsageObservation, cell string) error {
	if value.Version != 1 || value.Epoch == 0 || !entityid.Valid(value.DeploymentID) ||
		!entityid.Valid(value.SessionID) || value.ManagerVersion == 0 || value.Registration.ID != entityid.Derive("host", cell, value.Registration.Node) {
		return errors.New("usage observation identity, version or manager watermark is invalid")
	}
	if err := validateRegistration(value.Registration, cell); err != nil {
		return err
	}
	if err := value.Report.Validate(); err != nil {
		return err
	}
	if len(value.Requests) > hostload.MaxRoles || len(value.Tasks) > hostload.MaxTasks {
		return errors.New("usage observation exceeds allocation bounds")
	}
	for role, request := range value.Requests {
		if !slices.Contains(value.Registration.Roles, role) || math.IsNaN(request.CPUCores) || math.IsInf(request.CPUCores, 0) ||
			request.CPUCores <= 0 || request.CPUCores > hostload.MaxCPUCores || request.MemoryBytes <= 0 || request.MemoryBytes > hostload.MaxMemoryBytes {
			return errors.New("usage observation has invalid adopted requests")
		}
	}
	pins := map[string]UsageTask{}
	sums := map[string]hostload.Request{}
	for _, task := range value.Tasks {
		if _, repeated := pins[task.Task.TaskID]; repeated || validateDigest(task.ReleaseSHA256) != nil || validateDigest(task.SpecSHA256) != nil ||
			!slices.Contains(value.Registration.Roles, task.Role) || task.Request.CPUCores <= 0 || math.IsNaN(task.Request.CPUCores) || math.IsInf(task.Request.CPUCores, 0) ||
			task.Request.CPUCores > hostload.MaxCPUCores || task.Request.MemoryBytes <= 0 || task.Request.MemoryBytes > hostload.MaxMemoryBytes {
			return errors.New("usage observation has invalid manager task resources or proof pins")
		}
		pins[task.Task.TaskID] = task
		sum := sums[task.Role]
		sum.CPUCores += task.Request.CPUCores
		if sum.CPUCores > hostload.MaxCPUCores || sum.MemoryBytes > hostload.MaxMemoryBytes-task.Request.MemoryBytes {
			return errors.New("usage observation task resource sum exceeds bounds")
		}
		sum.MemoryBytes += task.Request.MemoryBytes
		sums[task.Role] = sum
	}
	for role, sum := range sums {
		if value.Requests[role] != sum {
			return errors.New("usage observation requests differ from exact manager task resources")
		}
	}
	for _, role := range value.Report.Roles {
		if !slices.Contains(value.Registration.Roles, role.Role) {
			return errors.New("usage observation contains an unregistered role")
		}
		for _, pin := range role.Tasks {
			task, exists := pins[pin.TaskID]
			if !exists || task.Role != role.Role || task.Task != pin {
				return errors.New("usage observation task pins differ from the sampled role")
			}
			delete(pins, pin.TaskID)
		}
	}
	if len(pins) != 0 {
		return errors.New("usage observation omitted a sampled manager task")
	}
	return nil
}
