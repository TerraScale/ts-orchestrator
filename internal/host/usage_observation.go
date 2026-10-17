package host

import (
	"context"
	"encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
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

// UsageSource names the authenticated applied manager boundary, not a host clock.
type UsageSource struct {
	Version     uint64 `json:"version"`
	NodeID      string `json:"node_id"`
	ClusterID   string `json:"cluster_id"`
	ServerEpoch string `json:"server_epoch"`
	Term        uint64 `json:"term"`
	Leader      uint64 `json:"leader"`
}

// UsageObservation is a point observation in the existing host control log.
// Coverage lags one report: PreviousSequence and CoveredSequence bound the two
// preceding points; this record's timestamp never extends that interval.
type UsageObservation struct {
	Version          int                         `json:"version"`
	Registration     Registration                `json:"registration"`
	DeploymentID     string                      `json:"deployment_id"`
	Epoch            uint64                      `json:"epoch"`
	SessionID        string                      `json:"session_id"`
	Source           UsageSource                 `json:"source"`
	PriorSequence    uint64                      `json:"prior_sequence,omitzero"`
	PreviousSequence uint64                      `json:"previous_sequence,omitzero"`
	CoveredSequence  uint64                      `json:"covered_sequence,omitzero"`
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
	caller, ok := ctx.Value(loadObservationContextKey{}).(*loadObservationCaller)
	if !ok || caller == nil || caller.controller != c || verify == nil || !reflect.DeepEqual(caller.registration, observation.Registration) {
		return CommittedUsage{}, errors.New("usage observation requires its authenticated host request")
	}
	if err := caller.checkActive(ctx); err != nil {
		return CommittedUsage{}, err
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
	if previous.Sequence != 0 && time.Since(previous.CreatedAt) < hostload.DefaultMinInterval {
		return CommittedUsage{}, hostload.ErrTooFrequent
	}
	observation.PriorSequence = previous.Sequence
	var prior UsageObservation
	if observation.CoveredSequence != 0 {
		if previous.Sequence == 0 || json.Unmarshal(previous.Payload, &prior, json.RejectUnknownMembers(true)) != nil {
			return CommittedUsage{}, errors.New("usage coverage predecessor is unavailable")
		}
		if observation.CoveredSequence != previous.Sequence || observation.PreviousSequence != prior.PriorSequence {
			// A concurrent accepted report may have advanced the head. Keep this
			// authenticated point while dropping its stale continuity claim.
			observation.PreviousSequence, observation.CoveredSequence = 0, 0
		}
	}
	if observation.CoveredSequence != 0 {
		raw, err := c.controlLog.GetMsg(ctx, observation.PreviousSequence)
		if err != nil {
			return CommittedUsage{}, err
		}
		first, err := authority.DecodeUsageObservationEntry(raw, c.cell)
		var start UsageObservation
		if err != nil || first.SubjectKey != key || json.Unmarshal(first.Payload, &start, json.RejectUnknownMembers(true)) != nil {
			return CommittedUsage{}, errors.Join(err, errors.New("usage coverage start is unavailable"))
		}
		if !sameUsageAllocation(start, prior) || !sameUsageAllocation(prior, observation) ||
			start.Source.Version > prior.Source.Version || prior.Source.Version > observation.Source.Version {
			observation.PreviousSequence, observation.CoveredSequence = 0, 0
		}
		// A host could have been retired and re-enrolled between equal endpoints.
		// Any intervening admission mutation invalidates this interval.
		for _, kind := range []string{"registration", "retirement"} {
			if observation.CoveredSequence == 0 {
				break
			}
			raw, err := c.controlLog.GetMsg(ctx, observation.PreviousSequence+1,
				jetstream.WithGetMsgSubject(protocol.Control(c.cell, "host")+"."+kind+"."+key))
			if err != nil && !errors.Is(err, jetstream.ErrMsgNotFound) {
				return CommittedUsage{}, err
			}
			if raw != nil && raw.Sequence <= observation.CoveredSequence {
				observation.PreviousSequence, observation.CoveredSequence = 0, 0
				break
			}
		}
	}
	data, err := json.Marshal(observation)
	if err != nil {
		return CommittedUsage{}, err
	}
	operation := entityid.New()
	sequence, err := store.CommitHostMutationVerified(ctx, observation.Epoch, authority.MutationUsageObservation,
		key, operation, previous.Sequence, data, func(ctx context.Context) error {
			if err := caller.checkActive(ctx); err != nil {
				return err
			}
			if err := c.recheckReplyAuthority(ctx, observation.Epoch, caller.request, caller.registration, false); err != nil {
				return err
			}
			if err := verify(ctx); err != nil {
				return err
			}
			return caller.checkActive(ctx)
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

func sameUsageAllocation(a, b UsageObservation) bool {
	a.Source.Version, b.Source.Version = 0, 0
	return a.Source == b.Source && a.Epoch == b.Epoch && a.DeploymentID == b.DeploymentID && a.SessionID == b.SessionID &&
		reflect.DeepEqual(a.Registration, b.Registration) && reflect.DeepEqual(a.Tasks, b.Tasks) && reflect.DeepEqual(a.Requests, b.Requests)
}

func validateUsageObservation(value UsageObservation, cell string) error {
	if value.Version != 1 || value.Epoch == 0 || !entityid.Valid(value.DeploymentID) ||
		!entityid.Valid(value.SessionID) || value.Source.Version == 0 || value.Source.NodeID == "" || value.Source.ClusterID == "" ||
		value.Source.ServerEpoch == "" || value.Source.Term == 0 || value.Source.Leader == 0 ||
		(value.PreviousSequence == 0) != (value.CoveredSequence == 0) || value.CoveredSequence > value.PriorSequence ||
		value.CoveredSequence != 0 && value.PreviousSequence >= value.CoveredSequence ||
		value.Registration.ID != entityid.Derive("host", cell, value.Registration.Node) {
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
