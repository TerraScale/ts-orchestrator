package databaseadmission

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

// ProjectDeletionRequest is the immutable, caller-authorized project intent.
// Policy admission happens before this journal transaction; only its digest is
// retained here.
type ProjectDeletionRequest struct {
	Environment       string `json:"environment"`
	TenantID          string `json:"tenant_id"`
	ProjectID         string `json:"project_id"`
	OperationID       string `json:"operation_id"`
	PolicyFingerprint string `json:"policy_fingerprint"`
}

type ProjectDeletionTarget struct {
	Identity databaselifecycle.Identity `json:"identity"`
}

type ProjectDeletion struct {
	Request     ProjectDeletionRequest  `json:"request"`
	State       string                  `json:"state"`
	Revision    uint64                  `json:"revision"`
	RequestedAt time.Time               `json:"requested_at"`
	Targets     []ProjectDeletionTarget `json:"targets"`
}

func projectDeletionKey(r ProjectDeletionRequest) string {
	b, _ := json.Marshal([]string{r.Environment, r.TenantID, r.ProjectID, r.OperationID})
	return string(b)
}

func projectScopeKey(r ProjectDeletionRequest) string {
	b, _ := json.Marshal([]string{r.Environment, r.TenantID, r.ProjectID})
	return string(b)
}

func validProjectDeletionRequest(r ProjectDeletionRequest) bool {
	if !environmentName.MatchString(r.Environment) || !canonicalID.MatchString(r.TenantID) || !canonicalID.MatchString(r.ProjectID) || len(r.OperationID) == 0 || len(r.OperationID) > 128 || len(r.PolicyFingerprint) == 0 || len(r.PolicyFingerprint) > 512 {
		return false
	}
	for _, value := range []string{r.OperationID, r.PolicyFingerprint} {
		for _, c := range value {
			if c < 33 || c > 126 {
				return false
			}
		}
	}
	return true
}

func projectFence(state *journalState, r Request) string {
	return state.ProjectFences[projectScopeKey(ProjectDeletionRequest{Environment: r.Environment, TenantID: r.TenantID, ProjectID: r.ProjectID})]
}

func validateProjectDeletions(state journalState) error {
	for key, deletion := range state.ProjectDeletions {
		if key != projectDeletionKey(deletion.Request) || !validProjectDeletionRequest(deletion.Request) || deletion.Revision == 0 || deletion.RequestedAt.IsZero() || deletion.State != "accepted" {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for i, target := range deletion.Targets {
			if !validProjectTargetIdentity(target.Identity, deletion.Request) || seen[target.Identity.DatabaseID] || (i > 0 && target.Identity.DatabaseID < deletion.Targets[i-1].Identity.DatabaseID) {
				return ErrInvalid
			}
			seen[target.Identity.DatabaseID] = true
		}
		if state.ProjectFences[projectScopeKey(deletion.Request)] != deletion.Request.OperationID {
			return ErrInvalid
		}
	}
	for scope, operation := range state.ProjectFences {
		if operation == "" {
			return ErrInvalid
		}
		found := false
		for _, deletion := range state.ProjectDeletions {
			if projectScopeKey(deletion.Request) == scope && deletion.Request.OperationID == operation {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}

func databaselifecycleIdentityInScope(identity databaselifecycle.Identity, request ProjectDeletionRequest) bool {
	return identity.Environment == request.Environment && identity.OrganizationID == request.TenantID && identity.ProjectID == request.ProjectID
}

func validProjectTargetIdentity(identity databaselifecycle.Identity, request ProjectDeletionRequest) bool {
	return databaselifecycleIdentityInScope(identity, request) && environmentName.MatchString(identity.Environment) && canonicalID.MatchString(identity.OrganizationID) && canonicalID.MatchString(identity.ProjectID) && canonicalID.MatchString(identity.DatabaseID) && (identity.ParentDatabaseID == "" || canonicalID.MatchString(identity.ParentDatabaseID) && identity.ParentDatabaseID != identity.DatabaseID)
}

func beginProjectDeletion(state *journalState, request ProjectDeletionRequest, now time.Time) (ProjectDeletion, error) {
	if !validProjectDeletionRequest(request) || now.IsZero() {
		return ProjectDeletion{}, ErrInvalid
	}
	if state.ProjectFences == nil {
		state.ProjectFences = map[string]string{}
	}
	if state.ProjectDeletions == nil {
		state.ProjectDeletions = map[string]ProjectDeletion{}
	}
	key := projectDeletionKey(request)
	if old, found := state.ProjectDeletions[key]; found {
		if old.Request != request {
			return ProjectDeletion{}, ErrConflict
		}
		return old, nil
	}
	scope := projectScopeKey(request)
	if operation, found := state.ProjectFences[scope]; found && operation != request.OperationID {
		return ProjectDeletion{}, ErrConflict
	}
	targets := make([]ProjectDeletionTarget, 0)
	seen := map[string]bool{}
	for _, resource := range state.Lifecycle.Resources {
		if databaselifecycleIdentityInScope(resource.Identity, request) && !seen[resource.DatabaseID] {
			targets = append(targets, ProjectDeletionTarget{Identity: resource.Identity})
			seen[resource.DatabaseID] = true
		}
	}
	// Lifecycle rows are normally paired with records, but include admitted
	// records in the same CAS so a pending row cannot be omitted by enumeration.
	for _, record := range state.Records {
		if record.Request.Environment == request.Environment && record.Request.TenantID == request.TenantID && record.Request.ProjectID == request.ProjectID && !seen[record.DatabaseID] {
			targets = append(targets, ProjectDeletionTarget{Identity: admissionLifecycleEvent(record).Identity})
			seen[record.DatabaseID] = true
		}
	}
	slices.SortFunc(targets, func(a, b ProjectDeletionTarget) int { return cmp.Compare(a.Identity.DatabaseID, b.Identity.DatabaseID) })
	deletion := ProjectDeletion{Request: request, State: "accepted", Revision: 1, RequestedAt: now.UTC(), Targets: targets}
	state.ProjectDeletions[key] = deletion
	state.ProjectFences[scope] = request.OperationID
	return deletion, nil
}

func (j *MemoryJournal) BeginProjectDeletion(ctx context.Context, request ProjectDeletionRequest, now time.Time) (ProjectDeletion, error) {
	var out ProjectDeletion
	err := j.lifecycleTransact(ctx, func(state *journalState) error {
		var err error
		out, err = beginProjectDeletion(state, request, now)
		return err
	})
	return out, err
}

func (j *NATSJournal) BeginProjectDeletion(ctx context.Context, request ProjectDeletionRequest, now time.Time) (ProjectDeletion, error) {
	if j == nil || j.journal == nil {
		return ProjectDeletion{}, ErrJournalUnavailable
	}
	var out ProjectDeletion
	err := j.journal.Transact(ctx, true, func(state *journalState) error {
		var err error
		out, err = beginProjectDeletion(state, request, now)
		return err
	})
	return out, err
}

var _ interface {
	BeginProjectDeletion(context.Context, ProjectDeletionRequest, time.Time) (ProjectDeletion, error)
} = (*MemoryJournal)(nil)
var _ interface {
	BeginProjectDeletion(context.Context, ProjectDeletionRequest, time.Time) (ProjectDeletion, error)
} = (*NATSJournal)(nil)
