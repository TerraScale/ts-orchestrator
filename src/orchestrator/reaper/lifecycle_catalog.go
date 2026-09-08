package reaper

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

// LifecycleCatalog joins the admission journal's resource inventory to the
// dashboard's current billing, protection, activity and owner observations.
// It does not turn an observation into authorization for a later mutation.
type LifecycleCatalog struct {
	journal     *databaseadmission.NATSJournal
	policy      *LifecyclePolicyClient
	environment string
	clock       Clock
}

func NewLifecycleCatalog(journal *databaseadmission.NATSJournal, policy *LifecyclePolicyClient, environment string) (*LifecycleCatalog, error) {
	if journal == nil || policy == nil || !destructionEnvironment.MatchString(environment) {
		return nil, ErrMissingDependency
	}
	return &LifecycleCatalog{journal: journal, policy: policy, environment: environment, clock: systemClock{}}, nil
}

func (c *LifecycleCatalog) List(ctx context.Context, cursor string, limit int) (Page, error) {
	if c == nil || c.journal == nil || c.policy == nil || ctx == nil || limit < 1 || limit > 1000 || (cursor != "" && !destructionULID.MatchString(cursor)) {
		return Page{}, ErrInvalidCursor
	}
	_, resources, err := c.journal.LifecycleResources(ctx)
	if err != nil {
		return Page{}, err
	}
	return c.page(ctx, resources, cursor, limit)
}

func (c *LifecycleCatalog) page(ctx context.Context, resources []databaselifecycle.Resource, cursor string, limit int) (Page, error) {
	// Keyset cursors tolerate new resources between scans. A resource inserted
	// before the cursor is picked up by the next full scan, never backdated.
	resources = slices.Clone(resources)
	slices.SortFunc(resources, func(a, b databaselifecycle.Resource) int { return cmp.Compare(a.DatabaseID, b.DatabaseID) })
	var result Page
	seen := make(map[string]bool)
	for _, resource := range resources {
		if resource.Environment != c.environment {
			continue
		}
		if !destructionULID.MatchString(resource.DatabaseID) || seen[resource.DatabaseID] {
			return Page{}, ErrInvalidDatabase
		}
		seen[resource.DatabaseID] = true
		if resource.DatabaseID <= cursor {
			continue
		}
		if len(result.Databases) == limit {
			result.NextCursor = result.Databases[len(result.Databases)-1].ID
			break
		}
		facts, err := c.policy.Evaluate(ctx, LifecyclePolicyScope{OrganizationID: resource.OrganizationID, ProjectID: resource.ProjectID, DatabaseID: resource.DatabaseID})
		if err != nil {
			return Page{}, err
		}
		database, err := policyDatabase(facts, c.clock.Now())
		if err != nil {
			return Page{}, err
		}
		result.Databases = append(result.Databases, database)
	}
	return result, nil
}

func policyDatabase(facts LifecyclePolicyFacts, now time.Time) (Database, error) {
	if len(facts.OwnerEmails) == 0 {
		return Database{}, ErrInvalidDatabase
	}
	owners := slices.Clone(facts.OwnerEmails)
	slices.Sort(owners)
	for _, owner := range owners {
		if !ociMailbox(owner) {
			return Database{}, ErrInvalidDatabase
		}
	}
	database := Database{ID: facts.DatabaseID, OrganizationID: facts.OrganizationID, ProjectID: facts.ProjectID, OwnerEmail: owners[0], Plan: PlanPaid, OwnershipProof: facts.Revision, PolicyRevision: facts.Revision}
	if len(facts.DeletionReasons) > 0 {
		database.SelectedGraceCondition = facts.DeletionReasons[0]
	}
	if facts.BillingDeletionEligible {
		condition, err := selectedBillingGrace(facts, now)
		if err != nil {
			return Database{}, err
		}
		database.SelectedGraceCondition = condition
	}
	database.BillingGraceDeadline = facts.BillingGraceDeadline
	database.BillingDeletionEligible = facts.BillingDeletionEligible
	if facts.Plan == "free" {
		database.Plan = PlanFree
	}
	if facts.LastAuthorizedRequestAt != nil {
		database.LastRequest = *facts.LastAuthorizedRequestAt
	}
	// The generic engine has fixed age thresholds. A policy denial at either
	// threshold must remain a denial when translated into that older interface.
	denied := false
	if !database.LastRequest.IsZero() {
		idle := now.Sub(database.LastRequest)
		denied = idle >= DefaultPauseAfter && !facts.PauseEligible
		if idle >= DefaultDeleteAfter && (facts.DeletionProtection || !facts.DeletionEligible) {
			denied = true
		}
	}
	if denied {
		database.Exemption = Exemption{Active: true, Reason: "current lifecycle policy does not admit the due operation"}
	}
	if err := validateDatabase(database); err != nil {
		return Database{}, fmt.Errorf("%w: lifecycle policy observation", ErrInvalidDatabase)
	}
	return database, nil
}

var _ Catalog = (*LifecycleCatalog)(nil)

// A billing observation selects a concrete due reason. Deletion admission still
// requires the Dashboard claim transaction to refresh exact pooled storage and
// revalidate the current policy; grace timestamps are not quantity evidence.
func selectedBillingGrace(facts LifecyclePolicyFacts, now time.Time) (string, error) {
	if facts.BillingGraceDeadline == nil || now.Before(*facts.BillingGraceDeadline) || len(facts.DeletionReasons) == 0 {
		return "", ErrLifecyclePolicy
	}
	reason := facts.DeletionReasons[0]
	var grace *LifecycleBillingGrace
	switch reason {
	case "card-loss":
		grace = facts.Coverage.CardLoss
	case "uncovered-storage":
		grace = facts.Coverage.UncoveredStorage
	default:
		if invoice, ok := strings.CutPrefix(reason, "unpaid-storage:"); ok && policyToken(invoice) {
			if value, exists := facts.Coverage.UnpaidStorageInvoices[invoice]; exists {
				grace = &value
			}
		}
	}
	if grace == nil || !grace.Deadline.Equal(*facts.BillingGraceDeadline) || grace.StartedAt.IsZero() || grace.Deadline.Sub(grace.StartedAt) < 30*24*time.Hour {
		return "", ErrLifecyclePolicy
	}
	return reason, nil
}
