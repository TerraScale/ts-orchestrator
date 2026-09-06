package main

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
)

// databaseActivitySource is the durable product activity authority. A
// database admission timestamp describes creation, never a customer request.
type databaseActivitySource interface {
	LastAuthorizedRequest(context.Context, databaseadmission.Record) (*time.Time, error)
}

// policyDatabaseActivitySource is the production bridge to the billing
// authority's durable activity fact. It intentionally returns nil when the
// policy has no successful customer request; callers must preserve that
// unknown value rather than substitute admission or process timestamps.
type policyDatabaseActivitySource struct {
	policy *reaper.LifecyclePolicyClient
}

func newPolicyDatabaseActivitySource(policy *reaper.LifecyclePolicyClient) databaseActivitySource {
	if policy == nil {
		return nil
	}
	return policyDatabaseActivitySource{policy: policy}
}

func (s policyDatabaseActivitySource) LastAuthorizedRequest(ctx context.Context, record databaseadmission.Record) (*time.Time, error) {
	if s.policy == nil {
		return nil, errors.New("native lifecycle durable activity policy is unavailable")
	}
	facts, err := s.policy.Evaluate(ctx, reaper.LifecyclePolicyScope{
		OrganizationID: record.Request.TenantID,
		ProjectID:      record.Request.ProjectID,
		DatabaseID:     record.DatabaseID,
	})
	if err != nil {
		return nil, err
	}
	if facts.LastAuthorizedRequestAt == nil {
		return nil, nil
	}
	last := facts.LastAuthorizedRequestAt.UTC()
	return &last, nil
}

// nativeLifecycleDatabase is the production reaper database adapter. Native
// mutations always resolve an admitted member endpoint and forward the full
// signed placement envelope to TBEP; the command root supplies catalog and CDN
// owners separately.
type nativeLifecycleDatabase struct {
	catalog  reaper.Catalog
	resolve  func(context.Context, string) (tbep.LifecycleAssignment, *tbep.Client, error)
	purgeCDN func(context.Context, string, string) error
}

func (d *nativeLifecycleDatabase) List(ctx context.Context, cursor string, limit int) (reaper.Page, error) {
	if d == nil || d.catalog == nil {
		return reaper.Page{}, errors.New("native lifecycle catalog is unavailable")
	}
	return d.catalog.List(ctx, cursor, limit)
}

func (d *nativeLifecycleDatabase) invoke(ctx context.Context, databaseID, operation string, call func(*tbep.Client, context.Context, tbep.LifecycleAssignment, string) error) error {
	if d == nil || d.resolve == nil {
		return errors.New("native lifecycle resolver is unavailable")
	}
	assignment, client, err := d.resolve(ctx, databaseID)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.New("native lifecycle client is unavailable")
	}
	return call(client, ctx, assignment, operation)
}

func (d *nativeLifecycleDatabase) EnsureSnapshot(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, func(c *tbep.Client, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.EnsureSnapshot(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) VerifySnapshotPlacement(ctx context.Context, databaseID string) error {
	return d.invoke(ctx, databaseID, "verify-placement-"+databaseID, func(c *tbep.Client, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.VerifySnapshotPlacement(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) CloseDatabase(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, func(c *tbep.Client, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.CloseDatabase(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) StopNativeBackup(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, func(c *tbep.Client, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.StopNativeBackup(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) Reactivate(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, func(c *tbep.Client, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.Reactivate(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) PurgeCDN(ctx context.Context, databaseID, operation string) error {
	if d == nil || d.purgeCDN == nil {
		return errors.New("native lifecycle CDN purge is unavailable")
	}
	return d.purgeCDN(ctx, databaseID, operation)
}
func (d *nativeLifecycleDatabase) DeleteOwnedData(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, func(c *tbep.Client, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.DeleteOwnedData(ctx, a, op)
	})
}

var _ reaper.DatabaseAdapter = (*nativeLifecycleDatabase)(nil)

// admittedNativeLifecycleDatabase resolves the durable database record and
// current GRU placement head on every operation. The signed head envelope is
// forwarded unchanged; no request epoch or mTLS identity is used as authority.
func admittedNativeLifecycleDatabase(config productionDatabaseConfig, database *productionDatabase, transition *productionPlacementTransition) (*nativeLifecycleDatabase, error) {
	if database == nil || database.lifecycleJournal == nil || transition == nil || transition.issuer == nil || len(config.Regions) == 0 {
		return nil, errors.New("native lifecycle admission is incomplete")
	}
	return &nativeLifecycleDatabase{
		catalog: databaseCatalog(database, config.Activity),
		resolve: func(ctx context.Context, databaseID string) (tbep.LifecycleAssignment, *tbep.Client, error) {
			record, err := database.AcceptedRecord(ctx, databaseID)
			if err != nil || databaseadmission.ValidateRecord(record) != nil || record.DatabaseID != databaseID {
				return tbep.LifecycleAssignment{}, nil, errors.New("native lifecycle database admission is unavailable")
			}
			target := record.Targets[0]
			for _, candidate := range record.Targets {
				if candidate.Region == config.Regions[0].Region {
					target = candidate
					break
				}
			}
			var host productionDatabaseHost
			for _, region := range config.Regions {
				if region.Region == target.Region {
					host = region.Writer
					break
				}
			}
			var acceptedTarget databaseadmission.PlacementTarget
			for _, candidate := range record.PlacementTargets {
				if candidate.ServerIdentity == host.ServerIdentity {
					acceptedTarget = candidate
					break
				}
			}
			if len(acceptedTarget.AcceptedProof) == 0 {
				return tbep.LifecycleAssignment{}, nil, errors.New("native lifecycle accepted proof is unavailable")
			}
			tlsConfig, err := host.LifecycleTLS.LoadTLS()
			if err != nil {
				return tbep.LifecycleAssignment{}, nil, err
			}
			cert := tlsConfig.Certificates[0]
			client, err := tbep.New(tbep.Config{Endpoint: host.LifecycleEndpoint, ServerIdentity: host.LifecycleIdentity, Certificate: cert, Roots: tlsConfig.RootCAs, Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, Timeout: time.Minute})
			if err != nil {
				return tbep.LifecycleAssignment{}, nil, err
			}
			var acceptedProof placementtransition.Signed
			if json.Unmarshal(acceptedTarget.AcceptedProof, &acceptedProof) != nil {
				return tbep.LifecycleAssignment{}, nil, errors.New("native lifecycle accepted proof is unavailable")
			}
			return tbep.LifecycleAssignment{Environment: record.Request.Environment, Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, Region: target.Region, Member: target.MemberID, PlacementRevision: acceptedTarget.AcceptedRevision, AuthorityEpoch: acceptedTarget.AcceptedEpoch, AuthorityLease: headProofLease(acceptedProof), AuthoritySignature: acceptedTarget.AcceptedProof}, client, nil
		},
	}, nil
}

func headProofEpoch(s placementtransition.Signed) uint64 {
	var p placementtransition.Proof
	_ = json.Unmarshal(s.Payload, &p)
	return p.AuthorityEpoch
}
func headProofLease(s placementtransition.Signed) string {
	var p placementtransition.Proof
	_ = json.Unmarshal(s.Payload, &p)
	return p.LeaseID
}

type databaseCatalogAdapter struct {
	database *productionDatabase
	activity databaseActivitySource
}

func databaseCatalog(d *productionDatabase, activity databaseActivitySource) reaper.Catalog {
	return databaseCatalogAdapter{database: d, activity: activity}
}
func (c databaseCatalogAdapter) List(ctx context.Context, cursor string, limit int) (reaper.Page, error) {
	if c.database == nil || c.database.lifecycleJournal == nil || c.activity == nil || limit < 1 || limit > 1000 {
		return reaper.Page{}, errors.New("native lifecycle catalog activity source is unavailable")
	}
	records, err := c.database.lifecycleJournal.List(ctx)
	if err != nil {
		return reaper.Page{}, err
	}
	return pageDatabaseActivityRecords(ctx, records, cursor, limit, c.activity)
}

func pageDatabaseActivityRecords(ctx context.Context, records []databaseadmission.Record, cursor string, limit int, activity databaseActivitySource) (reaper.Page, error) {
	if ctx == nil || activity == nil || limit < 1 || limit > 1000 {
		return reaper.Page{}, errors.New("native lifecycle catalog activity source is unavailable")
	}
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b databaseadmission.Record) int { return cmp.Compare(a.DatabaseID, b.DatabaseID) })
	out := reaper.Page{Databases: make([]reaper.Database, 0, min(limit, len(records)))}
	for _, r := range records {
		if r.DatabaseID <= cursor || (r.State != "accepted" && r.State != "ready") {
			continue
		}
		if len(out.Databases) == limit {
			out.NextCursor = out.Databases[len(out.Databases)-1].ID
			break
		}
		lastRequest, err := activity.LastAuthorizedRequest(ctx, r)
		if err != nil {
			return reaper.Page{}, err
		}
		out.Databases = append(out.Databases, reaper.Database{ID: r.DatabaseID, LastRequest: valueOrZero(lastRequest)})
	}
	return out, nil
}

func valueOrZero(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
}
