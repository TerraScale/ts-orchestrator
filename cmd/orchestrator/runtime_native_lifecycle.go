package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
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
	catalog      reaper.Catalog
	resolve      func(context.Context, string) ([]lifecycleTarget, error)
	purgeCDN     func(context.Context, string, string) error
	refresh      func(context.Context) (authority.RegionalAuthorityLeaseDocument, error)
	check        func(context.Context) error
	keyID        string
	key          ed25519.PrivateKey
	grantJournal func(string) (*authorityjournal.Journal[lifecycleGrantRecord], error)
}
type lifecycleRPC interface {
	Close() error
	EnsureSnapshot(context.Context, tbep.LifecycleAssignment, string) error
	VerifySnapshotPlacement(context.Context, tbep.LifecycleAssignment, string) error
	CloseDatabase(context.Context, tbep.LifecycleAssignment, string) error
	StopNativeBackup(context.Context, tbep.LifecycleAssignment, string) error
	Reactivate(context.Context, tbep.LifecycleAssignment, string) error
	DeleteOwnedData(context.Context, tbep.LifecycleAssignment, string) error
}
type lifecycleTarget struct {
	assignment tbep.LifecycleAssignment
	client     lifecycleRPC
}

type lifecycleGrantRecord struct {
	Scope, Action, Operation, ProofDigest string
	Revision                              uint64
	Completed                             bool
	Grant                                 []byte
}

func (d *nativeLifecycleDatabase) List(ctx context.Context, cursor string, limit int) (reaper.Page, error) {
	if d == nil || d.catalog == nil {
		return reaper.Page{}, errors.New("native lifecycle catalog is unavailable")
	}
	return d.catalog.List(ctx, cursor, limit)
}

func (d *nativeLifecycleDatabase) invoke(ctx context.Context, databaseID, operation, action string, call func(lifecycleRPC, context.Context, tbep.LifecycleAssignment, string) error) error {
	if d == nil || d.resolve == nil {
		return errors.New("native lifecycle resolver is unavailable")
	}
	targets, err := d.resolve(ctx, databaseID)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("native lifecycle targets are unavailable")
	}
	for index, target := range targets {
		assignment, client := target.assignment, target.client
		if client == nil {
			return errors.New("native lifecycle client is unavailable")
		}
		if err := d.invokeTarget(ctx, databaseID, operation, action, assignment, client, call); err != nil {
			for _, pending := range targets[index+1:] {
				if pending.client != nil {
					_ = pending.client.Close()
				}
			}
			return err
		}
	}
	return nil
}
func (d *nativeLifecycleDatabase) invokeTarget(ctx context.Context, databaseID, operation, action string, assignment tbep.LifecycleAssignment, client lifecycleRPC, call func(lifecycleRPC, context.Context, tbep.LifecycleAssignment, string) error) error {
	defer client.Close()
	if d.refresh == nil || d.keyID == "" || len(d.key) != ed25519.PrivateKeySize {
		return errors.New("native lifecycle authority issuer is unavailable")
	}
	lease, err := d.refresh(ctx)
	if err != nil {
		return err
	}
	if lease.Epoch <= 0 || !lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond).After(time.Now().UTC()) {
		return errors.New("native lifecycle authority lease is unavailable")
	}
	now := time.Now().UTC()
	dispatchOperation := operation + "-" + assignment.Member
	expires := now.Add(30 * time.Second)
	leaseExpiry := lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)
	if leaseExpiry.Before(expires) {
		expires = leaseExpiry
	}
	digest := sha256.Sum256(assignment.AuthoritySignature)
	grant, err := issueLifecycleOperationGrant(d.keyID, d.key, func() error { return d.check(ctx) }, lifecycleOperationGrant{
		Version: 1, Domain: lifecycleGrantDomain, Environment: assignment.Environment, Tenant: assignment.Tenant,
		Project: assignment.Project, Database: assignment.Database, Region: assignment.Region, Member: assignment.Member,
		Action: action, OperationID: dispatchOperation, AcceptedProofDigest: hex.EncodeToString(digest[:]),
		AcceptedPlacementRevision: assignment.PlacementRevision, AuthorityEpoch: uint64(lease.Epoch), AuthorityLease: lease.LeaseId,
		IssuedAtUnixMillis: now.UnixMilli(), ExpiresAtUnixMillis: expires.UnixMilli(),
	}, now, leaseExpiry, time.Second)
	if err != nil {
		return err
	}
	grantBytes, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	assignment.AuthorityEpoch = uint64(lease.Epoch)
	assignment.AuthorityLease = lease.LeaseId
	assignment.OperationGrant = grantBytes
	if d.grantJournal == nil {
		return errors.New("native lifecycle grant journal is unavailable")
	}
	grantJournal, err := d.grantJournal(dispatchOperation)
	if err != nil {
		return err
	}
	binding := assignment.Environment + ":" + assignment.Tenant + ":" + assignment.Project + ":" + assignment.Database + ":" + assignment.Region + ":" + assignment.Member
	completed := false
	if err := grantJournal.Transact(ctx, true, func(prior *lifecycleGrantRecord) error {
		if prior.Operation != "" && (prior.Scope != binding || prior.Action != action || prior.Operation != dispatchOperation || prior.ProofDigest != hex.EncodeToString(digest[:]) || prior.Revision != assignment.PlacementRevision) {
			return errors.New("native lifecycle operation identity conflict")
		}
		completed = prior.Completed
		*prior = lifecycleGrantRecord{Scope: binding, Action: action, Operation: dispatchOperation, ProofDigest: hex.EncodeToString(digest[:]), Revision: assignment.PlacementRevision, Grant: append([]byte(nil), grantBytes...), Completed: prior.Completed}
		return nil
	}); err != nil {
		return err
	}
	if completed {
		return nil
	}
	if err := call(client, ctx, assignment, dispatchOperation); err != nil {
		return err
	}
	return grantJournal.Transact(ctx, true, func(prior *lifecycleGrantRecord) error { prior.Completed = true; return nil })
}

func (d *nativeLifecycleDatabase) EnsureSnapshot(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, "ensure_snapshot", func(c lifecycleRPC, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.EnsureSnapshot(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) VerifySnapshotPlacement(ctx context.Context, databaseID string) error {
	return d.invoke(ctx, databaseID, "verify-placement-"+databaseID, "verify_snapshot_placement", func(c lifecycleRPC, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.VerifySnapshotPlacement(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) CloseDatabase(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, "close_database", func(c lifecycleRPC, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.CloseDatabase(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) StopNativeBackup(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, "stop_native_backup", func(c lifecycleRPC, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.StopNativeBackup(ctx, a, op)
	})
}
func (d *nativeLifecycleDatabase) Reactivate(ctx context.Context, databaseID, operation string) error {
	return d.invoke(ctx, databaseID, operation, "reactivate", func(c lifecycleRPC, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
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
	return d.invoke(ctx, databaseID, operation, "delete_owned_data", func(c lifecycleRPC, ctx context.Context, a tbep.LifecycleAssignment, op string) error {
		return c.DeleteOwnedData(ctx, a, op)
	})
}

var _ reaper.DatabaseAdapter = (*nativeLifecycleDatabase)(nil)

// admittedNativeLifecycleDatabase resolves the durable database record and
// current GRU placement head on every operation. The signed head envelope is
// forwarded unchanged; no request epoch or mTLS identity is used as authority.
func admittedNativeLifecycleDatabase(config productionDatabaseConfig, database *productionDatabase, transition *productionPlacementTransition, session globalWorkerSession) (*nativeLifecycleDatabase, error) {
	if database == nil || database.lifecycleJournal == nil || transition == nil || transition.issuer == nil || len(config.Regions) == 0 || session.guard == nil || session.check == nil || len(transition.config.Issuer.ProofKey) != ed25519.PrivateKeySize {
		return nil, errors.New("native lifecycle admission is incomplete")
	}
	return &nativeLifecycleDatabase{
		catalog: databaseCatalog(database, config.Activity),
		refresh: session.guard.RefreshAuthority, check: session.CheckEffectAuthority, keyID: transition.config.Issuer.ProofKeyID, key: slices.Clone(transition.config.Issuer.ProofKey),
		grantJournal: func(operation string) (*authorityjournal.Journal[lifecycleGrantRecord], error) {
			h := sha256.Sum256([]byte(operation))
			return authorityjournal.New(authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId, StateKey: "lifecycle-grant-" + hex.EncodeToString(h[:])}, func() lifecycleGrantRecord { return lifecycleGrantRecord{} }, func(lifecycleGrantRecord) error { return nil })
		},
		resolve: func(ctx context.Context, databaseID string) ([]lifecycleTarget, error) {
			record, err := database.AcceptedRecord(ctx, databaseID)
			if err != nil || databaseadmission.ValidateRecord(record) != nil || record.DatabaseID != databaseID {
				return nil, errors.New("native lifecycle database admission is unavailable")
			}
			slices.SortFunc(record.Targets, func(a, b databaseadmission.Target) int {
				return cmp.Or(cmp.Compare(a.Region, b.Region), cmp.Compare(a.MemberID, b.MemberID))
			})
			out := make([]lifecycleTarget, 0, len(record.Targets))
			success := false
			defer func() {
				if !success {
					for _, pending := range out {
						if pending.client != nil {
							_ = pending.client.Close()
						}
					}
				}
			}()
			for _, target := range record.Targets {
				var host productionDatabaseHost
				for _, region := range config.Regions {
					if region.Region == target.Region {
						if region.Writer.ServerIdentity == target.ServerIdentity {
							host = region.Writer
						}
						if region.Follower.ServerIdentity == target.ServerIdentity {
							host = region.Follower
						}
					}
				}
				var acceptedTarget databaseadmission.PlacementTarget
				for _, candidate := range record.PlacementTargets {
					if candidate.ServerIdentity == target.ServerIdentity {
						acceptedTarget = candidate
						break
					}
				}
				proofDigest := sha256.Sum256(acceptedTarget.AcceptedProof)
				if host.ServerIdentity == "" || len(acceptedTarget.AcceptedProof) == 0 || acceptedTarget.AcceptedRevision == 0 || acceptedTarget.AcceptedEpoch == 0 || acceptedTarget.AcceptedGeneration == 0 || acceptedTarget.AcceptedProofDigest != hex.EncodeToString(proofDigest[:]) {
					return nil, errors.New("native lifecycle accepted target is unavailable")
				}
				tlsConfig, err := host.LifecycleTLS.LoadTLS()
				if err != nil {
					return nil, err
				}
				client, err := tbep.New(tbep.Config{Endpoint: host.LifecycleEndpoint, ServerIdentity: host.LifecycleIdentity, Certificate: tlsConfig.Certificates[0], Roots: tlsConfig.RootCAs, Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, Timeout: time.Minute})
				if err != nil {
					return nil, err
				}
				var acceptedProof placementtransition.Signed
				if json.Unmarshal(acceptedTarget.AcceptedProof, &acceptedProof) != nil {
					client.Close()
					return nil, errors.New("native lifecycle accepted proof is unavailable")
				}
				out = append(out, lifecycleTarget{assignment: tbep.LifecycleAssignment{Environment: record.Request.Environment, Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, Region: target.Region, Member: target.MemberID, PlacementRevision: acceptedTarget.AcceptedRevision, AuthorityEpoch: acceptedTarget.AcceptedEpoch, AuthorityLease: headProofLease(acceptedProof), AuthoritySignature: acceptedTarget.AcceptedProof}, client: client})
			}
			success = true
			return out, nil
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
	records, err := c.database.currentRecords(ctx)
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
