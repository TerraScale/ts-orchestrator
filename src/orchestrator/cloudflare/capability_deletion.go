package cloudflare

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/zeebo/blake3"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

// ErrCapabilityDeletionPending means previously issued capabilities may still
// be accepted by an ingress that has not received the revocation deployment.
var ErrCapabilityDeletionPending = errors.New("cloudflare: deletion capability expiry pending")

const deletionCapabilityLifetime = 1200 * time.Second

type CapabilityDeletionRevoker struct {
	store   *SnippetCapabilityStore
	journal databaseadmission.DeletionJournal
	now     func() time.Time
}

var _ databaseadmission.DeletionEdgeRevoker = (*CapabilityDeletionRevoker)(nil)

func NewCapabilityDeletionRevoker(store *SnippetCapabilityStore, journal databaseadmission.DeletionJournal, now func() time.Time) (*CapabilityDeletionRevoker, error) {
	if store == nil || journal == nil || now == nil {
		return nil, capabilityEffectError()
	}
	return &CapabilityDeletionRevoker{store: store, journal: journal, now: now}, nil
}

func (r *CapabilityDeletionRevoker) RevokeDeletion(ctx context.Context, requested databaseadmission.Deletion) (databaseadmission.DeletionEdgeReceipt, error) {
	var empty databaseadmission.DeletionEdgeReceipt
	if r == nil || r.store == nil || r.journal == nil || r.now == nil {
		return empty, capabilityEffectError()
	}
	records, err := r.journal.ListDeletions(ctx)
	if err != nil {
		return empty, capabilityEffectError()
	}
	var authoritative *databaseadmission.Deletion
	for _, record := range records {
		if record.Request == requested.Request {
			if authoritative != nil || !record.Cutoff.Equal(requested.Cutoff) {
				return empty, capabilityEffectError()
			}
			authoritative = new(record)
		}
	}
	if authoritative == nil {
		return empty, capabilityEffectError()
	}
	entries, expires, err := deletionRevocations(*authoritative)
	if err != nil {
		return empty, err
	}
	// Probes establish deployment to the configured ingress only. The native
	// receipts establish the universal issuance cutoff; expiry closes the gap
	// for previously minted tokens at every other ingress.
	if !r.now().Before(expires) {
		entries = nil
	}
	if _, err = r.store.PublishRevocations(ctx, entries, "database-delete-"+requested.Request.OperationID); err != nil {
		return empty, err
	}
	if r.now().Before(expires) {
		return empty, ErrCapabilityDeletionPending
	}
	return databaseadmission.DeletionEdgeReceipt{Request: authoritative.Request, Cutoff: authoritative.Cutoff, AccessRevoked: true}, nil
}

func deletionRevocations(d databaseadmission.Deletion) ([]CapabilityRevocation, time.Time, error) {
	if d.Cutoff.IsZero() || len(d.Targets) == 0 || (d.State != "edge_pending" && d.State != "cleanup_pending") {
		return nil, time.Time{}, capabilityEffectError()
	}
	expires := d.Cutoff.Add(deletionCapabilityLifetime)
	expirySeconds := expires.Unix()
	if expires.Nanosecond() != 0 {
		expirySeconds++
	}
	scopes := map[string]bool{}
	targets := map[string]bool{}
	root := false
	for _, target := range d.Targets {
		s, receipt := target.Stop, target.Receipt
		if s.Environment != d.Request.Environment || s.OrganizationID != d.Request.TenantID || s.ProjectID != d.Request.ProjectID || s.DatabaseID == "" || s.OperationID != d.Request.OperationID || !s.Cutoff.Equal(d.Cutoff) || !slices.Contains([]string{"GRU", "SFO", "FRA"}, s.Region) || receipt == nil {
			return nil, time.Time{}, capabilityEffectError()
		}
		if receipt.Identity != s.Identity || receipt.OperationID != s.OperationID || receipt.Region != s.Region || !receipt.Cutoff.Equal(s.Cutoff) || !receipt.RetainUntil.Equal(s.RetainUntil) || !receipt.AccessRevoked || !receipt.UsageStopped {
			return nil, time.Time{}, capabilityEffectError()
		}
		key := s.DatabaseID + "/" + s.Region
		if targets[key] {
			return nil, time.Time{}, capabilityEffectError()
		}
		targets[key] = true
		root = root || s.DatabaseID == d.Request.DatabaseID
		scopes[deletionCapabilityScope(s.OrganizationID, s.ProjectID, s.DatabaseID)] = true
	}
	if !root {
		return nil, time.Time{}, capabilityEffectError()
	}
	names := make([]string, 0, len(scopes))
	for scope := range scopes {
		names = append(names, scope)
	}
	slices.Sort(names)
	entries := make([]CapabilityRevocation, 0, len(names))
	for _, scope := range names {
		entries = append(entries, CapabilityRevocation{Scope: scope, ExpiresAt: expirySeconds})
	}
	return entries, expires, nil
}

// Matches reactive_api.rs capability_scope over organization:project:database.
func deletionCapabilityScope(organization, project, database string) string {
	digest := blake3.Sum256([]byte(organization + ":" + project + ":" + database))
	return "scope-" + hex.EncodeToString(digest[:])
}
