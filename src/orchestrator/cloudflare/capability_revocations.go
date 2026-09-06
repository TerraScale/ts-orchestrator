package cloudflare

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaximumCapabilityRevocations keeps the rendered Snippet under its provider
// source-size limit. Overflow fails pending; live entries are never evicted.
const MaximumCapabilityRevocations = 32

type CapabilityRevocation struct {
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"expiresAt"`
}
type capabilityRevocationWire struct {
	Revision string                 `json:"revision"`
	Entries  []CapabilityRevocation `json:"entries"`
}

// CapabilityRevocationReceipt reports authenticated ingress observations. It
// does not assert that all Cloudflare locations have converged.
type CapabilityRevocationReceipt struct {
	Generation uint64
	Revision   uint64
	Digest     string
	ObservedAt time.Time
}

func validCapabilityRevocations(entries []CapabilityRevocation) bool {
	if len(entries) > MaximumCapabilityRevocations {
		return false
	}
	last := ""
	for _, entry := range entries {
		if len(entry.Scope) != 70 || !strings.HasPrefix(entry.Scope, "scope-") || entry.ExpiresAt < 0 || entry.ExpiresAt > 9007199254740991 || entry.Scope <= last {
			return false
		}
		digest, err := hex.DecodeString(strings.TrimPrefix(entry.Scope, "scope-"))
		if err != nil || len(digest) != 32 || strings.ToLower(entry.Scope) != entry.Scope {
			return false
		}
		last = entry.Scope
	}
	return true
}

func capabilityRevocationDigest(entries []CapabilityRevocation) string {
	var canonical strings.Builder
	for _, entry := range entries {
		canonical.WriteString(entry.Scope)
		canonical.WriteByte('.')
		canonical.WriteString(strconv.FormatInt(entry.ExpiresAt, 10))
		canonical.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}

// PublishRevocations unions the requested scopes with the durable ring. Only
// expired entries are pruned; a scope can never be un-revoked inside its window.
// The caller must prove that native issuance stopped before choosing expiry.
func (s *SnippetCapabilityStore) PublishRevocations(ctx context.Context, entries []CapabilityRevocation, operation string) (CapabilityRevocationReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requested := slices.Clone(entries)
	slices.SortFunc(requested, func(a, b CapabilityRevocation) int { return cmp.Compare(a.Scope, b.Scope) })
	if operation == "" || !validCapabilityRevocations(requested) {
		return CapabilityRevocationReceipt{}, capabilityEffectError()
	}
	receipt, revision, err := s.config.Journal.Load(ctx)
	if err != nil || receipt.Generation == 0 || !validCapabilityRevocations(receipt.Revocations) {
		return CapabilityRevocationReceipt{}, capabilityEffectError()
	}
	now := s.config.Now().UTC()
	merged := make(map[string]int64)
	for _, entry := range receipt.Revocations {
		if entry.ExpiresAt > now.Unix() {
			merged[entry.Scope] = entry.ExpiresAt
		}
	}
	for _, entry := range requested {
		if entry.ExpiresAt > now.Unix() {
			merged[entry.Scope] = max(merged[entry.Scope], entry.ExpiresAt)
		}
	}
	if len(merged) > MaximumCapabilityRevocations {
		return CapabilityRevocationReceipt{}, capabilityEffectError()
	}
	next := make([]CapabilityRevocation, 0, len(merged))
	for scope, expiry := range merged {
		next = append(next, CapabilityRevocation{Scope: scope, ExpiresAt: expiry})
	}
	slices.SortFunc(next, func(a, b CapabilityRevocation) int { return cmp.Compare(a.Scope, b.Scope) })
	if !slices.Equal(next, receipt.Revocations) {
		if receipt.RevocationRevision == ^uint64(0) {
			return CapabilityRevocationReceipt{}, capabilityEffectError()
		}
		receipt.Revocations = next
		receipt.RevocationRevision++
	}
	receipt.OperationID = operation
	// Reconstruct and observe before a repeated PUT, including after a lost
	// publication response. The journal holds intent, never an assumed receipt.
	if s.deploy(ctx, receipt, revision) != nil {
		return CapabilityRevocationReceipt{}, capabilityEffectError()
	}
	return CapabilityRevocationReceipt{Generation: receipt.Generation, Revision: receipt.RevocationRevision, Digest: capabilityRevocationDigest(receipt.Revocations), ObservedAt: s.config.Now().UTC()}, nil
}
