package cloudflare

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// MembershipRevocationSnapshot is the bounded authoritative dashboard outbox.
// Its lease is never extended locally, including after a failed publication.
type MembershipRevocationSnapshot struct {
	Revision   string                 `json:"revision"`
	ValidUntil int64                  `json:"validUntil"`
	Entries    []CapabilityRevocation `json:"entries"`
}

func (s MembershipRevocationSnapshot) valid() bool {
	return s.ValidUntil > 0 && s.ValidUntil <= 9007199254740991 && validCapabilityRevocations(s.Entries) && s.Revision == capabilityRevocationDigest(s.Entries)
}

// PublishMembershipRevocations persists the source lease and proves the exact
// deployment at authenticated ingress. Missing live entries cannot resurrect.
func (s *SnippetCapabilityStore) PublishMembershipRevocations(ctx context.Context, snapshot MembershipRevocationSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.config.Now().Unix()
	if !snapshot.valid() || snapshot.ValidUntil <= now || snapshot.ValidUntil > now+30 {
		return capabilityEffectError()
	}
	receipt, revision, err := s.config.Journal.Load(ctx)
	if err != nil || receipt.Generation == 0 {
		return capabilityEffectError()
	}
	if old := receipt.MembershipRevocations; old != nil {
		if snapshot.ValidUntil < old.ValidUntil {
			return capabilityEffectError()
		}
		for _, entry := range old.Entries {
			if entry.ExpiresAt > now && !slices.ContainsFunc(snapshot.Entries, func(next CapabilityRevocation) bool {
				return next.Scope == entry.Scope && next.ExpiresAt >= entry.ExpiresAt
			}) {
				return capabilityEffectError()
			}
		}
	}
	snapshot.Entries = slices.Clone(snapshot.Entries)
	receipt.MembershipRevocations = &snapshot
	receipt.OperationID = "membership-" + snapshot.Revision
	return s.deploy(ctx, receipt, revision)
}

type MembershipRevocationPublisherConfig struct {
	Endpoint   string
	Audience   string
	ServiceKey func() (string, error)
	HTTPClient *http.Client
	Store      *SnippetCapabilityStore
	Authorize  func(context.Context) error
}
type MembershipRevocationPublisher struct {
	config MembershipRevocationPublisherConfig
}

func NewMembershipRevocationPublisher(c MembershipRevocationPublisherConfig) (*MembershipRevocationPublisher, error) {
	u, err := url.Parse(c.Endpoint)
	audience, audienceErr := url.Parse(c.Audience)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/internal/identity/introspect" || audienceErr != nil || audience.Scheme != "https" || audience.Host == "" || c.ServiceKey == nil || c.HTTPClient == nil || c.Store == nil || c.Authorize == nil {
		return nil, capabilityEffectError()
	}
	client := *c.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.HTTPClient = &client
	return &MembershipRevocationPublisher{config: c}, nil
}

// Tick is a control-plane poll, independent of subscriber count and read rate.
func (p *MembershipRevocationPublisher) Tick(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := p.config.Authorize(ctx); err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Kind     string `json:"kind"`
		Audience string `json:"audience"`
	}{"revocations", p.config.Audience})
	if err != nil {
		return capabilityEffectError()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return capabilityEffectError()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	key, err := p.config.ServiceKey()
	if err != nil || key == "" {
		return capabilityEffectError()
	}
	req.Header.Set("x-terrascale-identity-service-key", key)
	response, err := p.config.HTTPClient.Do(req)
	if err != nil {
		return capabilityEffectError()
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 || response.StatusCode != http.StatusOK {
		return capabilityEffectError()
	}
	var result struct {
		Active   bool                          `json:"active"`
		Snapshot *MembershipRevocationSnapshot `json:"membershipRevocations"`
	}
	if json.Unmarshal(raw, &result, json.RejectUnknownMembers(true)) != nil || result.Active || result.Snapshot == nil {
		return capabilityEffectError()
	}
	if err := p.config.Authorize(ctx); err != nil {
		return err
	}
	return p.config.Store.PublishMembershipRevocations(ctx, *result.Snapshot)
}
