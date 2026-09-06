package cloudflare

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// CapabilityDeploymentMarker belongs to the bundled Snippet template, before
// publication. Substitution happens only in memory; source containing keys must
// never enter an artifact mirror or a release journal.
const CapabilityDeploymentMarker = "/*__TERRASCALE_CAPABILITY_DEPLOYMENT__*/ null"

// SnippetCapabilityStoreConfig requires a deployed route covering both reactive
// reads and /.well-known/terrascale-capability-generation. ProbeURLs name every
// independently operated probe ingress required by deployment policy. A probe
// proves only the consumer reached by that request, never worldwide propagation.
type SnippetCapabilityStoreConfig struct {
	// Artifacts resolves verified release templates by their durable digest.
	Artifacts       EdgeArtifactSource
	TemplateService string
	Zone            *Zone
	Client          *Client
	SnippetName     string
	Source          []byte
	Vault           security.CapabilityVault
	Journal         CapabilityJournal
	Authorize       func(context.Context) error
	ProbeURLs       []string
	HTTPClient      *http.Client
	Now             func() time.Time
}

type SnippetCapabilityStore struct {
	config SnippetCapabilityStoreConfig
	mu     sync.Mutex
}

var _ security.SecretsStore = (*SnippetCapabilityStore)(nil)

func NewSnippetCapabilityStore(c SnippetCapabilityStoreConfig) (*SnippetCapabilityStore, error) {
	if c.Client == nil || c.Client.HTTP == nil || c.SnippetName == "" || c.Vault == nil || c.Journal == nil || c.Authorize == nil || c.HTTPClient == nil || c.Now == nil || len(c.ProbeURLs) == 0 || bytes.Count(c.Source, []byte(CapabilityDeploymentMarker)) != 1 {
		return nil, capabilityEffectError()
	}
	if (c.Artifacts == nil) != (c.TemplateService == "") {
		return nil, capabilityEffectError()
	}
	if err := ValidateCapabilityDeployment(c.Source, c.Zone, c.SnippetName, c.ProbeURLs); err != nil {
		return nil, err
	}
	provider := &Client{Token: c.Client.Token, ZoneID: c.Client.ZoneID, AccountID: c.Client.AccountID, BaseURL: c.Client.BaseURL, HTTP: capabilityTemplateTransport{next: c.Client.HTTP, authorize: c.Authorize}, maxAttempts: c.Client.maxAttempts, sleep: c.Client.sleep, now: c.Client.now}
	c.Client = provider
	c.Source = bytes.Clone(c.Source)
	c.ProbeURLs = append([]string(nil), c.ProbeURLs...)
	client := *c.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.HTTPClient = &client
	return &SnippetCapabilityStore{config: c}, nil
}

func capabilityEffectError() error {
	return errors.New("cloudflare: capability deployment could not be proved")
}
func capabilityState(m security.CapabilityMaterial) security.CapabilityKeyState {
	return security.CapabilityKeyState{ID: m.ID, Reference: m.Reference, Version: m.Version, Bucket: m.Bucket, NotBefore: m.NotBefore, ExpiresAt: m.ExpiresAt}
}
func (s *SnippetCapabilityStore) Distribute(ctx context.Context, c security.CredentialSet, operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if operation == "" || c.Capability.Version == 0 || !s.config.Now().Before(c.Capability.ExpiresAt) {
		return capabilityEffectError()
	}
	old, rev, err := s.config.Journal.Load(ctx)
	if err != nil {
		return capabilityEffectError()
	}
	if old.Generation > c.Capability.Version {
		return capabilityEffectError()
	}
	if old.Generation == c.Capability.Version {
		if old.Current.Reference != c.Capability.Reference || old.Current.ID != c.Capability.ID || old.Phase != "staged" && old.Phase != "active" {
			return capabilityEffectError()
		}
		return s.deploy(ctx, old, rev)
	}
	receipt := CapabilityReceipt{Generation: c.Capability.Version, Current: capabilityState(c.Capability), Previous: capabilityState(c.PreviousCapability), Phase: "staged", OperationID: operation, TemplateDigest: edgeDigest(s.config.Source)}
	if old.Generation != 0 && (old.Phase != "active" || old.Current.Reference != receipt.Previous.Reference) {
		return capabilityEffectError()
	}
	if old.Generation != 0 {
		receipt.TemplateDigest = old.TemplateDigest
		receipt.RevocationRevision = old.RevocationRevision
		receipt.Revocations = slices.Clone(old.Revocations)
	}
	if receipt.Previous.Reference != "" {
		receipt.Previous.ExpiresAt = minTime(receipt.Previous.ExpiresAt, receipt.Current.NotBefore.Add(security.CapabilityOverlap))
	}
	return s.deploy(ctx, receipt, rev)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *SnippetCapabilityStore) Verify(ctx context.Context, generation uint64) (security.ConsumerObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, _, err := s.config.Journal.Load(ctx)
	if err != nil || r.Generation != generation || r.Phase == "fenced" {
		return security.ConsumerObservation{}, capabilityEffectError()
	}
	if err = s.observe(ctx, r); err != nil {
		return security.ConsumerObservation{}, err
	}
	return security.ConsumerObservation{Generation: r.Generation, ValidUntil: time.Unix(r.Current.ExpiresAt.Unix(), 0)}, nil
}
func (s *SnippetCapabilityStore) Activate(ctx context.Context, generation uint64, operation string) error {
	return s.transition(ctx, generation, operation, "active")
}
func (s *SnippetCapabilityStore) Fence(ctx context.Context, operation string) error {
	return s.transition(ctx, 0, operation, "fenced")
}
func (s *SnippetCapabilityStore) Rollback(ctx context.Context, generation uint64, operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, rev, err := s.config.Journal.Load(ctx)
	if err != nil || r.Generation != generation || operation == "" {
		return capabilityEffectError()
	}
	// Rollback cannot restore a key after its bounded overlap expiry.
	if r.Previous.Reference == "" || !s.config.Now().Before(r.Previous.ExpiresAt) {
		r.Phase = "fenced"
	} else {
		r.Current = r.Previous
		r.Previous = security.CapabilityKeyState{}
		r.Generation = r.Current.Version
		r.Phase = "active"
	}
	r.OperationID = operation
	return s.deploy(ctx, r, rev)
}
func (s *SnippetCapabilityStore) Retire(ctx context.Context, generation uint64, operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, rev, err := s.config.Journal.Load(ctx)
	if err != nil || operation == "" || r.Phase != "active" || r.Current.Version == generation {
		return capabilityEffectError()
	}
	if r.Previous.Reference != "" && (r.Previous.Version != generation || s.config.Now().Before(r.Previous.ExpiresAt)) {
		return capabilityEffectError()
	}
	r.Previous = security.CapabilityKeyState{}
	r.OperationID = operation
	return s.deploy(ctx, r, rev)
}
func (s *SnippetCapabilityStore) transition(ctx context.Context, generation uint64, operation, phase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, rev, err := s.config.Journal.Load(ctx)
	if err != nil || r.Generation == 0 || generation != 0 && r.Generation != generation || operation == "" {
		return capabilityEffectError()
	}
	if phase == "active" && r.Phase != "staged" && r.Phase != "active" {
		return capabilityEffectError()
	}
	r.Phase = phase
	r.OperationID = operation
	return s.deploy(ctx, r, rev)
}

type capabilityWireKey struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	NotBefore int64  `json:"notBefore"`
	NotAfter  int64  `json:"notAfter"`
}
type capabilityDeployment struct {
	Revocations capabilityRevocationWire `json:"revocations"`
	Generation  string                   `json:"generation"`
	Phase       string                   `json:"phase"`
	ValidUntil  int64                    `json:"validUntil"`
	Current     capabilityWireKey        `json:"current"`
	Previous    *capabilityWireKey       `json:"previous,omitzero"`
}

func (s *SnippetCapabilityStore) fetch(ctx context.Context, state security.CapabilityKeyState) (security.CapabilityMaterial, error) {
	m, err := s.config.Vault.Fetch(ctx, state.Reference)
	if err != nil || m.ID != state.ID || m.Version != state.Version || m.Reference != state.Reference || len(m.Key) < 32 || m.ExpiresAt.Before(state.ExpiresAt) {
		clear(m.Key)
		return security.CapabilityMaterial{}, capabilityEffectError()
	}
	return m, nil
}
func wireKey(m security.CapabilityMaterial, state security.CapabilityKeyState) capabilityWireKey {
	return capabilityWireKey{ID: m.ID, Key: hex.EncodeToString(m.Key), NotBefore: state.NotBefore.Unix(), NotAfter: state.ExpiresAt.Unix()}
}
func (s *SnippetCapabilityStore) source(ctx context.Context, r CapabilityReceipt) ([]byte, error) {
	template, err := s.template(ctx, r.TemplateDigest)
	if err != nil {
		return nil, err
	}
	current, err := s.fetch(ctx, r.Current)
	if err != nil {
		return nil, err
	}
	defer clear(current.Key)
	d := capabilityDeployment{Generation: strconv.FormatUint(r.Generation, 10), Phase: r.Phase, ValidUntil: r.Current.ExpiresAt.Unix(), Current: wireKey(current, r.Current), Revocations: capabilityRevocationWire{Revision: strconv.FormatUint(r.RevocationRevision, 10), Entries: append([]CapabilityRevocation{}, r.Revocations...)}}
	if r.Previous.Reference != "" && s.config.Now().Before(r.Previous.ExpiresAt) {
		previous, e := s.fetch(ctx, r.Previous)
		if e != nil {
			return nil, e
		}
		defer clear(previous.Key)
		d.Previous = new(wireKey(previous, r.Previous))
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return nil, capabilityEffectError()
	}
	defer clear(encoded)
	source := bytes.Replace(template, []byte(CapabilityDeploymentMarker), encoded, 1)
	if len(source) > 32768 {
		clear(source)
		return nil, capabilityEffectError()
	}
	return source, nil
}
func (s *SnippetCapabilityStore) deploy(ctx context.Context, r CapabilityReceipt, revision uint64) error {
	source, err := s.source(ctx, r)
	if err != nil {
		return err
	}
	defer clear(source)
	r.Digest = edgeDigest(source)
	// Commit intent first. On uncertain publication a restart reconstructs the
	// exact source from Vault references and observes the provider before PUT.
	if s.authorize(ctx) != nil || s.config.Journal.Save(ctx, r, revision) != nil {
		return capabilityEffectError()
	}
	observed, readErr := s.config.Client.SnippetCode(ctx, s.config.SnippetName)
	if readErr != nil || observed.Digest != r.Digest {
		if readErr != nil && !errors.Is(readErr, ErrNotFound) && !isCloudflareNotFound(readErr) {
			return capabilityEffectError()
		}
		if s.authorize(ctx) != nil {
			return capabilityEffectError()
		}
		if s.config.Client.PutSnippetCode(ctx, s.config.SnippetName, r.Digest, source) != nil {
			return capabilityEffectError()
		}
	}
	if s.authorize(ctx) != nil {
		return capabilityEffectError()
	}
	// Initial distribution must establish the Snippet route before its probe.
	if s.config.Zone != nil {
		if ReconcileSnippetRules(ctx, s.config.Client, s.config.Zone, s.config.SnippetName) != nil {
			return capabilityEffectError()
		}
	}
	return s.observe(ctx, r)
}
func (s *SnippetCapabilityStore) observe(ctx context.Context, r CapabilityReceipt) error {
	if !s.config.Now().Before(r.Current.ExpiresAt) || s.authorize(ctx) != nil {
		return capabilityEffectError()
	}
	code, err := s.config.Client.SnippetCode(ctx, s.config.SnippetName)
	if err != nil || code.Digest != r.Digest {
		return capabilityEffectError()
	}
	material, err := s.fetch(ctx, r.Current)
	if err != nil {
		return err
	}
	defer clear(material.Key)
	for _, endpoint := range s.config.ProbeURLs {
		if s.probe(ctx, endpoint, r, material.Key) != nil {
			return capabilityEffectError()
		}
	}
	return s.authorize(ctx)
}
func capabilityMAC(key []byte, text string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *SnippetCapabilityStore) probe(ctx context.Context, endpoint string, r CapabilityReceipt, key []byte) error {
	if s.authorize(ctx) != nil {
		return capabilityEffectError()
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return capabilityEffectError()
	}
	nonce := hex.EncodeToString(nonceBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?nonce="+nonce, nil)
	if err != nil {
		return capabilityEffectError()
	}
	req.Header.Set("x-terrascale-capability-generation-proof", capabilityMAC(key, "terrascale-capability-generation-request-v1\n"+nonce))
	req.Header.Set("Cache-Control", "no-store")
	resp, err := s.config.HTTPClient.Do(req)
	if err != nil {
		return capabilityEffectError()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return capabilityEffectError()
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return capabilityEffectError()
	}
	var proof struct {
		Nonce              string `json:"nonce"`
		Generation         string `json:"generation"`
		Phase              string `json:"phase"`
		ValidUntil         int64  `json:"validUntil"`
		Proof              string `json:"proof"`
		RevocationRevision string `json:"revocationRevision"`
		RevocationDigest   string `json:"revocationDigest"`
	}
	if json.Unmarshal(raw, &proof) != nil || proof.Nonce != nonce || proof.Generation != strconv.FormatUint(r.Generation, 10) || proof.Phase != r.Phase || proof.ValidUntil != r.Current.ExpiresAt.Unix() || proof.RevocationRevision != strconv.FormatUint(r.RevocationRevision, 10) || proof.RevocationDigest != capabilityRevocationDigest(r.Revocations) {
		return capabilityEffectError()
	}
	expected := capabilityMAC(key, "terrascale-capability-generation-response-v2\n"+nonce+"\n"+proof.Generation+"\n"+proof.Phase+"\n"+strconv.FormatInt(proof.ValidUntil, 10)+"\n"+proof.RevocationRevision+"\n"+proof.RevocationDigest)
	if !hmac.Equal([]byte(expected), []byte(proof.Proof)) {
		return capabilityEffectError()
	}
	return nil
}

// template never returns bound source; mirrored artifacts contain only the marker.
func (s *SnippetCapabilityStore) template(ctx context.Context, digest string) ([]byte, error) {
	if digest == edgeDigest(s.config.Source) {
		return s.config.Source, nil
	}
	if s.config.Artifacts == nil || s.config.TemplateService == "" {
		return nil, capabilityEffectError()
	}
	source, err := s.config.Artifacts.EdgeArtifact(ctx, s.config.TemplateService, digest)
	if err != nil || edgeDigest(source) != digest || bytes.Count(source, []byte(CapabilityDeploymentMarker)) != 1 {
		return nil, capabilityEffectError()
	}
	return source, nil
}

// PromoteTemplate preserves the live ring while releasing a new verified
// Snippet template. The durable template digest is resolved again after restart.
func (s *SnippetCapabilityStore) PromoteTemplate(ctx context.Context, service, digest string) error {
	ctx = context.WithValue(ctx, capabilityTemplateContextKey{}, true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if service == "" || service != s.config.TemplateService || s.config.Artifacts == nil {
		return capabilityEffectError()
	}
	if _, err := s.template(ctx, digest); err != nil {
		return err
	}
	receipt, revision, err := s.config.Journal.Load(ctx)
	if err != nil || receipt.Generation == 0 {
		return capabilityEffectError()
	}
	receipt.TemplateDigest = digest
	receipt.OperationID = "snippet-template/" + digest
	return s.deploy(ctx, receipt, revision)
}

// CoordinateTemplateRules validates the rendered source, not the unbound
// artifact digest, before enabling the declared reactive/probe routes.
func (s *SnippetCapabilityStore) CoordinateTemplateRules(ctx context.Context, service, digest string) error {
	ctx = context.WithValue(ctx, capabilityTemplateContextKey{}, true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.Zone == nil || service == "" || service != s.config.TemplateService {
		return capabilityEffectError()
	}
	receipt, _, err := s.config.Journal.Load(ctx)
	if err != nil || receipt.TemplateDigest != digest || receipt.Generation == 0 {
		return capabilityEffectError()
	}
	code, err := s.config.Client.SnippetCode(ctx, s.config.SnippetName)
	if err != nil || code.Digest != receipt.Digest || s.authorize(ctx) != nil {
		return capabilityEffectError()
	}
	if ReconcileSnippetRules(ctx, s.config.Client, s.config.Zone, s.config.SnippetName) != nil {
		return capabilityEffectError()
	}
	return s.observe(ctx, receipt)
}

// ObserveTemplate proves the bound release and declared rule at this instant.
// False is a retryable absence; an unavailable/unauthorized observation errors.
func (s *SnippetCapabilityStore) ObserveTemplate(ctx context.Context, service, digest string) (bool, error) {
	ctx = context.WithValue(ctx, capabilityTemplateContextKey{}, true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if service == "" || service != s.config.TemplateService || s.config.Zone == nil {
		return false, capabilityEffectError()
	}
	receipt, _, err := s.config.Journal.Load(ctx)
	if err != nil {
		return false, capabilityEffectError()
	}
	if receipt.Generation == 0 || receipt.TemplateDigest != digest {
		return false, nil
	}
	code, readErr := s.config.Client.SnippetCode(ctx, s.config.SnippetName)
	if errors.Is(readErr, ErrNotFound) {
		return false, nil
	}
	if readErr != nil {
		return false, capabilityEffectError()
	}
	if code.Digest != receipt.Digest {
		return false, nil
	}
	if err := s.observe(ctx, receipt); err != nil {
		return false, err
	}
	snippets, err := s.config.Client.ListSnippets(ctx)
	if err != nil {
		return false, capabilityEffectError()
	}
	for _, declaration := range s.config.Zone.SnippetRules {
		if declaration.SnippetName != s.config.SnippetName {
			continue
		}
		expected := SnippetRuleWire{Expression: snippetGateExpression(declarationHosts(declaration), declaration.PathPrefix), Description: refDescription(declaration.SnippetName), Enabled: declaration.Enabled}
		for _, snippet := range snippets {
			if snippet.Name == s.config.SnippetName && len(snippet.Rules) == 1 && snippet.Rules[0] == expected && expected.Enabled {
				return true, nil
			}
		}
	}
	return false, nil
}

// ValidateCapabilityDeployment validates static declarations without contacting
// Vault, Cloudflare, NATS, or any probe ingress.
func ValidateCapabilityDeployment(source []byte, zone *Zone, snippetName string, probeURLs []string) error {
	if bytes.Count(source, []byte(CapabilityDeploymentMarker)) != 1 || zone == nil || snippetName == "" || len(probeURLs) == 0 || zone.validateGateDeclaration() != nil {
		return capabilityEffectError()
	}
	var hostnames []string
	for _, rule := range zone.SnippetRules {
		if rule.SnippetName == snippetName && rule.Enabled {
			hostnames = declarationHosts(rule)
		}
	}
	if len(hostnames) == 0 {
		return capabilityEffectError()
	}
	if snippetName == GateSnippetName && !requiredGateHosts(hostnames) {
		return capabilityEffectError()
	}
	for _, hostname := range hostnames {
		if hostname == "" || strings.TrimSpace(hostname) != hostname || strings.ContainsAny(hostname, "/:?#@*\\") {
			return capabilityEffectError()
		}
	}
	for _, hostname := range hostnames {
		if len(hostname) > 253 {
			return capabilityEffectError()
		}
		for label := range strings.SplitSeq(hostname, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return capabilityEffectError()
			}
			for _, char := range label {
				if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
					return capabilityEffectError()
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, endpoint := range probeURLs {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || !containsFold(hostnames, u.Hostname()) || u.Path != "/.well-known/terrascale-capability-generation" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.Contains(endpoint, "#") {
			return capabilityEffectError()
		}
		port := u.Port()
		if port != "" {
			n, e := strconv.Atoi(port)
			if e != nil || n < 1 || n > 65535 {
				return capabilityEffectError()
			}
			port = strconv.Itoa(n)
		}
		identity := strings.ToLower(u.Hostname()) + ":" + port
		if port == "443" {
			identity = strings.ToLower(u.Hostname()) + ":"
		}
		if seen[identity] {
			return capabilityEffectError()
		}
		seen[identity] = true
	}
	return nil
}

func requiredGateHosts(hosts []string) bool {
	want := map[string]bool{"sync.api.terrascale.tech": true, "gru.sync.api.terrascale.tech": true, "sfo.sync.api.terrascale.tech": true, "fra.sync.api.terrascale.tech": true}
	if len(hosts) != len(want) {
		return false
	}
	for _, host := range hosts {
		if !want[strings.ToLower(host)] {
			return false
		}
	}
	return true
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

type capabilityTemplateContextKey struct{}

func (s *SnippetCapabilityStore) authorize(ctx context.Context) error {
	if ctx.Value(capabilityTemplateContextKey{}) == true && delivery.CheckExecutionFence(ctx) != nil {
		return capabilityEffectError()
	}
	return s.config.Authorize(ctx)
}

type capabilityTemplateTransport struct {
	next      http.RoundTripper
	authorize func(context.Context) error
}

func (t capabilityTemplateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Value(capabilityTemplateContextKey{}) == true {
		if delivery.CheckExecutionFence(r.Context()) != nil || t.authorize(r.Context()) != nil {
			return nil, capabilityEffectError()
		}
	}
	return t.next.RoundTrip(r)
}
