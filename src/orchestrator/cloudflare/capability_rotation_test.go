package cloudflare_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorizationlease"
	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	sandboxcf "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type rotationJournal struct {
	mu       sync.Mutex
	receipt  cf.CapabilityReceipt
	revision uint64
	fail     bool
}

func (j *rotationJournal) Load(context.Context) (cf.CapabilityReceipt, uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.receipt, j.revision, nil
}
func (j *rotationJournal) Save(_ context.Context, r cf.CapabilityReceipt, rev uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fail {
		return errors.New("journal unavailable")
	}
	if rev != j.revision {
		return cf.ErrCapabilityJournalConflict
	}
	j.receipt = r
	j.revision++
	return nil
}

type rotationVault map[string]security.CapabilityMaterial

func (v rotationVault) Generate(context.Context, security.CapabilityRequest) (security.CapabilityMaterial, error) {
	return security.CapabilityMaterial{}, errors.New("unexpected generate")
}

type originVault map[string]security.OriginProofMaterial

func (v originVault) Generate(context.Context, security.OriginProofRequest) (security.OriginProofMaterial, error) {
	return security.OriginProofMaterial{}, errors.New("unexpected generate")
}
func (v originVault) Retire(context.Context, string, string) error {
	return errors.New("unexpected retire")
}
func (v originVault) Fetch(_ context.Context, ref string) (security.OriginProofMaterial, error) {
	m, ok := v[ref]
	if !ok {
		return m, errors.New("unknown reference")
	}
	m.Secret = bytes.Clone(m.Secret)
	return m, nil
}
func (v rotationVault) Retire(context.Context, string, string) error {
	return errors.New("unexpected retire")
}
func (v rotationVault) Fetch(_ context.Context, ref string) (security.CapabilityMaterial, error) {
	m, ok := v[ref]
	if !ok {
		return m, errors.New("unknown reference")
	}
	m.Key = bytes.Clone(m.Key)
	return m, nil
}
func rotationMAC(key []byte, body string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

type rotationFixture struct {
	store         *cf.SnippetCapabilityStore
	config        cf.SnippetCapabilityStoreConfig
	journal       *rotationJournal
	vault         rotationVault
	originVault   originVault
	provider      *sandboxcf.Server
	now           time.Time
	puts          atomic.Int64
	forged        atomic.Bool
	deny          atomic.Bool
	denyAfterRead atomic.Bool
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	f := &rotationFixture{journal: &rotationJournal{}, vault: rotationVault{}, originVault: originVault{}, now: time.Unix(1800000000, 0), provider: sandboxcf.New(sandboxcf.Config{ZoneID: "zone", AccountID: "account"})}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt, revision, _ := f.journal.Load(r.Context())
		if revision == 0 || receipt.Digest == "" {
			t.Error("provider contacted before durable intent")
		}
		if r.Method == http.MethodPut && r.URL.Path == "/zones/zone/snippets/gate" {
			f.puts.Add(1)
		}
		f.provider.ServeHTTP(w, r)
		if r.Method == http.MethodGet && f.denyAfterRead.Load() {
			f.deny.Store(true)
		}
	}))
	t.Cleanup(api.Close)
	probe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt, _, _ := f.journal.Load(r.Context())
		key := f.vault[receipt.Current.Reference].Key
		nonce := r.URL.Query().Get("nonce")
		if r.URL.Path != "/.well-known/terrascale-capability-generation" || len(nonce) != 64 || r.Header.Get("x-terrascale-capability-generation-proof") != rotationMAC(key, "terrascale-capability-generation-request-v1\n"+nonce) {
			t.Error("invalid probe request")
			w.WriteHeader(403)
			return
		}
		generation := fmt.Sprint(receipt.Generation)
		expires := receipt.Current.ExpiresAt.Unix()
		revocationCanonical := ""
		for _, entry := range receipt.Revocations {
			revocationCanonical += fmt.Sprintf("%s.%d\n", entry.Scope, entry.ExpiresAt)
		}
		revocationHash := sha256.Sum256([]byte(revocationCanonical))
		revocationDigest := hex.EncodeToString(revocationHash[:])
		revocationRevision := fmt.Sprint(receipt.RevocationRevision)
		leaseAudience, leaseDigest := f.config.AuthorizationLeaseAudience, f.config.AuthorizationLeaseKeys.Digest()
		proof := rotationMAC(key, fmt.Sprintf("terrascale-capability-generation-response-v4\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s", nonce, generation, receipt.Phase, expires, revocationRevision, revocationDigest, leaseAudience, leaseDigest))
		if f.forged.Load() {
			proof = rotationMAC([]byte("attacker"), nonce)
		}
		body, _ := json.Marshal(map[string]any{"nonce": nonce, "generation": generation, "phase": receipt.Phase, "validUntil": expires, "proof": proof, "revocationRevision": revocationRevision, "revocationDigest": revocationDigest, "authorizationLeaseAudience": leaseAudience, "authorizationLeaseKeysDigest": leaseDigest})
		w.Write(body)
	}))
	t.Cleanup(probe.Close)
	client := cf.NewClient("token", "zone", "account")
	client.BaseURL = api.URL
	f.config = cf.SnippetCapabilityStoreConfig{AuthorizationLeaseAudience: "https://api.terrascale.tech", AuthorizationLeaseKeys: authorizationlease.Ring{Keys: []authorizationlease.Key{{ID: "lease", Key: "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", NotBefore: 1, NotAfter: 4102444800}}}, Client: client, Zone: &cf.Zone{SnippetRules: []cf.SnippetRule{{SnippetName: "gate", Hostnames: []string{"127.0.0.1"}, PathPrefix: "/api/v1/reactive/", Enabled: true}}}, SnippetName: "gate", Source: []byte("const deployment = " + cf.CapabilityDeploymentMarker + ";"), Vault: f.vault, OriginVault: f.originVault, Journal: f.journal, Authorize: func(context.Context) error {
		if f.deny.Load() {
			return errors.New("authority lost")
		}
		return nil
	}, ProbeURLs: []string{probe.URL + "/.well-known/terrascale-capability-generation"}, HTTPClient: probe.Client(), Now: func() time.Time { return f.now }}
	var err error
	f.store, err = cf.NewSnippetCapabilityStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *rotationFixture) material(version uint64) security.CapabilityMaterial {
	m := security.CapabilityMaterial{ID: fmt.Sprintf("key-%d", version), Reference: fmt.Sprintf("vault/key-%d", version), Version: version, NotBefore: f.now, ExpiresAt: f.now.Add(2 * time.Hour), Key: bytes.Repeat([]byte{byte(version)}, 32)}
	f.vault[m.Reference] = m
	return m
}
func (f *rotationFixture) originMaterial(version uint64) security.OriginProofMaterial {
	m := security.OriginProofMaterial{ID: fmt.Sprintf("origin-%d", version), Reference: fmt.Sprintf("vault/origin-%d", version), Version: version, Bucket: f.now.Unix() / int64(security.CapabilityPeriod/time.Second), NotBefore: f.now, ExpiresAt: f.now.Add(2 * time.Hour), Secret: bytes.Repeat([]byte{byte(version + 10)}, 32)}
	f.originVault[m.Reference] = m
	return m
}
func TestSnippetCapabilityRotationLifecycle(t *testing.T) {
	f := newRotationFixture(t)
	first := f.material(1)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: first, OriginProof: f.originMaterial(1)}, "stage-1"); err != nil {
		t.Fatal(err)
	}
	r, _, _ := f.journal.Load(t.Context())
	if r.Phase != "staged" {
		t.Fatalf("phase = %s", r.Phase)
	}
	if err := f.store.Activate(t.Context(), 1, "activate-1"); err != nil {
		t.Fatal(err)
	}
	second := f.material(2)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: second, PreviousCapability: first, OriginProof: f.originMaterial(2), PreviousOriginProof: f.originMaterial(1)}, "stage-2"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Activate(t.Context(), 2, "activate-2"); err != nil {
		t.Fatal(err)
	}
	observation, err := f.store.Verify(t.Context(), 2)
	if err != nil || observation.Generation != 2 || !observation.ValidUntil.Equal(second.ExpiresAt) {
		t.Fatalf("observation = %+v, %v", observation, err)
	}
	if err := f.store.Retire(t.Context(), 1, "early-retire"); err == nil {
		t.Fatal("retired previous before overlap elapsed")
	}
	f.now = f.now.Add(security.CapabilityOverlap)
	if err := f.store.Retire(t.Context(), 1, "retire-1"); err != nil {
		t.Fatal(err)
	}
	r, _, _ = f.journal.Load(t.Context())
	if r.Previous.Reference != "" {
		t.Fatal("retired key retained")
	}
	if err := f.store.Fence(t.Context(), "fence"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Verify(t.Context(), 2); err == nil {
		t.Fatal("fenced deployment verified")
	}
}
func TestSnippetCapabilityForgedProofRejected(t *testing.T) {
	f := newRotationFixture(t)
	f.forged.Store(true)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: f.material(1), OriginProof: f.originMaterial(1)}, "stage"); err == nil {
		t.Fatal("accepted forged proof")
	}
}
func TestSnippetCapabilityLostPublicationResponseRecoversByObservation(t *testing.T) {
	f := newRotationFixture(t)
	credentials := security.CredentialSet{Capability: f.material(1), OriginProof: f.originMaterial(1)}
	f.provider.AddFault(sandboxcf.Fault{Method: http.MethodPut, Path: "/zones/zone/snippets/gate", Calls: 1, Steps: []sandboxcf.FaultStep{{Status: 500, Commit: true}}})
	if err := f.store.Distribute(t.Context(), credentials, "stage"); err == nil {
		t.Fatal("lost response reported success")
	}
	restarted, err := cf.NewSnippetCapabilityStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Distribute(t.Context(), credentials, "stage"); err != nil {
		t.Fatal(err)
	}
	if got := f.puts.Load(); got != 1 {
		t.Fatalf("PUT count = %d, want 1", got)
	}
}
func TestSnippetCapabilityDurabilityAndAuthorityPreventPublication(t *testing.T) {
	for _, failure := range []string{"journal", "authority", "authority-after-read"} {
		t.Run(failure, func(t *testing.T) {
			f := newRotationFixture(t)
			switch failure {
			case "journal":
				f.journal.fail = true
			case "authority":
				f.deny.Store(true)
			case "authority-after-read":
				f.denyAfterRead.Store(true)
			}
			if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: f.material(1), OriginProof: f.originMaterial(1)}, "stage"); err == nil {
				t.Fatal("deployment succeeded despite failed prerequisite")
			}
			if got := f.puts.Load(); got != 0 {
				t.Fatalf("PUT count = %d, want 0", got)
			}
		})
	}
}

func TestSnippetCapabilityTemplateReleaseSurvivesRestartAndRotation(t *testing.T) {
	f := newRotationFixture(t)
	candidate := []byte("// released template\nconst deployment = " + cf.CapabilityDeploymentMarker + ";")
	digest := testEdgeDigest(candidate)
	f.config.TemplateService = "ts-proxy-snippet"
	f.config.Artifacts = edgeArtifactMap{f.config.TemplateService + "\x00" + digest: candidate}
	var err error
	f.store, err = cf.NewSnippetCapabilityStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	first := f.material(1)
	second := f.material(2)
	ofirst := f.originMaterial(1)
	osecond := f.originMaterial(2)
	for _, credentials := range []security.CredentialSet{{Capability: first, OriginProof: ofirst}, {Capability: second, PreviousCapability: first, OriginProof: osecond, PreviousOriginProof: ofirst}} {
		if err := f.store.Distribute(t.Context(), credentials, "stage"); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Activate(t.Context(), credentials.Capability.Version, "activate"); err != nil {
			t.Fatal(err)
		}
	}
	before, _, _ := f.journal.Load(t.Context())
	if err := f.store.PromoteTemplate(templateContext(t), f.config.TemplateService, digest); err != nil {
		t.Fatal(err)
	}
	released, _, _ := f.journal.Load(t.Context())
	if released.TemplateDigest != digest || released.Digest == before.Digest || released.Digest == digest {
		t.Fatalf("release digests = %+v", released)
	}
	if released.Current != before.Current || released.Previous != before.Previous || released.Phase != before.Phase || released.Generation != before.Generation {
		t.Fatal("template release changed the live key ring")
	}
	// The process still boots from the initial template; receipt resolution must
	// load the release artifact before reconstructing an idempotent publication.
	restarted, err := cf.NewSnippetCapabilityStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	puts := f.puts.Load()
	if err := restarted.Distribute(t.Context(), security.CredentialSet{Capability: second, PreviousCapability: first, OriginProof: f.originMaterial(2), PreviousOriginProof: f.originMaterial(1)}, "retry"); err != nil {
		t.Fatal(err)
	}
	if f.puts.Load() != puts {
		t.Fatal("restart republished a template already present")
	}
	third := f.material(3)
	if err := restarted.Distribute(t.Context(), security.CredentialSet{Capability: third, PreviousCapability: second, OriginProof: f.originMaterial(3), PreviousOriginProof: f.originMaterial(2)}, "stage-next"); err != nil {
		t.Fatal(err)
	}
	next, _, _ := f.journal.Load(t.Context())
	if next.TemplateDigest != digest || next.Generation != 3 || next.Current.Reference != third.Reference {
		t.Fatalf("next rotation = %+v", next)
	}
}

func templateContext(t *testing.T) context.Context {
	t.Helper()
	ctx, err := delivery.WithExecutionFence(t.Context(), delivery.OperationFence{OperationID: "release", RequestDigest: "digest", OwnerID: "owner", Generation: 1}, func(delivery.OperationFence) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestCapabilityDeploymentDeclarationValidation(t *testing.T) {
	source := []byte(cf.CapabilityDeploymentMarker)
	hosts := []string{"sync.api.terrascale.tech", "gru.sync.api.terrascale.tech", "sfo.sync.api.terrascale.tech", "fra.sync.api.terrascale.tech"}
	zone := &cf.Zone{SnippetRules: []cf.SnippetRule{{SnippetName: "ts-gate", Hostnames: hosts, Enabled: true}}}
	var probes []string
	for _, host := range hosts {
		probes = append(probes, "https://"+host+"/.well-known/terrascale-capability-generation")
	}
	base := probes[0]
	if err := cf.ValidateCapabilityDeployment(source, zone, "ts-gate", probes); err != nil {
		t.Fatal(err)
	}
	for _, urls := range [][]string{nil, {base, base}, {base, "https://sync.api.terrascale.tech:443/.well-known/terrascale-capability-generation"}, {"https://other.example/.well-known/terrascale-capability-generation"}, {base + "?"}, {base + "#fragment"}, {"https://user@sync.api.terrascale.tech/.well-known/terrascale-capability-generation"}, {"https://sync.api.terrascale.tech:99999/.well-known/terrascale-capability-generation"}} {
		if cf.ValidateCapabilityDeployment(source, zone, "ts-gate", urls) == nil {
			t.Fatalf("accepted invalid probes %v", urls)
		}
	}
	if cf.ValidateCapabilityDeployment(source, nil, "ts-gate", []string{base}) == nil {
		t.Fatal("accepted missing zone")
	}
}

func TestSnippetTemplateChecksDeliveryFenceBeforeDispatch(t *testing.T) {
	f := newRotationFixture(t)
	material := f.material(1)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: material, OriginProof: f.originMaterial(1)}, "initial"); err != nil {
		t.Fatal(err)
	}
	candidate := []byte("// candidate\n" + cf.CapabilityDeploymentMarker)
	digest := testEdgeDigest(candidate)
	f.config.TemplateService = "ts-proxy-snippet"
	f.config.Artifacts = edgeArtifactMap{f.config.TemplateService + "\x00" + digest: candidate}
	store, err := cf.NewSnippetCapabilityStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	before := f.puts.Load()
	var checks int
	ctx, err := delivery.WithExecutionFence(t.Context(), delivery.OperationFence{OperationID: "release", RequestDigest: "digest", OwnerID: "owner", Generation: 1}, func(delivery.OperationFence) error {
		checks++
		if checks >= 3 {
			return errors.New("operation ownership lost")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.PromoteTemplate(ctx, f.config.TemplateService, digest) == nil {
		t.Fatal("accepted lost operation fence")
	}
	if f.puts.Load() != before {
		t.Fatal("published after operation fence loss")
	}
	if store.PromoteTemplate(t.Context(), f.config.TemplateService, digest) == nil {
		t.Fatal("accepted missing operation fence")
	}
}

func TestSnippetRevocationsPersistAcrossRotationAndRejectOverflow(t *testing.T) {
	f := newRotationFixture(t)
	first := f.material(1)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: first, OriginProof: f.originMaterial(1)}, "stage"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Activate(t.Context(), 1, "activate"); err != nil {
		t.Fatal(err)
	}
	scope := "scope-" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	entry := cf.CapabilityRevocation{Scope: scope, ExpiresAt: f.now.Add(20 * time.Minute).Unix()}
	proof, err := f.store.PublishRevocations(t.Context(), []cf.CapabilityRevocation{entry}, "delete")
	if err != nil || proof.Revision != 1 || proof.Digest == "" {
		t.Fatalf("revocation receipt: %+v %v", proof, err)
	}
	puts := f.puts.Load()
	repeat, err := f.store.PublishRevocations(t.Context(), []cf.CapabilityRevocation{entry}, "delete")
	if err != nil || repeat.Revision != 1 || f.puts.Load() != puts {
		t.Fatal("duplicate revocation republished")
	}
	second := f.material(2)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: second, PreviousCapability: first, OriginProof: f.originMaterial(2), PreviousOriginProof: f.originMaterial(1)}, "next"); err != nil {
		t.Fatal(err)
	}
	current, _, _ := f.journal.Load(t.Context())
	if current.RevocationRevision != 1 || len(current.Revocations) != 1 || current.Revocations[0] != entry {
		t.Fatal("rotation lost live revocation")
	}
	additions := make([]cf.CapabilityRevocation, cf.MaximumCapabilityRevocations)
	for i := range additions {
		additions[i] = cf.CapabilityRevocation{Scope: fmt.Sprintf("scope-%064x", i+10), ExpiresAt: entry.ExpiresAt}
	}
	if _, err := f.store.PublishRevocations(t.Context(), additions, "overflow"); err == nil {
		t.Fatal("overflow evicted live entries")
	}
	unchanged, _, _ := f.journal.Load(t.Context())
	if unchanged.RevocationRevision != 1 || len(unchanged.Revocations) != 1 {
		t.Fatal("overflow mutated durable ring")
	}
	f.now = f.now.Add(20 * time.Minute)
	proof, err = f.store.PublishRevocations(t.Context(), nil, "prune")
	if err != nil || proof.Revision != 2 {
		t.Fatalf("expiry pruning: %+v %v", proof, err)
	}
	pruned, _, _ := f.journal.Load(t.Context())
	if len(pruned.Revocations) != 0 {
		t.Fatal("expired revocations were not pruned")
	}
}

func TestCapabilityProbeBindsLeaseAudienceKeysAndExpiry(t *testing.T) {
	for name, mutate := range map[string]func(*rotationFixture){
		"audience": func(f *rotationFixture) { f.config.AuthorizationLeaseAudience = "https://other.example" },
		"same ID different key": func(f *rotationFixture) {
			f.config.AuthorizationLeaseKeys.Keys[0].Key = hex.EncodeToString(bytes.Repeat([]byte{42}, 32))
		},
		"extended window": func(f *rotationFixture) { f.config.AuthorizationLeaseKeys.Keys[0].NotAfter++ },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRotationFixture(t)
			if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: f.material(1), OriginProof: f.originMaterial(1)}, "stage"); err != nil {
				t.Fatal(err)
			}
			mutate(f)
			if _, err := f.store.Verify(t.Context(), 1); err == nil {
				t.Fatal("stale lease verifier configuration accepted")
			}
		})
	}
}

func TestCapabilityDeploymentRejectsSharedLeaseSigningMaterial(t *testing.T) {
	f := newRotationFixture(t)
	capability := f.material(1)
	f.config.AuthorizationLeaseKeys.Keys[0].Key = hex.EncodeToString(capability.Key)
	store, err := cf.NewSnippetCapabilityStore(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Distribute(t.Context(), security.CredentialSet{Capability: capability, OriginProof: f.originMaterial(1)}, "stage"); err == nil {
		t.Fatal("lease key reused capability key")
	}
	if f.puts.Load() != 0 {
		t.Fatal("shared key reached provider")
	}
}
