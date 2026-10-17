package rootfoundation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

type ocirJournalProtocol struct {
	mu      sync.Mutex
	grant   []byte
	path    string
	token   map[string]any
	creates int
	lostCAS bool
}

func (p *ocirJournalProtocol) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	write := func(value any) { _ = json.MarshalWrite(w, value) }
	if strings.Contains(r.URL.Path, "/authTokens") {
		if r.Method == http.MethodGet {
			items := []any{}
			if p.token != nil {
				items = append(items, p.token)
			}
			write(items)
			return
		}
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			w.WriteHeader(400)
			return
		}
		p.creates++
		p.token = map[string]any{"id": "ocid1.credential.oc1..uncertain", "userId": "ocid1.user.oc1..pull", "description": body["description"], "timeCreated": time.Now().UTC().Format(time.RFC3339Nano), "lifecycleState": "ACTIVE"}
		w.WriteHeader(503)
		write(map[string]string{"code": "Unavailable", "message": "response withheld after accepted mint"})
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/GRU.json") {
		_, _ = w.Write(p.grant)
		return
	}
	wire, readErr := os.ReadFile(p.path)
	etag := fmt.Sprintf("%x", sha256.Sum256(wire))
	if r.Method == http.MethodGet {
		if readErr != nil {
			w.WriteHeader(404)
			write(map[string]string{"code": "NotFound", "message": "protected record absent"})
			return
		}
		w.Header().Set("etag", etag)
		_, _ = w.Write(wire)
		return
	}
	if r.Method != http.MethodPut {
		w.WriteHeader(405)
		return
	}
	if r.Header.Get("if-none-match") == "*" && readErr == nil || r.Header.Get("if-match") != "" && (readErr != nil || r.Header.Get("if-match") != etag) {
		w.WriteHeader(412)
		write(map[string]string{"code": "PreconditionFailed", "message": "conditional record replaced"})
		return
	}
	next, err := io.ReadAll(r.Body)
	if err != nil || os.WriteFile(p.path, next, 0600) != nil {
		w.WriteHeader(500)
		return
	}
	if p.lostCAS {
		p.lostCAS = false
		w.WriteHeader(503)
		write(map[string]string{"code": "Unavailable", "message": "CAS response withheld after disk commit"})
		return
	}
	w.Header().Set("etag", fmt.Sprintf("%x", sha256.Sum256(next)))
}

func TestOCIRProtectedSDKJournalRestartPreservesUncertainAttempt(t *testing.T) {
	remote := &ocirJournalProtocol{path: filepath.Join(t.TempDir(), "own-cell")}
	factory, endpoint := ociresourcetest.Server(t, remote.serve)
	scope := journalIssuerScope(t, remote, factory, endpoint)
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&objects.BaseClient, endpoint)
	open := func() region.FoundationStore {
		store, err := region.NewObjectFoundationStore(&objects, "ns", "heads")
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open()
	now := time.Now().UTC()
	original := region.FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: factory.Region(), TenancyID: scope.TenancyID(), ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: scope.Generation(), GrantSHA256: scope.GrantDigest(), IntentDigest: strings.Repeat("a", 64), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: map[string]string{"vault": scope.Intent().VaultTarget.VaultID}}
	if _, err := store.CompareAndSwap(t.Context(), original, ""); err != nil {
		t.Fatal(err)
	}
	var fenced atomic.Bool
	guard := func(ctx context.Context) error {
		if fenced.Load() {
			return ErrScope
		}
		return ctx.Err()
	}
	reopen := func() *ocirJournal {
		return &ocirJournal{store: open(), cell: "GRU", original: original, scope: scope, deadline: now.Add(time.Minute), guard: guard}
	}
	journal := reopen()
	canonical, err := json.Marshal(struct {
		Tenancy, Installation string
		Intent                region.OCIRIssuerIntent
	}{scope.TenancyID(), scope.InstallationID(), scope.Intent()}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	hash := hex.EncodeToString(digest[:])
	key := "ocir-issuer." + hash
	state := region.OCIRIssuanceState{ScopeHash: hash, Generation: scope.Generation(), GrantDigest: scope.GrantDigest(), OperationID: uuid.New().String(), Stage: "token-pending", UserID: "ocid1.user.oc1..pull", TokenOperation: uuid.New().String(), TokenStarted: now, TokenExpires: now.Add(time.Minute)}
	revision, err := journal.CompareAndSwap(t.Context(), key, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := factory.Identity()
	if err != nil {
		t.Fatal(err)
	}
	destination, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	iam.HTTPClient = ocirJournalRedirect{destination: destination}
	ociclient.ConfigureRequestCancellation(&iam.BaseClient)
	effect, cancelEffect := context.WithDeadline(t.Context(), state.TokenExpires)
	defer cancelEffect()
	effect = ociclient.WithWireAttempt(effect, journal.BeginEffect)
	_, err = iam.CreateAuthToken(ociclient.RequestContext(effect), identity.CreateAuthTokenRequest{UserId: new(state.UserID), Description: new("terrascale-ocir:" + state.TokenOperation), OpcRetryToken: new(state.TokenOperation), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
	if err == nil {
		t.Fatal("lost once-returned token response unexpectedly succeeded")
	}
	observed, err := iam.ListAuthTokens(ociclient.RequestContext(t.Context()), identity.ListAuthTokensRequest{UserId: new(state.UserID)})
	if err != nil || len(observed.Items) != 1 {
		t.Fatalf("reconcile accepted token: %v", err)
	}
	state.TokenID = *observed.Items[0].Id
	state.Stage = "vault-pending"
	remote.mu.Lock()
	remote.lostCAS = true
	remote.mu.Unlock()
	if _, err := journal.CompareAndSwap(t.Context(), key, state, revision); err == nil {
		t.Fatal("lost accepted CAS response unexpectedly succeeded")
	}
	// Reconstruct the actual production adapter and SDK-backed store from disk.
	journal = reopen()
	loaded, acceptedRevision, err := journal.Load(t.Context(), key)
	if err != nil || acceptedRevision != revision+1 || loaded.TokenOperation != state.TokenOperation || loaded.TokenID != state.TokenID || !loaded.TokenExpires.Equal(state.TokenExpires) {
		t.Fatalf("original uncertain attempt lost during restart: %+v %v", loaded, err)
	}
	record, protectedETag, err := store.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	rejectRemoval := func(stage string) {
		t.Helper()
		t.Run("sibling-removal-"+stage, func(t *testing.T) {
			snapshot, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.OCIRIssuances[key].State.Stage != stage {
				t.Fatal("fixture did not persist requested stage")
			}
			removed := snapshot
			removed.OCIRIssuances = nil
			if _, err := store.CompareAndSwap(t.Context(), removed, etag); err == nil {
				t.Fatal("omitted issuance sibling reset original operation")
			}
			preserved, currentETag, err := store.Load(t.Context(), "GRU")
			if err != nil || currentETag != etag || preserved.OCIRIssuances[key].State.OperationID != state.OperationID || preserved.OCIRIssuances[key].Attempts[state.TokenOperation].TokenID != state.TokenID {
				t.Fatal("rejected omission changed original disk history")
			}
		})
	}
	rejectRemoval("vault-pending")
	for _, field := range []string{"attempts", "requests", "origin", "request-deadline"} {
		t.Run("history-removal-"+field, func(t *testing.T) {
			wire, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var removed region.FoundationRecord
			if err := json.Unmarshal(wire, &removed); err != nil {
				t.Fatal(err)
			}
			entry := removed.OCIRIssuances[key]
			switch field {
			case "attempts":
				entry.Attempts = nil
			case "requests":
				entry.Requests = nil
			case "origin":
				entry.Origin = region.OCIRIssuanceOrigin{}
			case "request-deadline":
				for hash, request := range entry.Requests {
					request.Deadline = request.Deadline.Add(time.Minute)
					entry.Requests[hash] = request
				}
			}
			removed.OCIRIssuances[key] = entry
			if _, err := store.CompareAndSwap(t.Context(), removed, protectedETag); err == nil {
				t.Fatal("original uncertain issuance history was removed")
			}
		})
	}
	proof := record.OCIRIssuances[key].Attempts[state.TokenOperation]
	if len(record.OCIRIssuances[key].Requests) != 1 {
		t.Fatal("actual SDK effect lacked original protected wire checkpoint")
	}
	for _, request := range record.OCIRIssuances[key].Requests {
		if request.RetryToken != state.TokenOperation || request.BodySHA256 == "" || request.FirstAttemptAt.IsZero() || !request.Deadline.Equal(state.TokenExpires) || len(request.Dispatches) != 1 || !request.Dispatches[0].Sent || request.Dispatches[0].Status != 503 {
			t.Fatal("original SDK request or ambiguous outcome lost")
		}
	}
	if proof.TokenID != state.TokenID || proof.RequestSHA256 == "" || proof.Epoch != original.Epoch || !proof.ExpiresAt.Equal(state.TokenExpires) || record.ResourceIDs["vault"] != original.ResourceIDs["vault"] {
		t.Fatal("restart changed original authority, request, credential or unrelated sibling")
	}
	wire, err := os.ReadFile(remote.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "private-issued-token") || strings.Contains(string(wire), "password") {
		t.Fatal("protected record contains credential material")
	}
	changed := loaded
	changed.TokenExpires = changed.TokenExpires.Add(time.Minute)
	if _, err := journal.CompareAndSwap(t.Context(), key, changed, acceptedRevision); err == nil {
		t.Fatal("restart extended original token expiry")
	}
	if _, err := journal.CompareAndSwap(t.Context(), key, loaded, revision); err == nil {
		t.Fatal("stale pre-response CAS revision accepted")
	}
	// Seed a completed public receipt to verify every other root writer also
	// preserves ready history. This does not qualify Vault publication.
	ready := loaded
	ready.Stage = "ready"
	ready.TokenOperation = ""
	ready.BeforeTokens = nil
	ready.SecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull"
	ready.Version = 1
	ready.Hash = strings.Repeat("c", 64)
	ready.PublishedAt = time.Now().UTC()
	if _, err := journal.CompareAndSwap(t.Context(), key, ready, acceptedRevision); err != nil {
		t.Fatal(err)
	}
	rejectRemoval("ready")
	fenced.Store(true)
	if _, _, err := journal.Load(t.Context(), key); err == nil {
		t.Fatal("fenced source read accepted")
	}
	fenced.Store(false)
	if err := os.Rename(remote.path, remote.path+".retained"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Load(t.Context(), key); err == nil || errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatal("missing protected record became a new operation")
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.creates != 1 {
		t.Fatal("journal reconstruction blindly minted another token")
	}
	// This scenario exercises real signed SDK requests, disk and production CAS;
	// it does not establish a sealed runtime/HomeIAM startup admission.
}

func journalIssuerScope(t *testing.T, remote *ocirJournalProtocol, factory *ociclient.Factory, endpoint string) region.VerifiedOCIRIssuer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	installation, deployment, cluster := entityid.New(), entityid.New(), entityid.New()
	domain := bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", LedgerBucket: "ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"}
	target := vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.owned", KeyID: domain.HeadKMSKeyOCID}
	grant := region.FoundationGrant{InstallationID: installation, SchemaVersion: 1, Generation: 1, TenancyID: "ocid1.tenancy.oc1..t", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "fixture",
		Regions:            []region.FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": "ocid1.tenancy.oc1..t", "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{"control_compartment": target.CompartmentID, "vault": target.VaultID, "key": target.KeyID}}}},
		ReleaseAuthorities: []region.ContainerReleaseAuthorityIntent{{ImageRepository: "sa-saopaulo-1.ocir.io/ns/terrascale/terrabase"}},
		OCIRIssuances:      []region.OCIRIssuerIntent{{RegistryHost: "sa-saopaulo-1.ocir.io", OCIRegion: "sa-saopaulo-1", RepositoryCompartmentID: target.CompartmentID, RepositoryName: "terrascale/terrabase", RegistryNamespace: "ns", PrincipalName: "terrascale-pull", PrincipalEmail: "terrascale-pull@terrascale.tech", VaultTarget: target, SecretName: "gru-orch-ocir-pull"}}}
	for _, repository := range []string{"ts-auth", "function-worker"} {
		image := "gru.ocir.io/ns/terrascale/" + repository
		principal, email, secret, err := region.OCIRServiceIdentity(installation, image)
		if err != nil {
			t.Fatal(err)
		}
		grant.ReleaseAuthorities = append(grant.ReleaseAuthorities, region.ContainerReleaseAuthorityIntent{ImageRepository: image})
		grant.OCIRIssuances = append(grant.OCIRIssuances, region.OCIRIssuerIntent{OCIRegion: "sa-saopaulo-1", RegistryHost: "gru.ocir.io", RepositoryCompartmentID: target.CompartmentID, RepositoryName: "terrascale/" + repository, RegistryNamespace: "ns", PrincipalName: principal, PrincipalEmail: email, VaultTarget: target, SecretName: secret})
	}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "foundation", Slot: cluster}, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	remote.mu.Lock()
	remote.grant = wire
	remote.mu.Unlock()
	sum := sha256.Sum256(wire)
	home := bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, TenancyID: grant.TenancyID, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, GrantGeneration: 1, GrantSHA256: hex.EncodeToString(sum[:])}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	intentHash := sha256.Sum256(intentWire)
	slots := []string{"controller-a", "controller-b", "controller-c"}
	registration := bootstrap.InitialSourceRegistration{InstallationID: installation, DeploymentID: deployment, Environment: "production", ClusterID: cluster, Cell: oci.RegionGRU, Generation: 1, PlanSHA256: strings.Repeat("a", 64), SeedSlot: slots[0], ControllerSlots: slots, StorageDomain: domain, LedgerRecordDomains: bootstrap.BootstrapLedgerCapabilityDomains()}
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: 1, DeploymentID: deployment, Environment: "production", ClusterID: cluster, Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, FoundationScope: &home, InitialSourceRegistration: &registration, ControllerSlots: slots, InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: hex.EncodeToString(intentHash[:]), InitialRegionIntentWire: intentWire}
	signedAnchor, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyBootstrapAnchor(signedAnchor, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&objects.BaseClient, endpoint)
	reader, err := region.NewSignedFootprint(objects, verified, roots, grant.TenancyID)
	if err != nil {
		t.Fatal(err)
	}
	issuers, err := reader.OCIRIssuers(t.Context())
	if err != nil || len(issuers) != 3 {
		t.Fatalf("multi-repository sealed scopes=%+v err=%v", issuers, err)
	}
	proof, err := reader.OCIRIssuer(t.Context(), "sa-saopaulo-1.ocir.io/ns/terrascale/terrabase")
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// Redirect only the fixture transport, after the real SDK has signed and the
// production dispatcher has checkpointed its original canonical OCI request.
type ocirJournalRedirect struct{ destination *url.URL }

func (d ocirJournalRedirect) Do(request *http.Request) (*http.Response, error) {
	copied := request.Clone(request.Context())
	copied.URL = request.URL.Clone()
	copied.URL.Scheme, copied.URL.Host = d.destination.Scheme, d.destination.Host
	copied.Host = d.destination.Host
	return http.DefaultClient.Do(copied)
}
