package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type issuerProtocol struct {
	mu                              sync.Mutex
	grant                           []byte
	user, group, policy, membership map[string]any
	tokens                          map[string]map[string]any
	replays                         map[string]string
	secret                          string
	version                         int64
	created, revoked                int
	lostToken, lostVault            bool
	blockToken                      chan struct{}
	repository                      string
	t                               *testing.T
}

func (s *issuerProtocol) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	w.Header().Set("etag", fmt.Sprint(s.version))
	write := func(value any) {
		wire, err := json.Marshal(value)
		if err != nil {
			s.t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Write(wire)
	}
	fail := func(status int) {
		w.WriteHeader(status)
		write(map[string]string{"code": "Unavailable", "message": "private response withheld"})
	}
	read := func() map[string]any {
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			s.t.Error(err)
		}
		return body
	}
	path := r.URL.Path
	if strings.Contains(path, "/o/") {
		w.Write(s.grant)
		return
	}
	if strings.HasSuffix(path, "/container/repositories") {
		write(map[string]any{"items": []any{map[string]any{"id": s.repository, "displayName": "terrascale/terrabase", "compartmentId": "ocid1.compartment.oc1..control", "isPublic": false, "isImmutable": true, "lifecycleState": "AVAILABLE"}}, "remainingItemsCount": 0})
		return
	}
	if strings.Contains(path, "/container/repositories/") {
		write(map[string]any{"id": s.repository, "displayName": "terrascale/terrabase", "compartmentId": "ocid1.compartment.oc1..control", "isPublic": false, "isImmutable": true, "lifecycleState": "AVAILABLE"})
		return
	}
	if strings.Contains(path, "/authTokens") {
		if r.Method == "GET" {
			items := []any{}
			for _, token := range s.tokens {
				clone := map[string]any{}
				for k, v := range token {
					if k != "token" {
						clone[k] = v
					}
				}
				items = append(items, clone)
			}
			write(items)
			return
		}
		if r.Method == "DELETE" {
			_, id, _ := strings.Cut(path, "/authTokens/")
			delete(s.tokens, id)
			s.revoked++
			w.WriteHeader(204)
			return
		}
		if r.Method == "POST" {
			body := read()
			retry := r.Header.Get("opc-retry-token")
			if retry == "" {
				s.t.Error("token create missing durable retry identity")
			}
			id := s.replays[retry]
			if id == "" {
				s.created++
				id = fmt.Sprintf("ocid1.credential.oc1..token%d", s.created)
				s.replays[retry] = id
				s.tokens[id] = map[string]any{"id": id, "userId": "ocid1.user.oc1..pull", "description": body["description"], "token": fmt.Sprintf("private-issued-token-%d", s.created), "timeCreated": time.Now().UTC().Format(time.RFC3339Nano), "lifecycleState": "ACTIVE"}
			}
			if s.lostToken {
				s.lostToken = false
				fail(503)
				return
			}
			if s.blockToken != nil {
				started := s.blockToken
				s.blockToken = nil
				close(started)
				<-r.Context().Done()
				return
			}
			write(s.tokens[id])
			return
		}
	}
	if strings.HasSuffix(path, "/capabilities") {
		body := read()
		s.user["capabilities"] = body
		write(s.user)
		return
	}
	for _, part := range []struct {
		path, id string
		value    *map[string]any
	}{{"users", "ocid1.user.oc1..pull", &s.user}, {"groups", "ocid1.group.oc1..pull", &s.group}, {"policies", "ocid1.policy.oc1..pull", &s.policy}} {
		if strings.HasSuffix(path, "/"+part.path) && r.Method == "POST" {
			if *part.value != nil {
				fail(409)
				return
			}
			body := read()
			body["id"] = part.id
			body["lifecycleState"] = "ACTIVE"
			body["timeCreated"] = time.Now().UTC().Format(time.RFC3339Nano)
			body["isMfaActivated"] = false
			*part.value = body
			write(body)
			return
		}
		if strings.Contains(path, "/"+part.path+"/") && r.Method == "GET" {
			if *part.value == nil {
				fail(404)
				return
			}
			write(*part.value)
			return
		}
	}
	if strings.HasSuffix(path, "/userGroupMemberships") {
		if r.Method == "GET" {
			if s.membership == nil {
				write([]any{})
			} else {
				write([]any{s.membership})
			}
			return
		}
		body := read()
		body["id"] = "ocid1.groupmembership.oc1..pull"
		body["compartmentId"] = "ocid1.tenancy.oc1..t"
		body["timeCreated"] = time.Now().UTC().Format(time.RFC3339Nano)
		body["lifecycleState"] = "ACTIVE"
		s.membership = body
		write(body)
		return
	}
	if strings.HasSuffix(path, "/secretbundles/actions/getByName") {
		if s.secret == "" {
			fail(404)
			return
		}
		write(map[string]any{"secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull", "versionNumber": s.version, "secretBundleContent": map[string]any{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(s.secret))}})
		return
	}
	if strings.HasSuffix(path, "/secrets") {
		if r.Method == "GET" {
			items := []any{}
			if s.secret != "" {
				items = append(items, map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull", "secretName": "gru-orch-ocir-pull", "lifecycleState": "ACTIVE"})
			}
			write(items)
			return
		}
		body := read()
		content := body["secretContent"].(map[string]any)["content"].(string)
		value, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			s.t.Error(err)
		}
		s.secret = string(value)
		s.version = 1
		if s.lostVault {
			s.lostVault = false
			fail(503)
			return
		}
		write(map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull", "currentVersionNumber": s.version})
		return
	}
	if strings.Contains(path, "/secrets/") {
		if r.Method == "PUT" {
			if r.Header.Get("if-match") != fmt.Sprint(s.version) {
				fail(412)
				return
			}
			body := read()
			value, err := base64.StdEncoding.DecodeString(body["secretContent"].(map[string]any)["content"].(string))
			if err != nil {
				s.t.Error(err)
			}
			s.secret = string(value)
			s.version++
		}
		write(map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull", "vaultId": "ocid1.vault.oc1.sa-saopaulo-1.owned", "secretName": "gru-orch-ocir-pull", "lifecycleState": "ACTIVE", "currentVersionNumber": s.version})
		return
	}
	s.t.Errorf("unexpected issuer HTTP %s %s", r.Method, path)
	fail(400)
}

func issuerScope(t *testing.T, remote *issuerProtocol, factory *ociclient.Factory, endpoint string) region.VerifiedOCIRIssuer {
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

func setupIssuer(t *testing.T) (*Issuer, *issuerProtocol, *atomic.Bool) {
	t.Helper()
	controller, _, _, fenced := setup(t)
	remote := &issuerProtocol{tokens: map[string]map[string]any{}, replays: map[string]string{}, repository: "ocid1.containerrepo.oc1.sa-saopaulo-1.owned", t: t}
	factory, endpoint := ociresourcetest.Server(t, remote.serve)
	proof := issuerScope(t, remote, factory, endpoint)
	iam, err := factory.Identity()
	if err != nil {
		t.Fatal(err)
	}
	vault, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	vault.SetRegion(factory.Region())
	factory.Configure(&vault.BaseClient, ociclient.ServiceVault)
	secrets, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := factory.Artifacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*common.BaseClient{&iam.BaseClient, &vault.BaseClient, &secrets.BaseClient, &artifacts.BaseClient} {
		ociclient.PinHost(client, endpoint)
		client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
	}
	i := &Issuer{identity: iam, vault: vault, secrets: secrets, artifacts: artifacts, journal: controller.journal, scope: proof, guard: controller.guard, homeWrite: func(ctx context.Context) (context.Context, func(), error) { return ctx, func() {}, nil }, host: proof.Intent().RegistryHost}
	return i, remote, fenced
}

func TestIssuerSignedScopeIAMVaultAndRotationHTTP(t *testing.T) {
	i, remote, _ := setupIssuer(t)
	binding, err := i.Ensure(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if binding.RegistryHost != "sa-saopaulo-1.ocir.io" || binding.Repository != "ns/terrascale/terrabase" || binding.Ref.Name != "gru-orch-ocir-pull" {
		t.Fatalf("wrong owned binding: %+v", binding)
	}
	remote.mu.Lock()
	if remote.created != 1 || remote.version != 1 || !strings.Contains(remote.secret, "private-issued-token-1") {
		t.Fatal("automatic issuance did not reach Vault")
	}
	statement := remote.policy["statements"].([]any)
	if len(statement) != 1 || statement[0] != "Allow group id ocid1.group.oc1..pull to read repos in compartment id ocid1.compartment.oc1..control where target.repo.name = 'terrascale/terrabase'" {
		t.Fatal("policy escaped exact repository read scope")
	}
	remote.mu.Unlock()
	a, err := i.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entry, err := i.journal.Get(t.Context(), a.key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(entry.Value()), "private-issued") || strings.Contains(string(entry.Value()), "terrascale-pull@") {
		t.Fatal("issuer journal contains credentials or username")
	}
	a.state.PublishedAt = time.Now().Add(-tokenRotation - time.Hour)
	a.state.LeaseID = ""
	a.state.LeaseUntil = time.Time{}
	if err := a.save(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.created != 2 || remote.revoked != 1 || remote.version != 2 || len(remote.tokens) != 1 || !strings.Contains(remote.secret, "private-issued-token-2") {
		t.Fatal("rotation did not publish new Vault version before retiring old token")
	}
}

func TestIssuerLostTokenAndVaultResponsesRecoverWithoutBlindMint(t *testing.T) {
	for _, scenario := range []string{"token", "vault"} {
		t.Run(scenario, func(t *testing.T) {
			i, remote, _ := setupIssuer(t)
			remote.mu.Lock()
			remote.lostToken = scenario == "token"
			remote.lostVault = scenario == "vault"
			remote.mu.Unlock()
			_, firstErr := i.Ensure(t.Context())
			if scenario == "token" && firstErr == nil {
				t.Fatal("lost once-returned token incorrectly succeeded")
			}
			if _, err := i.Ensure(t.Context()); err != nil {
				t.Fatal(err)
			}
			remote.mu.Lock()
			defer remote.mu.Unlock()
			if scenario == "token" && (remote.created != 2 || remote.revoked != 1 || len(remote.tokens) != 1) {
				t.Fatal("unknown token was not revoked before fresh operation")
			}
			if scenario == "vault" && (remote.created != 1 || remote.revoked != 0 || remote.version != 1) {
				t.Fatal("lost Vault response generated another token")
			}
		})
	}
}

func TestIssuerAuthorityReplacementAndForeignIdentityBlock(t *testing.T) {
	i, remote, fenced := setupIssuer(t)
	if _, err := i.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	remote.mu.Lock()
	remote.repository = "ocid1.containerrepo.oc1.sa-saopaulo-1.replacement"
	remote.mu.Unlock()
	if _, err := i.Ensure(t.Context()); err == nil {
		t.Fatal("replacement physical repository accepted")
	}
	remote.mu.Lock()
	remote.repository = "ocid1.containerrepo.oc1.sa-saopaulo-1.owned"
	remote.policy["statements"] = []any{"Allow group id ocid1.group.oc1..pull to manage all-resources in tenancy"}
	remote.mu.Unlock()
	if _, err := i.Ensure(t.Context()); err == nil {
		t.Fatal("broadened IAM policy accepted")
	}
	fenced.Store(true)
	if _, err := i.Ensure(t.Context()); err == nil {
		t.Fatal("fenced issuer made progress")
	}
	if _, err := NewIssuer(t.Context(), nil, i.journal, region.VerifiedOCIRIssuer{}, i.guard, i.homeWrite); err == nil {
		t.Fatal("unverified issuer scope accepted")
	}
}

func TestIssuerConcurrentClaimAndSecretDebugBlock(t *testing.T) {
	i, remote, _ := setupIssuer(t)
	a, err := i.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Ensure(t.Context()); err == nil {
		t.Fatal("concurrent issuer bypassed durable lease")
	}
	a.state.LeaseID = ""
	a.state.LeaseUntil = time.Time{}
	if err := a.save(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCI_GO_SDK_DEBUG", "info")
	if _, err := i.Ensure(t.Context()); err == nil {
		t.Fatal("issuer allowed SDK secret logging")
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.created != 0 || remote.user != nil {
		t.Fatal("blocked issuer reached IAM")
	}
}

func TestIssuerHomeLeaseLossCancelsJoinedTokenHTTP(t *testing.T) {
	i, remote, _ := setupIssuer(t)
	started := make(chan struct{})
	remote.mu.Lock()
	remote.blockToken = started
	remote.mu.Unlock()
	var mu sync.Mutex
	var cancelLease context.CancelFunc
	i.homeWrite = func(ctx context.Context) (context.Context, func(), error) {
		leased, cancel := context.WithCancel(ctx)
		mu.Lock()
		cancelLease = cancel
		mu.Unlock()
		return leased, cancel, nil
	}
	done := make(chan error, 1)
	go func() { _, err := i.Ensure(t.Context()); done <- err }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("token request did not start")
	}
	mu.Lock()
	cancel := cancelLease
	mu.Unlock()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("lost home lease reported successful issuance")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lost home lease did not cancel and join SDK token request")
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.created != 1 || remote.secret != "" {
		t.Fatal("lost home lease published credentials or minted another token")
	}
}
