package region

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestOriginalStartupRetentionUsesActualHomeSDKRule(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	beforeCreates, beforeLaunches, beforeMaterial := fixture.cloud.creates, fixture.cloud.launchPosts, fixture.cloud.materialPosts
	ruleID, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain)
	if err != nil || ruleID != "ledger-indefinite-locked" {
		t.Fatalf("actual locked HOME rule was not discovered: %q %v", ruleID, err)
	}
	for _, regional := range fixture.prepared.Grant.Regions {
		material := regional.BootstrapMaterial
		want, err := originalStartupAdmission(*material.OriginalSourceProducer, ruleID)
		if err != nil || !sameOriginalSourceValue(material.OriginalStartupAdmission, &want) || material.Startup.ControllerConfigDerivation != bootstrap.ControllerConfigDerivationV2 {
			t.Fatalf("%s lacks the exact signed startup purpose: %v", regional.Plan["cell"], err)
		}
	}
	if fixture.cloud.creates != beforeCreates || fixture.cloud.launchPosts != beforeLaunches || fixture.cloud.materialPosts != beforeMaterial {
		t.Fatal("retention discovery performed an effect")
	}
}

func TestOriginalStartupRetentionRejectsAmbiguousOrMutableRulesSDK(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	bucket := fixture.approval.HomeStorageDomain.LedgerBucket
	locked := func() map[string]any {
		return map[string]any{"id": "ledger-indefinite-locked", "displayName": "ledger-indefinite-locked", "etag": "ledger-rule-etag", "timeCreated": "2026-01-01T00:00:00Z", "timeModified": "2026-01-01T00:00:00Z", "timeRuleLocked": "2026-01-02T00:00:00Z"}
	}
	cases := map[string]func() []any{
		"absent":    func() []any { return nil },
		"ambiguous": func() []any { return []any{locked(), locked()} },
		"unlocked":  func() []any { rule := locked(); delete(rule, "timeRuleLocked"); return []any{rule} },
		"future lock": func() []any {
			rule := locked()
			rule["timeRuleLocked"] = time.Now().Add(time.Hour).Format(time.RFC3339)
			return []any{rule}
		},
		"finite duration": func() []any {
			rule := locked()
			rule["duration"] = map[string]any{"timeAmount": 365, "timeUnit": "DAYS"}
			return []any{rule}
		},
		"missing etag": func() []any { rule := locked(); rule["etag"] = ""; return []any{rule} },
		"path id":      func() []any { rule := locked(); rule["id"] = "foreign/rule"; return []any{rule} },
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			fixture.cloud.retention[bucket] = rules()
			beforeCreates, beforeLaunches, beforeMaterial := fixture.cloud.creates, fixture.cloud.launchPosts, fixture.cloud.materialPosts
			if id, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain); err == nil || id != "" {
				t.Fatalf("unsafe retention acquired startup purpose: %q %v", id, err)
			}
			if fixture.cloud.creates != beforeCreates || fixture.cloud.launchPosts != beforeLaunches || fixture.cloud.materialPosts != beforeMaterial {
				t.Fatal("rejected retention performed an effect")
			}
		})
	}
}

func TestOriginalStartupAdmissionRejectsPartialAndChangedPurpose(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	factory := fixture.factoryFor()
	preparedWire, err := json.Marshal(fixture.prepared)
	if err != nil {
		t.Fatal(err)
	}
	before := originalMaterialIAMSnapshot(t, fixture.cloud)
	requests, creates, launches, material := fixture.cloud.requests, fixture.cloud.creates, fixture.cloud.launchPosts, fixture.cloud.materialPosts
	assertNoEffects := func(t *testing.T) {
		t.Helper()
		if !bytes.Equal(before, originalMaterialIAMSnapshot(t, fixture.cloud)) || fixture.cloud.requests != requests || fixture.cloud.creates != creates || fixture.cloud.launchPosts != launches || fixture.cloud.materialPosts != material || fixture.cloud.hasAnchor() {
			t.Fatal("startup purpose authorization changed SDK requests, durable history or effects")
		}
	}
	bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
	if err := VerifyFoundationProvisionBundle(t.Context(), fixture.roots, bundle); err != nil {
		t.Fatal("unchanged signed startup purpose missed the authenticated boundary", err)
	}
	assertNoEffects(t)
	for _, test := range []struct {
		name   string
		mutate func(*FoundationPreparation)
	}{
		{"purpose", func(prepared *FoundationPreparation) {
			prepared.Grant.Regions[0].BootstrapMaterial.OriginalStartupAdmission.Purpose = ""
		}},
		{"producer digest", func(prepared *FoundationPreparation) {
			prepared.Grant.Regions[0].BootstrapMaterial.OriginalStartupAdmission.ProducerIntentSHA256 = strings.Repeat("a", 64)
		}},
		{"different retention rule", func(prepared *FoundationPreparation) {
			prepared.Grant.Regions[0].BootstrapMaterial.OriginalStartupAdmission.LedgerRetentionRuleID = "foreign-rule"
		}},
		{"partial purpose", func(prepared *FoundationPreparation) {
			prepared.Grant.Regions[0].BootstrapMaterial.OriginalStartupAdmission = nil
		}},
		{"v3 without startup purposes", func(prepared *FoundationPreparation) {
			for index := range prepared.Grant.Regions {
				prepared.Grant.Regions[index].BootstrapMaterial.OriginalStartupAdmission = nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var prepared FoundationPreparation
			if err := json.Unmarshal(preparedWire, &prepared, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			test.mutate(&prepared)
			changed := signProvisionFoundation(t, prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
			if err := VerifyFoundationProvisionBundle(t.Context(), fixture.roots, changed); !errors.Is(err, ErrOriginalSourceProducerHold) {
				t.Fatal("changed signed startup purpose missed its authenticated refusal", err)
			}
			if err := ProvisionFoundationBundle(t.Context(), factory, fixture.roots, changed); !errors.Is(err, ErrOriginalSourceProducerHold) {
				t.Fatal("operator accepted changed signed startup purpose or lost the refusal reason", err)
			}
			assertNoEffects(t)
		})
	}
	t.Run("historical v2 absent startup purposes remain DATA", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		var prepared FoundationPreparation
		if err := json.Unmarshal(preparedWire, &prepared, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		for index := range prepared.Grant.Regions {
			prepared.Grant.Regions[index].BootstrapMaterial.OriginalStartupAdmission = nil
		}
		for index := range *prepared.Grant.OriginalMaterialPublicationIAM {
			recipe := &(*prepared.Grant.OriginalMaterialPublicationIAM)[index]
			recipe.Purpose = originalMaterialIAMPurposeV2
			recipe.LinkSecretNames, recipe.LinkObject, recipe.LinkEscrowSecretName, recipe.RuntimeJoinSecretName = [8]string{}, "", "", ""
		}
		historical := signProvisionFoundation(t, prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
		if err := VerifyFoundationProvisionBundle(t.Context(), fixture.roots, historical); err != nil {
			t.Fatal("historical absent startup purpose failed authenticated DATA verification", err)
		}
		assertNoEffects(t)
	})
}

func TestOriginalStartupRetentionPaginationAndReadbackSDK(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	bucket := fixture.approval.HomeStorageDomain.LedgerBucket
	rule := fixture.cloud.retention[bucket][0]
	fixture.cloud.retentionPages = map[string][]any{bucket + "|": {}, bucket + "|second": {rule}}
	fixture.cloud.retentionNextPages = map[string]string{bucket + "|": "second"}
	if id, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain); err != nil || id != "ledger-indefinite-locked" {
		t.Fatal("complete SDK pagination missed exact rule", id, err)
	}
	fixture.cloud.retentionNextPages[bucket+"|second"] = "second"
	if _, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain); err == nil {
		t.Fatal("repeated retention page accepted")
	}
	fixture.cloud.retentionPages[bucket+"|"] = []any{rule}
	fixture.cloud.retentionPages[bucket+"|second"] = []any{rule}
	delete(fixture.cloud.retentionNextPages, bucket+"|second")
	if _, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain); err == nil {
		t.Fatal("duplicate across retention pages accepted")
	}
	fixture.cloud.retentionPages, fixture.cloud.retentionNextPages = map[string][]any{}, map[string]string{}
	page := ""
	for i := range 33 {
		next := strings.Repeat("x", i+1)
		fixture.cloud.retentionNextPages[bucket+"|"+page] = next
		page = next
	}
	beforeReads := fixture.cloud.requests
	if _, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain); err == nil || fixture.cloud.requests-beforeReads != 32 {
		t.Fatal("retention traversal exceeded the fixed32page bound", err, fixture.cloud.requests-beforeReads)
	}
	fixture.cloud.retentionPages, fixture.cloud.retentionNextPages = nil, nil
	fixture.cloud.retentionDetails = map[string]map[string]any{"ledger-indefinite-locked": {"id": "ledger-indefinite-locked", "displayName": "changed", "etag": "changed-etag", "timeCreated": "2026-01-01T00:00:00Z", "timeModified": "2026-01-01T00:00:00Z", "timeRuleLocked": "2026-01-02T00:00:00Z"}}
	if _, err := discoverOriginalStartupRetention(t.Context(), fixture.factoryFor(), fixture.approval.HomeStorageDomain); err == nil {
		t.Fatal("retention exact GET body/ETag drift accepted")
	}
}

func TestOriginalStartupCompleteSignedGrantFitsBound(t *testing.T) {
	fixture := newFoundationProvisionFixture(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bundle := signProvisionFoundation(t, fixture.prepared, fixture.bundle.RootChainWire, fixture.root, fixture.now)
	if len(bundle.GrantWire) > 256<<10 || len(bundle.GrantWire) == 0 {
		t.Fatal("complete prospective signed grant exceeds fixed256KiB bound", len(bundle.GrantWire))
	}
	if err := VerifyFoundationProvisionBundle(t.Context(), fixture.roots, bundle); err != nil {
		t.Fatal("complete prospective grant failed actual authenticated bundle verification", err)
	}
}

func TestOriginalStartupActorCannotBypassRunningBinarySDK(t *testing.T) {
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	record := f.record(t)
	instance := originalActorID(record.OriginalFoundationCompartments.Regions[0].Actor)
	token := originalDeliveryToken(t, instance, f.approval.TenancyID, time.Now().Add(time.Hour).Unix())
	provider := originalDeliveryProvider{provisionProvider: f.provider, token: token, kind: common.InstancePrincipal}
	reads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Authorization"), "keyId=\""+token+"\"") {
			t.Error("startup actor escaped own-principal read-only SDK boundary")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reads++
		if r.Host == "objectstorage.sa-saopaulo-1.oraclecloud.com" && r.URL.Path == "/n" {
			json.MarshalWrite(w, f.approval.HomeStorageDomain.Namespace)
			return
		}
		f.serveHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	originalSourceActorTestTransport(t, server)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	before := originalMaterialIAMSnapshot(t, f.cloud)
	actor, err := readOriginalSourceActor(t.Context(), factory, instance, "GRU", digestSource(f.originalAdmissionReadsSDKFixture.reads.publicBundle), f.roots)
	// The signed fixture image is not the running test binary; no test-only root or binary seam admits it.
	if actor.IsVerified() || !errors.Is(err, bootstrapstart.ErrRunningBinaryMismatch) || reads < 10 {
		t.Fatalf("unqualified fixture binary reached startup: verified=%v reads=%d err=%v", actor.IsVerified(), reads, err)
	}
	if template, err := actor.OriginalStartupTemplate(t.Context()); err == nil || template.IsVerified() {
		t.Fatal("failed actual actor observation minted startup authority")
	}
	if string(before) != string(originalMaterialIAMSnapshot(t, f.cloud)) || f.cloud.hasAnchor() {
		t.Fatal("refused startup changed durable history or published ordinary foundation")
	}
}
