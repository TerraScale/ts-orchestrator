package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

var certTestNow = time.Unix(1_800_000_000, 0)

func testCertRegion() estate.Region {
	region := testNetworkRegion()
	region.Certificates = []estate.Certificate{{
		Name: "member-control", Purpose: "member-control",
		DNSNames:         []string{"gru.api.terrascale.tech"},
		RenewBeforeHours: 720,
	}}
	return region
}

func certTestDisplay() string { return CertDisplayName("gru", "member-control") }

// fakeCertGateway models issuance, renewal versions, and expiry.
type fakeCertGateway struct {
	certs   map[string]ObservedCert
	creates []string
	renews  []string
	now     time.Time
}

func (f *fakeCertGateway) ListCertificates(ctx context.Context) ([]ObservedCert, error) {
	certs := make([]ObservedCert, 0, len(f.certs))
	for _, cert := range f.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (f *fakeCertGateway) CreateCertificate(ctx context.Context, displayName string, dnsNames []string) (ObservedCert, error) {
	f.creates = append(f.creates, displayName)
	cert := ObservedCert{
		ID: "ocid1.certificate.oc1.x", DisplayName: displayName, LifecycleState: "ACTIVE",
		DNSNames: append([]string(nil), dnsNames...), ExpiresAtUnix: f.now.AddDate(0, 0, certificateValidityDays).Unix(),
	}
	if f.certs == nil {
		f.certs = map[string]ObservedCert{}
	}
	f.certs[displayName] = cert
	return cert, nil
}

func (f *fakeCertGateway) RenewCertificate(ctx context.Context, certID string, dnsNames []string) (ObservedCert, error) {
	f.renews = append(f.renews, certID)
	for name, cert := range f.certs {
		if cert.ID == certID {
			cert.DNSNames = append([]string(nil), dnsNames...)
			cert.LifecycleState = "ACTIVE"
			cert.ExpiresAtUnix = f.now.AddDate(0, 0, certificateValidityDays).Unix()
			f.certs[name] = cert
			return cert, nil
		}
	}
	return ObservedCert{}, &provider.InvalidDataError{Message: "certificate is unknown"}
}

func certTestReconciler(gateway *fakeCertGateway) *CertReconciler {
	return &CertReconciler{Gateway: gateway, Now: func() time.Time { return certTestNow }}
}

func TestCertReconcilePlans(t *testing.T) {
	declared := testCertRegion()
	farExpiry := certTestNow.AddDate(0, 0, certificateValidityDays).Unix()
	cases := []struct {
		name        string
		observed    CertsObserved
		wantKinds   []OCIActionKind
		wantReasons []RenewReason
		wantErr     bool
	}{
		{
			name:      "missing certificate plans creation",
			observed:  CertsObserved{},
			wantKinds: []OCIActionKind{OCIActionCreateCertificate},
		},
		{
			name: "matching certificate far from expiry plans nothing",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(),
				LifecycleState: "ACTIVE", DNSNames: []string{"gru.api.terrascale.tech"}, ExpiresAtUnix: farExpiry,
			}}},
			wantKinds: nil,
		},
		{
			name: "issuance in flight plans nothing",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "CREATING",
			}}},
			wantKinds: nil,
		},
		{
			name: "renewal in flight plans nothing",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "UPDATING",
				DNSNames: []string{"gru.api.terrascale.tech"}, ExpiresAtUnix: certTestNow.Add(time.Hour).Unix(),
			}}},
			wantKinds: nil,
		},
		{
			name: "widened SAN set plans renewal",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE",
				DNSNames: []string{"gru.api.terrascale.tech", "evil.terrascale.tech"}, ExpiresAtUnix: farExpiry,
			}}},
			wantKinds:   []OCIActionKind{OCIActionRenewCertificate},
			wantReasons: []RenewReason{RenewReasonDrift},
		},
		{
			name: "narrowed SAN set plans renewal",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(),
				LifecycleState: "ACTIVE", ExpiresAtUnix: farExpiry,
			}}},
			wantKinds:   []OCIActionKind{OCIActionRenewCertificate},
			wantReasons: []RenewReason{RenewReasonDrift},
		},
		{
			name: "expiry inside the renewal window plans renewal",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE",
				DNSNames: []string{"gru.api.terrascale.tech"}, ExpiresAtUnix: certTestNow.Add(24 * time.Hour).Unix(),
			}}},
			wantKinds:   []OCIActionKind{OCIActionRenewCertificate},
			wantReasons: []RenewReason{RenewReasonWindow},
		},
		{
			name: "expired certificate plans expiry-repair renewal",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE",
				DNSNames: []string{"gru.api.terrascale.tech"}, ExpiresAtUnix: certTestNow.Add(-time.Hour).Unix(),
			}}},
			wantKinds:   []OCIActionKind{OCIActionRenewCertificate},
			wantReasons: []RenewReason{RenewReasonExpired},
		},
		{
			name: "failed issuance is refused",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "FAILED",
			}}},
			wantErr: true,
		},
		{
			name: "unknown lifecycle is refused",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "SUSPENDED",
			}}},
			wantErr: true,
		},
		{
			name: "missing expiry evidence is refused",
			observed: CertsObserved{Certs: []ObservedCert{{
				ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(),
				LifecycleState: "ACTIVE", DNSNames: []string{"gru.api.terrascale.tech"},
			}}},
			wantErr: true,
		},
		{
			name: "duplicate display names are refused",
			observed: CertsObserved{Certs: []ObservedCert{
				{ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE"},
				{ID: "ocid1.certificate.oc1.y", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE"},
			}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := certTestReconciler(&fakeCertGateway{now: certTestNow})
			plan, err := reconciler.Reconcile(context.Background(), declared, tc.observed)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Reconcile() accepted invalid state")
				}
				return
			}
			if err != nil {
				t.Fatalf("Reconcile() failed: %v", err)
			}
			got := plan.Kinds()
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
			}
			for i := range got {
				if got[i] != tc.wantKinds[i] {
					t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
				}
			}
			renews := 0
			for _, action := range plan.Actions {
				if renew, ok := action.(RenewCertificateAction); ok {
					if tc.wantReasons == nil || renew.Reason != tc.wantReasons[renews] {
						t.Fatalf("renewal reason = %q, want %v", renew.Reason, tc.wantReasons)
					}
					if !strings.Contains(renew.Summary(), string(renew.Reason)) {
						t.Fatalf("summary %q does not carry the renewal reason", renew.Summary())
					}
					renews++
				}
			}
			if renews != len(tc.wantReasons) {
				t.Fatalf("renewals = %d, want %d", renews, len(tc.wantReasons))
			}
		})
	}
}

func TestCertReconcileRejectsDeclarationWithoutWindow(t *testing.T) {
	declared := testCertRegion()
	declared.Certificates[0].RenewBeforeHours = 0
	reconciler := certTestReconciler(&fakeCertGateway{now: certTestNow})
	if _, err := reconciler.Reconcile(context.Background(), declared, CertsObserved{}); err == nil {
		t.Fatal("certificate without a renewal window accepted")
	}
	declared.Certificates[0].RenewBeforeHours = 720
	declared.Certificates[0].DNSNames = []string{"not a hostname!!"}
	if _, err := reconciler.Reconcile(context.Background(), declared, CertsObserved{}); err == nil {
		t.Fatal("certificate with an invalid DNS name accepted")
	}
}

func TestCertReconcileRejectsAmbiguousHostnameCoverage(t *testing.T) {
	declared := testCertRegion()
	declared.Certificates = append(declared.Certificates, estate.Certificate{
		Name: "member-control-extra", Purpose: "member-control",
		DNSNames:         []string{"gru.api.terrascale.tech", "alt.gru.internal"},
		RenewBeforeHours: 720,
	})
	reconciler := certTestReconciler(&fakeCertGateway{now: certTestNow})
	if _, err := reconciler.Reconcile(context.Background(), declared, CertsObserved{}); err == nil {
		t.Fatal("two declared certificates covering one hostname accepted")
	}
}

func TestCertApplyConvergesIdempotently(t *testing.T) {
	declared := testCertRegion()
	gateway := &fakeCertGateway{now: certTestNow}
	reconciler := certTestReconciler(gateway)
	ctx := context.Background()
	for pass := 0; pass < 3; pass++ {
		observed, err := reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("observe failed: %v", err)
		}
		plan, err := reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}
		if plan.Empty() {
			cert := gateway.certs[certTestDisplay()]
			if cert.LifecycleState != "ACTIVE" || !sameCertDNSNames(cert.DNSNames, []string{"gru.api.terrascale.tech"}) {
				t.Fatalf("certificate state = %+v, want active with declared SANs", cert)
			}
			if len(gateway.creates) != 1 || len(gateway.renews) != 0 {
				t.Fatalf("creates = %v, renews = %v, want exactly one create", gateway.creates, gateway.renews)
			}
			return
		}
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
	}
	t.Fatal("certificates did not converge in three passes")
}

func TestCertRenewalConvergesOnExpiry(t *testing.T) {
	declared := testCertRegion()
	gateway := &fakeCertGateway{now: certTestNow, certs: map[string]ObservedCert{
		certTestDisplay(): {
			ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE",
			DNSNames: []string{"gru.api.terrascale.tech"}, ExpiresAtUnix: certTestNow.Add(time.Hour).Unix(),
		},
	}}
	reconciler := certTestReconciler(gateway)
	ctx := context.Background()
	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil || len(plan.Actions) != 1 || plan.Actions[0].Kind() != OCIActionRenewCertificate {
		t.Fatalf("renewal plan = %+v, %v", plan, err)
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
		t.Fatalf("renew apply failed: %v", err)
	}
	observed, err = reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = reconciler.Reconcile(ctx, declared, observed)
	if err != nil || !plan.Empty() {
		t.Fatalf("post-renewal plan = %+v, %v; want converged", plan, err)
	}
	if len(gateway.renews) != 1 {
		t.Fatalf("renews = %v, want exactly one", gateway.renews)
	}
}

func TestCertApplyRejectsForeignAndStalePlans(t *testing.T) {
	declared := testCertRegion()
	gateway := &fakeCertGateway{now: certTestNow}
	reconciler := certTestReconciler(gateway)
	ctx := context.Background()
	if err := reconciler.Apply(ctx, declared, CertsObserved{}, OCIPlan{Actions: []OCIAction{CreateBucketAction{}}}); err == nil {
		t.Fatal("foreign action accepted")
	}
	stale := OCIPlan{Actions: []OCIAction{CreateCertificateAction{Name: "other", DisplayName: "terrascale-gru-other"}}}
	if err := reconciler.Apply(ctx, declared, CertsObserved{}, stale); err == nil {
		t.Fatal("misderived display name accepted")
	}
	if err := reconciler.Apply(ctx, declared, CertsObserved{Certs: []ObservedCert{{
		ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE",
	}}}, OCIPlan{Actions: []OCIAction{CreateCertificateAction{Name: "member-control", DisplayName: certTestDisplay(), DNSNames: []string{"gru.api.terrascale.tech"}}}}); err == nil {
		t.Fatal("stale create over an existing certificate accepted")
	}
	renew := OCIPlan{Actions: []OCIAction{RenewCertificateAction{CertID: "ocid1.certificate.oc1.gone", DisplayName: certTestDisplay(), DNSNames: []string{"gru.api.terrascale.tech"}}}}
	if err := reconciler.Apply(ctx, declared, CertsObserved{}, renew); err == nil {
		t.Fatal("renew of a vanished certificate accepted")
	}
	unreasoned := OCIPlan{Actions: []OCIAction{RenewCertificateAction{CertID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), DNSNames: []string{"gru.api.terrascale.tech"}}}}
	if err := reconciler.Apply(ctx, declared, CertsObserved{Certs: []ObservedCert{{
		ID: "ocid1.certificate.oc1.x", DisplayName: certTestDisplay(), LifecycleState: "ACTIVE",
	}}}, unreasoned); err == nil {
		t.Fatal("renewal without a reason accepted")
	}
}

func TestCertDisplayNameIsRegionQualified(t *testing.T) {
	if got := CertDisplayName("gru", "member-control"); got != "terrascale-gru-member-control" {
		t.Fatalf("CertDisplayName() = %q", got)
	}
	if CertDisplayName("gru", "member-control") == CertDisplayName("sfo", "member-control") {
		t.Fatal("certificate display names collide across regions sharing a compartment")
	}
}

func certTestGateway(t *testing.T, roundTrip roundTripFunc) *OCICertificatesGateway {
	t.Helper()
	gateway, err := NewOCICertificatesGateway(
		testOCITransport(t, provider.OCIServiceCertificates, roundTrip),
		"ocid1.compartment.oc1.x", "ocid1.certificateauthority.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func TestOCICertificatesGatewayRejectsScope(t *testing.T) {
	if _, err := NewOCICertificatesGateway(nil, "ocid1.compartment.oc1.x", "ocid1.certificateauthority.oc1.x"); err == nil {
		t.Fatal("nil transport accepted")
	}
	core := testOCITransport(t, provider.OCIServiceCore, func(*http.Request) (*http.Response, error) { return testHTTPResponse(http.StatusOK, `{}`, nil), nil })
	if _, err := NewOCICertificatesGateway(core, "ocid1.compartment.oc1.x", "ocid1.certificateauthority.oc1.x"); err == nil {
		t.Fatal("core transport accepted for certificates")
	}
	certs := testOCITransport(t, provider.OCIServiceCertificates, func(*http.Request) (*http.Response, error) { return testHTTPResponse(http.StatusOK, `{}`, nil), nil })
	if _, err := NewOCICertificatesGateway(certs, "not-an-ocid", "ocid1.certificateauthority.oc1.x"); err == nil {
		t.Fatal("invalid compartment accepted")
	}
	if _, err := NewOCICertificatesGateway(certs, "ocid1.compartment.oc1.x", "ocid1.certificate.oc1.x"); err == nil {
		t.Fatal("certificate identity accepted as issuing authority")
	}
}

func TestOCICertificatesGatewayListsWithVersionEvidence(t *testing.T) {
	expiry := certTestNow.AddDate(0, 0, certificateValidityDays).Format(time.RFC3339)
	gateway := certTestGateway(t, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/20210224/certificates/") {
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.certificate.oc1.x","name":"`+certTestDisplay()+`","lifecycleState":"ACTIVE",`+
				`"currentVersion":{"subjectAlternativeNames":[{"type":"DNS","value":"gru.api.terrascale.tech"}],`+
				`"validity":{"timeOfValidityNotBefore":"2027-01-15T08:00:00Z","timeOfValidityNotAfter":"`+expiry+`"}}}`,
				nil), nil
		}
		if request.Method == http.MethodGet && request.URL.Path == "/20210224/certificates" {
			if request.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1.x" {
				t.Fatalf("list scope = %q", request.URL.RawQuery)
			}
			return testHTTPResponse(http.StatusOK, `{"items":[{"id":"ocid1.certificate.oc1.x","name":"`+certTestDisplay()+`","lifecycleState":"ACTIVE"}]}`, nil), nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		return nil, nil
	})
	certs, err := gateway.ListCertificates(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("ListCertificates = %+v, %v", certs, err)
	}
	if certs[0].DisplayName != certTestDisplay() || !sameCertDNSNames(certs[0].DNSNames, []string{"gru.api.terrascale.tech"}) {
		t.Fatalf("observed = %+v", certs[0])
	}
	if certs[0].ExpiresAtUnix != certTestNow.AddDate(0, 0, certificateValidityDays).Unix() {
		t.Fatalf("expiry = %d", certs[0].ExpiresAtUnix)
	}
}

func TestOCICertificatesGatewayCreateAndRenewContracts(t *testing.T) {
	var bodies []map[string]any
	gateway := certTestGateway(t, func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.certificate.oc1.x","name":"`+certTestDisplay()+`","lifecycleState":"CREATING"}`,
			nil), nil
	})
	ctx := context.Background()
	if _, err := gateway.CreateCertificate(ctx, certTestDisplay(), []string{"gru.api.terrascale.tech"}); err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	created := bodies[0]
	if created["certificateConfigType"] != "ISSUED_BY_INTERNAL_CA" || created["name"] != certTestDisplay() ||
		created["issuerCertificateAuthorityId"] != "ocid1.certificateauthority.oc1.x" || created["compartmentId"] != "ocid1.compartment.oc1.x" {
		t.Fatalf("create identity = %+v", created)
	}
	sans := created["subjectAlternativeNames"].([]any)
	first := sans[0].(map[string]any)
	if first["type"] != "DNS" || first["value"] != "gru.api.terrascale.tech" {
		t.Fatalf("create SANs = %+v", sans)
	}
	if created["subject"].(map[string]any)["commonName"] != "gru.api.terrascale.tech" {
		t.Fatalf("create subject = %+v", created["subject"])
	}
	if _, err := gateway.RenewCertificate(ctx, "ocid1.certificate.oc1.x", []string{"gru.api.terrascale.tech"}); err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}
	renewed := bodies[1]
	validity := renewed["validity"].(map[string]any)
	if renewed["certificateConfigType"] != "ISSUED_BY_INTERNAL_CA" || validity["timeOfValidityNotAfter"] == nil || validity["timeOfValidityNotBefore"] == nil {
		t.Fatalf("renew validity = %+v", renewed)
	}
	if _, err := gateway.CreateCertificate(ctx, certTestDisplay(), []string{"not a hostname!!"}); err == nil {
		t.Fatal("invalid SAN accepted")
	}
	if _, err := gateway.RenewCertificate(ctx, "ocid1.instance.oc1.x", []string{"gru.api.terrascale.tech"}); err == nil {
		t.Fatal("non-certificate identity accepted for renew")
	}
}
