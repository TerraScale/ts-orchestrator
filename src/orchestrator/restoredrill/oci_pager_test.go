package restoredrill

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/reaper"
)

type pagerTransport func(*http.Request) (*http.Response, error)

func (f pagerTransport) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestOCIEmailPagerContainsOnlyRunMetadata(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	client, err := reaper.NewOCIMailAdapter(reaper.OCIMailConfig{
		Endpoint:      "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..test",
		Sender:        "sender@example.com", KeyID: "ocid1.tenancy.oc1..test/ocid1.user.oc1..test/aa:bb",
		PrivateKey:           privateKey,
		CheckEffectAuthority: func(ctx context.Context) error { return ctx.Err() },
		Transport: pagerTransport(func(request *http.Request) (*http.Response, error) {
			encoded, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			body = string(encoded)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"messageId":"message","envelopeId":"envelope","suppressedRecipients":[]}`))}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	pager, err := NewOCIEmailPager(client, "operator@example.com")
	if err != nil {
		t.Fatal(err)
	}
	page := Page{RunID: "drill-2026-09-05", Reason: "secret provider reason", Outcome: RunRecord{ID: "drill-2026-09-05", Status: RunFailed, DatabaseIDs: []string{"secret-database"}, Error: "secret error"}}
	if err := pager.Page(t.Context(), page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, page.RunID) || !strings.Contains(body, "operator@example.com") || strings.Contains(body, "secret") {
		t.Fatalf("unexpected email payload: %s", body)
	}
	body = ""
	page.Outcome.ID = "another-run"
	if err := pager.Page(t.Context(), page); !errors.Is(err, ErrInvalidRestoreRequest) || body != "" {
		t.Fatalf("mismatched run was dispatched: %v", err)
	}
}

func TestOCIEmailPagerRejectsMissingDependencies(t *testing.T) {
	if _, err := NewOCIEmailPager(nil, "operator@example.com"); !errors.Is(err, ErrProductionDependency) {
		t.Fatal(err)
	}
	if _, err := NewOCIEmailPager(&reaper.OCIMailAdapter{}, "Operator <operator@example.com>"); !errors.Is(err, ErrProductionDependency) {
		t.Fatal(err)
	}
}
