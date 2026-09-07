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

func TestPendingDrillWithOCIEmailPagerKeepsSchedulingAndResumes(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	messages := 0
	client, err := reaper.NewOCIMailAdapter(reaper.OCIMailConfig{
		Endpoint:      "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..test",
		Sender:        "sender@example.com", KeyID: "ocid1.tenancy.oc1..test/ocid1.user.oc1..test/aa:bb",
		PrivateKey:           privateKey,
		CheckEffectAuthority: func(ctx context.Context) error { return ctx.Err() },
		Transport: pagerTransport(func(*http.Request) (*http.Response, error) {
			messages++
			return nil, errors.New("unexpected restore notification")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	pager, err := NewOCIEmailPager(client, "operator@example.com")
	if err != nil {
		t.Fatal(err)
	}
	drill, backup, branches, journal, _ := drillFixture()
	drill.pager = pager
	scheduler := &fakeScheduler{}
	drill.scheduler = scheduler
	backup.restoreErrs = []error{ErrPending, nil, nil, ErrPending}
	if err := drill.Start(t.Context()); err != nil {
		t.Fatalf("pending startup prevented scheduling: %v", err)
	}
	if scheduler.callback == nil {
		t.Fatal("pending startup did not install the scheduled callback")
	}
	if err := scheduler.callback(t.Context(), drill.config.Now()); err != nil {
		t.Fatalf("pending scheduled retry returned a worker-stopping error: %v", err)
	}
	runID := runIDFor(drill.config.Now())
	run, found, err := journal.LoadRun(t.Context(), runID)
	if err != nil || !found || run.Status != RunRunning || !run.CompletedAt.IsZero() {
		t.Fatalf("pending run = %+v, found=%v, err=%v", run, found, err)
	}
	item, found, err := journal.LoadItem(t.Context(), runID+"/control")
	if err != nil || !found || item.Status != ItemRunning || item.BranchID == "" || !item.CompletedAt.IsZero() {
		t.Fatalf("pending item = %+v, found=%v, err=%v", item, found, err)
	}
	if len(branches.created) != 3 || len(branches.deleted) != 2 {
		t.Fatalf("pending branch ownership: created=%d deleted=%d", len(branches.created), len(branches.deleted))
	}
	restarted, err := New(backup, branches, journal, &fakeScheduler{}, pager, drill.config)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := restarted.Run(t.Context())
	if err != nil || completed.ID != runID || completed.Status != RunSucceeded || completed.CompletedAt.IsZero() {
		t.Fatalf("resumed run = %+v, err=%v", completed, err)
	}
	if len(backup.restores) != 5 || backup.restores[0] != backup.restores[3] || backup.restores[0] != backup.restores[4] {
		t.Fatalf("pending retries changed restore identity: %+v", backup.restores)
	}
	if len(branches.created) != 3 || len(branches.deleted) != 3 || messages != 0 {
		t.Fatalf("completed restore: created=%d deleted=%d notifications=%d", len(branches.created), len(branches.deleted), messages)
	}
}
