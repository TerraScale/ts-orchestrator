package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testConfig() BootstrapConfig {
	c := DefaultBootstrapConfig()
	c.TenancyID = "tenancy-1"
	c.ImageID = "image-1"
	c.AvailabilityDomains = []string{"AD-1"}
	c.CloudInit = CloudInitConfig{ArtifactURL: "https://releases.example/ts-node", SignatureURL: "https://releases.example/ts-node.sig", SHA256: strings.Repeat("a", 64), SignaturePublicKey: strings.Repeat("ab", 32)}
	return c
}

func TestPlanBootstrapIsDeterministicAndSafe(t *testing.T) {
	a, err := PlanBootstrap(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	b, err := PlanBootstrap(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint || a.Validate() != nil {
		t.Fatalf("plans are not stable: %q %q", a.Fingerprint, b.Fingerprint)
	}
	if len(a.Steps) != 8 {
		t.Fatalf("steps = %d, want compartment, network, vault, buckets, and two hosts", len(a.Steps))
	}
	for _, step := range a.Steps {
		if step.Kind == ResourceHost {
			if len(step.Host.Candidates) != 2 || step.Host.Candidates[0].Shape != BootstrapPrimaryShape || step.Host.Candidates[1].Shape != BootstrapFallbackShape {
				t.Fatalf("host candidates = %#v", step.Host.Candidates)
			}
			if step.Host.CloudInit != "" {
				t.Fatal("retired greenfield renderer populated host cloud-init")
			}
		}
	}
}

func TestPlanBootstrapRejectsUntrustedArtifactInputs(t *testing.T) {
	for name, mutate := range map[string]func(*CloudInitConfig){
		"missing signature URL": func(c *CloudInitConfig) { c.SignatureURL = "" },
		"missing public key":    func(c *CloudInitConfig) { c.SignaturePublicKey = "" },
		"placeholder public key": func(c *CloudInitConfig) {
			c.SignaturePublicKey = "ed25519-public-key"
		},
		"wrong public key type": func(c *CloudInitConfig) {
			c.SignaturePublicKey = strings.Repeat("not-a-key", 4)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			mutate(&config.CloudInit)
			if _, err := PlanBootstrap(config); !errors.Is(err, ErrInvalidBootstrap) {
				t.Fatalf("plan error = %v, want ErrInvalidBootstrap", err)
			}
		})
	}
}

type testCredentialProvider struct{}

func (testCredentialProvider) Resolve(context.Context, CredentialRequest) (CredentialLease, error) {
	return CredentialLease{Token: "opaque", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type testJournal struct {
	records map[string]JournalRecord
	durable bool
}

func (j *testJournal) AuthoritativeDurable() bool { return j != nil && j.durable }
func (j *testJournal) Prepare(_ context.Context, id, fp string) (JournalRecord, error) {
	if j.records == nil {
		j.records = map[string]JournalRecord{}
	}
	if r := j.records[id]; r.Fingerprint != "" {
		if r.Fingerprint != fp {
			return JournalRecord{}, ErrFingerprintMismatch
		}
		return r, nil
	}
	r := JournalRecord{StepID: id, Fingerprint: fp, State: JournalPrepared}
	j.records[id] = r
	return r, nil
}
func (j *testJournal) MarkSubmitted(_ context.Context, id, fp string, n int) (JournalRecord, error) {
	r := j.records[id]
	r.Fingerprint = fp
	r.State = JournalSubmitted
	r.Attempts = n
	j.records[id] = r
	return r, nil
}
func (j *testJournal) MarkSucceeded(_ context.Context, id, fp string, receipt ResourceReceipt) (JournalRecord, error) {
	r := j.records[id]
	r.Fingerprint = fp
	r.State = JournalSucceeded
	r.Receipt = receipt
	j.records[id] = r
	return r, nil
}
func (j *testJournal) MarkFailed(_ context.Context, id, fp, reason string) (JournalRecord, error) {
	r := j.records[id]
	r.Fingerprint = fp
	r.State = JournalFailed
	r.Failure = reason
	j.records[id] = r
	return r, nil
}

type testProvider struct{ calls int }

func (p *testProvider) EnsureCompartment(context.Context, ProviderRequest) (ResourceReceipt, error) {
	p.calls++
	return ResourceReceipt{ID: "compartment"}, nil
}
func (p *testProvider) EnsureVCN(context.Context, ProviderRequest) (ResourceReceipt, error) {
	p.calls++
	return ResourceReceipt{ID: "vcn"}, nil
}
func (p *testProvider) EnsureNSG(context.Context, ProviderRequest) (ResourceReceipt, error) {
	p.calls++
	return ResourceReceipt{ID: "nsg"}, nil
}
func (p *testProvider) EnsureVault(context.Context, ProviderRequest) (ResourceReceipt, error) {
	p.calls++
	return ResourceReceipt{ID: "vault"}, nil
}
func (p *testProvider) EnsureBucket(context.Context, ProviderRequest) (ResourceReceipt, error) {
	p.calls++
	return ResourceReceipt{ID: "bucket"}, nil
}
func (p *testProvider) EnsureHost(context.Context, ProviderRequest) (ResourceReceipt, error) {
	p.calls++
	return ResourceReceipt{ID: "host"}, nil
}
func (p *testProvider) AcquirePlacement(context.Context, string, string) error { return nil }

func TestExecutorResumesIdempotently(t *testing.T) {
	p := &testProvider{}
	j := &testJournal{durable: true}
	e, err := NewExecutor(Providers{Compartment: p, Network: p, Vault: p, Bucket: p, Host: p, Placement: p}, j, testCredentialProvider{}, RetryPolicy{MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanBootstrap(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.Execute(context.Background(), plan, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Completed) != 8 || p.calls != 8 {
		t.Fatalf("first run completed=%d calls=%d", len(first.Completed), p.calls)
	}
	second, err := e.Execute(context.Background(), plan, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Skipped) != 8 || p.calls != 8 {
		t.Fatalf("second run skipped=%d calls=%d", len(second.Skipped), p.calls)
	}
}

func TestExecutorFailsClosedWithoutDurabilityOrCredentials(t *testing.T) {
	if _, err := NewExecutor(Providers{}, &testJournal{}, testCredentialProvider{}, RetryPolicy{MaxAttempts: 1}); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatalf("journal error=%v", err)
	}
	if _, err := NewExecutor(Providers{}, &testJournal{durable: true}, nil, RetryPolicy{MaxAttempts: 1}); !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("credential error=%v", err)
	}
}
