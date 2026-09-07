package keyrotation

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type capabilityFake struct {
	secret           vault.Secret
	content          string
	uncertain        bool
	creatingReads    int
	mutateBundle     func(*secrets.SecretBundle)
	creates, deletes int
}

func (f *capabilityFake) ListSecrets(context.Context, vault.ListSecretsRequest) (vault.ListSecretsResponse, error) {
	r := vault.ListSecretsResponse{}
	if f.secret.Id != nil {
		r.Items = []vault.SecretSummary{{Id: f.secret.Id, SecretName: f.secret.SecretName}}
	}
	return r, nil
}
func (f *capabilityFake) CreateSecret(_ context.Context, r vault.CreateSecretRequest) (vault.CreateSecretResponse, error) {
	f.creates++
	f.secret = vault.Secret{Id: new("ocid.secret.test"), CompartmentId: r.CompartmentId, VaultId: r.VaultId, KeyId: r.KeyId, SecretName: r.SecretName, FreeformTags: r.FreeformTags, LifecycleState: vault.SecretLifecycleStateActive}
	f.content = *r.SecretContent.(vault.Base64SecretContentDetails).Content
	if f.uncertain {
		return vault.CreateSecretResponse{}, errors.New("uncertain provider detail")
	}
	return vault.CreateSecretResponse{Secret: f.secret}, nil
}
func (f *capabilityFake) GetSecret(context.Context, vault.GetSecretRequest) (vault.GetSecretResponse, error) {
	s := f.secret
	if f.creatingReads > 0 {
		f.creatingReads--
		s.LifecycleState = vault.SecretLifecycleStateCreating
	}
	return vault.GetSecretResponse{Secret: s}, nil
}
func (f *capabilityFake) GetSecretBundle(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
	b := secrets.SecretBundle{SecretId: f.secret.Id, VersionNumber: new(int64(1)), SecretBundleContent: secrets.Base64SecretBundleContentDetails{Content: new(f.content)}}
	if f.mutateBundle != nil {
		f.mutateBundle(&b)
	}
	return secrets.GetSecretBundleResponse{SecretBundle: b}, nil
}
func (f *capabilityFake) ScheduleSecretDeletion(context.Context, vault.ScheduleSecretDeletionRequest) (vault.ScheduleSecretDeletionResponse, error) {
	f.deletes++
	f.secret.LifecycleState = vault.SecretLifecycleStatePendingDeletion
	return vault.ScheduleSecretDeletionResponse{}, nil
}
func capabilityFixture() (*OCICapabilityVault, *capabilityFake, security.CapabilityRequest) {
	f := &capabilityFake{}
	v := &OCICapabilityVault{&ociHMACVault{purpose: "ts-capability", config: ociHMACVaultConfig{CompartmentID: "compartment", VaultID: "vault", KeyID: "key", Authority: func(context.Context) error { return nil }}, management: f, bundles: f}}
	r := security.CapabilityRequest{OperationID: "operation", Generation: 9, Bucket: 4, NotBefore: time.Now().UTC(), IdempotencyKey: "create"}
	r.ExpiresAt = r.NotBefore.Add(24 * time.Hour)
	return v, f, r
}
func TestOCICapabilityRecoversUncertainCreateAfterRestart(t *testing.T) {
	v, f, r := capabilityFixture()
	f.uncertain = true
	first, e := v.Generate(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	restarted := &OCICapabilityVault{&ociHMACVault{purpose: "ts-capability", config: v.config, management: f, bundles: f}}
	second, e := restarted.Generate(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	if first.Reference != second.Reference || base64.StdEncoding.EncodeToString(first.Key) != base64.StdEncoding.EncodeToString(second.Key) || f.creates != 1 {
		t.Fatal("uncertain create was not recovered durably")
	}
	if e = v.Retire(t.Context(), first.Reference, "retire"); e != nil {
		t.Fatal(e)
	}
	if e = v.Retire(t.Context(), first.Reference, "retire"); e != nil || f.deletes != 1 {
		t.Fatal("deletion not idempotent", e)
	}
}
func TestOCICapabilityRejectsConflictingGenerationAndForeignVault(t *testing.T) {
	v, f, r := capabilityFixture()
	m, e := v.Generate(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Generation++
	if _, e = v.Generate(t.Context(), r); e == nil {
		t.Fatal("accepted conflicting generation")
	}
	f.secret.VaultId = new("foreign")
	if _, e = v.Fetch(t.Context(), m.Reference); e == nil {
		t.Fatal("accepted foreign vault")
	}
}
func TestOCICapabilityFencesCalls(t *testing.T) {
	v, f, r := capabilityFixture()
	v.config.Authority = func(context.Context) error { return errors.New("fenced") }
	if _, e := v.Generate(t.Context(), r); e == nil || f.creates != 0 {
		t.Fatal("create escaped fence")
	}
}
func TestOCIAuthorityDispatcherFencesAfterSDKSigning(t *testing.T) {
	calls := 0
	d := NewOCIAuthorityDispatcher("sa-saopaulo-1", func(context.Context) error { calls++; return errors.New("fenced") })
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://vaults.sa-saopaulo-1.oci.oraclecloud.com/20180608/secrets", nil)
	if _, e := d.Do(r); e == nil || calls != 1 {
		t.Fatal("dispatch escaped authority")
	}
	r.URL.Host = "attacker.invalid"
	if _, e := d.Do(r); e == nil || calls != 1 {
		t.Fatal("foreign host accepted")
	}
}

func TestOCICapabilityWaitsForCreatingSecret(t *testing.T) {
	v, f, r := capabilityFixture()
	f.creatingReads = 1
	if _, e := v.Generate(t.Context(), r); e != nil {
		t.Fatal(e)
	}
	if f.creatingReads != 0 || f.creates != 1 {
		t.Fatal("create did not settle")
	}
}
func TestOCICapabilityWaitHonorsCancellation(t *testing.T) {
	v, f, r := capabilityFixture()
	f.creatingReads = 100
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if _, e := v.Generate(ctx, r); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("wait ignored cancellation", e)
	}
}
func TestOCICapabilityRejectsBundleMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*secrets.SecretBundle){
		"reference": func(b *secrets.SecretBundle) { b.SecretId = new("foreign") },
		"version":   func(b *secrets.SecretBundle) { b.VersionNumber = new(int64(2)) },
		"expiry":    func(b *secrets.SecretBundle) { b.TimeOfExpiry = new(common.SDKTime{Time: time.Now()}) },
		"deletion":  func(b *secrets.SecretBundle) { b.TimeOfDeletion = new(common.SDKTime{Time: time.Now().Add(time.Hour)}) },
		"oversized": func(b *secrets.SecretBundle) {
			b.SecretBundleContent = secrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(make([]byte, 33)))}
		}} {
		t.Run(name, func(t *testing.T) {
			v, f, r := capabilityFixture()
			f.mutateBundle = mutate
			if _, e := v.Generate(t.Context(), r); e == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}

func TestOCIAuthorityCallCancellationRetainsGateUntilExit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := ociAuthorityCall(ctx, func() (int, error) { close(started); <-release; return 1, nil })
		done <- e
	}()
	<-started
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked caller")
	}
	second, cancelSecond := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancelSecond()
	_, e := ociAuthorityCall(second, func() (int, error) { t.Error("SDK gate released early"); return 0, nil })
	close(release)
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("gate did not bound pending worker", e)
	}
}
