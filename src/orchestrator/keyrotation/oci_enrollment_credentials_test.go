package keyrotation

import (
	"context"
	"errors"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/vault"
)

type enrollmentVaultFake struct{ capabilityFake }

func (f *enrollmentVaultFake) CreateSecret(ctx context.Context, r vault.CreateSecretRequest) (vault.CreateSecretResponse, error) {
	_, err := f.capabilityFake.CreateSecret(ctx, r)
	f.secret.Id = new("ocid1.vaultsecret.oc1.sa-saopaulo-1.enrollment")
	return vault.CreateSecretResponse{Secret: f.secret}, err
}

func TestOCIEnrollmentCredentialRecoversExactVersionAfterUnknownCreate(t *testing.T) {
	fake := &enrollmentVaultFake{capabilityFake: capabilityFake{uncertain: true}}
	configuration := OCICapabilityVaultConfig{Region: "sa-saopaulo-1", CompartmentID: "compartment", VaultID: "vault", KeyID: "key", Authority: func(context.Context) error { return nil }}
	create := func() *OCICapabilityVault {
		return &OCICapabilityVault{config: configuration, management: fake, bundles: fake}
	}
	request := EnrollmentCredentialRequest{OperationID: "enroll-gru-3", Destination: "/etc/terrascale/placement/host.nkey", Content: []byte("private-credential-canary")}
	first, err := create().PublishEnrollmentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := create().PublishEnrollmentCredential(t.Context(), request)
	if err != nil || first != second || fake.creates != 1 {
		t.Fatalf("resumed credential: first=%+v second=%+v creates=%d err=%v", first, second, fake.creates, err)
	}
	request.Content = []byte("different-private-credential")
	if _, err := create().PublishEnrollmentCredential(t.Context(), request); err == nil || fake.creates != 1 {
		t.Fatal("changed credential retried under original operation")
	}
	request.Destination = "/etc/shadow"
	if _, err := create().PublishEnrollmentCredential(t.Context(), request); err == nil || fake.creates != 1 {
		t.Fatal("unapproved destination reached provider")
	}
	configuration.Authority = func(context.Context) error { return errors.New("lease fenced") }
	request.Destination = "/etc/terrascale/placement/host.nkey"
	if _, err := create().PublishEnrollmentCredential(t.Context(), request); err == nil || fake.creates != 1 {
		t.Fatal("fenced credential publication")
	}
}
