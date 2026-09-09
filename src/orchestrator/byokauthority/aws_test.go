package byokauthority

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

type fakeKMS struct {
	context map[string]string
	cipher  []byte
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	f.context = in.EncryptionContext
	return &kms.GenerateDataKeyOutput{Plaintext: []byte("01234567890123456789012345678901"), CiphertextBlob: []byte("wrapped")}, nil
}
func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if string(in.CiphertextBlob) != "wrapped" || in.EncryptionContext["terrascale.key_version"] != "version" {
		return nil, ErrUnavailable
	}
	return &kms.DecryptOutput{Plaintext: []byte("01234567890123456789012345678901")}, nil
}

func TestAWSAuthorityBindsEncryptionContextAndReturnsCiphertext(t *testing.T) {
	fake := new(fakeKMS)
	authority, err := newWithClient(fake, "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", KeyVersion: "version", Region: "sa-east-1", Purpose: "data"}
	ciphertext, err := authority.Wrap(t.Context(), binding, make([]byte, 32))
	if err != nil || ciphertext == "" {
		t.Fatalf("Wrap() = %q, %v", ciphertext, err)
	}
	if fake.context["terrascale.database_id"] != "database" || fake.context["terrascale.purpose"] != "data" {
		t.Fatalf("encryption context lost scope: %#v", fake.context)
	}
	key, err := authority.Unwrap(t.Context(), binding, ciphertext)
	if err != nil || key == nil || string(key.Bytes()) != "01234567890123456789012345678901" {
		t.Fatalf("Unwrap() = %v, %v", key, err)
	}
	hostsecrets.ReleaseDataKey(key)
}

func TestAWSAuthorityRejectsAmbientOrInvalidConfiguration(t *testing.T) {
	for _, config := range []Config{{Region: "sa-east-1", RoleARN: "arn:aws:iam::123456789012:role/customer", KeyARN: "arn:aws:kms:sa-east-1:123456789012:key/id", SessionName: "session"}, {Region: "sa-east-1", RoleARN: "arn:aws:iam::123456789012:role/customer", KeyARN: "arn:aws:kms:sa-east-1:123456789012:key/id", OIDCTokenFile: "/tmp/token", SessionName: "session"}} {
		if validConfig(config) {
			t.Fatalf("invalid explicit OIDC config accepted: %+v", config)
		}
	}
	if _, err := newWithClient(nil, "arn:aws:kms:sa-east-1:123456789012:key/id"); err == nil {
		t.Fatal("nil KMS client accepted")
	}
}
