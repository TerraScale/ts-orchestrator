package byokauthority

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

type fakeKMS struct {
	context   map[string]string
	cipher    []byte
	plaintext []byte
}

func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.context = in.EncryptionContext
	f.plaintext = append([]byte(nil), in.Plaintext...)
	return &kms.EncryptOutput{CiphertextBlob: []byte("wrapped")}, nil
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
	if !bytes.Equal(fake.plaintext, make([]byte, 32)) {
		t.Fatalf("Wrap did not submit caller DEK: %q", fake.plaintext)
	}
	key, err := authority.Unwrap(t.Context(), binding, ciphertext)
	if err != nil || key == nil || string(key.Bytes()) != "01234567890123456789012345678901" {
		t.Fatalf("Unwrap() = %v, %v", key, err)
	}
	hostsecrets.ReleaseDataKey(key)
}

func TestAWSAuthorityRejectsAmbientOrInvalidConfiguration(t *testing.T) {
	config := Config{Region: "sa-east-1", RoleARN: "arn:aws:iam::123456789012:role/customer", KeyARN: "arn:aws:kms:sa-east-1:123456789012:key/id", SessionName: "session"}
	if validConfig(config) {
		t.Fatal("missing explicit OIDC token file accepted")
	}
	config.OIDCTokenFile = "/tmp/token"
	if _, err := New(t.Context(), config); err == nil {
		t.Fatal("unreadable explicit OIDC token file accepted")
	}
	if _, err := newWithClient(nil, "arn:aws:kms:sa-east-1:123456789012:key/id"); err == nil {
		t.Fatal("nil KMS client accepted")
	}
}

func TestAWSAuthorityEndpointValidation(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "https://kms.example.test", want: true},
		{value: "http://kms.example.test", want: false},
		{value: "https://user:kms@example.test", want: false},
		{value: "https://kms.example.test/?account=other", want: false},
	} {
		if got := validKMSEndpoint(test.value); got != test.want {
			t.Errorf("validKMSEndpoint(%q) = %t, want %t", test.value, got, test.want)
		}
	}
}

func TestKMSClientUsesConfiguredEndpoint(t *testing.T) {
	var requestHost string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost = r.Host
		http.Error(w, "test endpoint reached", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	base := awssdk.Config{
		Region:      "sa-east-1",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("access", "secret", ""),
	}
	client := newKMSClient(base, server.URL)
	_, err := client.Encrypt(t.Context(), &kms.EncryptInput{KeyId: awssdk.String("key"), Plaintext: []byte("plaintext")})
	if err == nil {
		t.Fatal("Encrypt unexpectedly succeeded against test endpoint")
	}
	if requestHost != server.Listener.Addr().String() {
		t.Fatalf("KMS request host = %q, want %q", requestHost, server.Listener.Addr().String())
	}
}
