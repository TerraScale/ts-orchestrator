package initialcontrol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

func TestPublicationRefusesGuardBeforeReadingCredentials(t *testing.T) {
	refused := errors.New("global term lost")
	_, err := publishPreliminaryAdmitted(t.Context(), initialgrant.Config{}, preliminarytransfer.VerifiedUpload{}, profiles{}, func(context.Context) error { return refused })
	if !errors.Is(err, refused) {
		t.Fatalf("guard refusal: %v", err)
	}
}

func TestPublicationPinsSignerBeforeOpeningConnections(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "membership.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreignDER, err := x509.MarshalPKIXPublicKey(&foreign.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := initialgrant.Config{Membership: initialgrant.Membership{SigningKeyFile: path}}
	// Connection configuration is intentionally absent: signer rejection must
	// precede even accessing credentials for NATS or OCI.
	upload := preliminarytransfer.VerifiedUpload{Scope: preliminarytransfer.VerifiedScope{Scope: preliminarytransfer.Scope{SourcePublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: foreignDER}))}}}
	_, err = publishPreliminaryAdmitted(t.Context(), cfg, upload, profiles{}, func(context.Context) error { return nil })
	if err == nil || err.Error() != "initial control: publication signer differs from admitted capture source" {
		t.Fatalf("foreign signer: %v", err)
	}
}
