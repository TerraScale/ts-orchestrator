package app

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// newAcceptedSpecTrust supplies accepted image roots while retaining real signature checks.
func newAcceptedSpecTrust(t *testing.T, cfg *Config) {
	t.Helper()
	accepted := bootstrapstart.AcceptedIdentity{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Cell: cfg.NATS.Cell, Environment: "test"}
	roots := testSpecRoots(t)
	if spec := cfg.Controller.SpecTrust; spec != nil {
		accepted.DeploymentID, accepted.Environment = spec.DeploymentID, spec.Environment
		wire, err := os.ReadFile(spec.RootPublicKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(wire)
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Fatal("spec trust root is not a PEM public key")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		public, ok := key.(ed25519.PublicKey)
		if !ok {
			t.Fatal("spec trust root is not Ed25519")
		}
		roots, err = trust.ParseKeyring(public)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg.Controller.SpecTrust = nil
	previous := specAcceptedInputs
	specAcceptedInputs = func() (bootstrapstart.AcceptedIdentity, bootstrapstart.TrustInputs, error) {
		chain := trust.RootChain{Version: 1}
		identity := trust.ChainIdentity{DeploymentID: accepted.DeploymentID, Cell: accepted.Cell, Environment: accepted.Environment}
		verified, err := trust.VerifyRootChain(roots, identity, chain)
		return accepted, bootstrapstart.TrustInputs{ChainIdentity: identity, Genesis: roots, Chain: chain, Roots: verified}, err
	}
	t.Cleanup(func() { specAcceptedInputs = previous })
}
