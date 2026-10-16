//go:build linux

package swarmruntime

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
)

// SignRuntimeStop accepts only the concrete runtime's opaque stopped witness.
// Managers independently bind its signature to current task and journal state.
func (n *Node) SignRuntimeStop(ctx context.Context, observed execution.ObservedRuntimeStop) (executionwire.SignedRuntimeStop, error) {
	if err := ctx.Err(); err != nil {
		return executionwire.SignedRuntimeStop{}, err
	}
	payload, err := observed.Payload()
	if err != nil {
		return executionwire.SignedRuntimeStop{}, err
	}
	now := time.Now().UTC()
	if n == nil || n.upstream == nil || n.role != "container" || payload.NodeID != n.ID() || payload.InstanceID == "" ||
		payload.Challenge == "" || payload.Deadline.IsZero() || now.Before(payload.Deadline) || payload.ObservedAt.Before(payload.Deadline) ||
		payload.ObservedAt.After(now.Add(time.Second)) || now.Sub(payload.ObservedAt) > 10*time.Second {
		return executionwire.SignedRuntimeStop{}, errors.New("runtime stop differs from current admitted worker or fresh expired grant")
	}
	wire, err := os.ReadFile(filepath.Join(n.stateDir, "admission.json"))
	var admission admittedIdentity
	if err != nil || json.Unmarshal(wire, &admission, json.RejectUnknownMembers(true)) != nil || admission.InstanceID != payload.InstanceID || admission.Role != n.role {
		return executionwire.SignedRuntimeStop{}, errors.New("runtime stop differs from persistent worker admission")
	}
	key, chain, err := n.nodeSigningKey()
	if err != nil {
		return executionwire.SignedRuntimeStop{}, err
	}
	certificate, err := x509.ParseCertificate(chain[0])
	if err != nil || len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != "swarm-worker" {
		return executionwire.SignedRuntimeStop{}, errors.New("runtime stop requires actual upstream worker certificate")
	}
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		return executionwire.SignedRuntimeStop{}, errors.New("unsupported runtime stop signing key")
	}
	wire, err = json.Marshal(payload, json.Deterministic(true))
	if err != nil {
		return executionwire.SignedRuntimeStop{}, err
	}
	digest := sha256.Sum256(append([]byte("TS-RUNTIME-STOP-V1\x00"), wire...))
	if err := ctx.Err(); err != nil {
		return executionwire.SignedRuntimeStop{}, err
	}
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return executionwire.SignedRuntimeStop{}, err
	}
	return executionwire.SignedRuntimeStop{Payload: payload, CertificateChain: chain, Signature: signature}, nil
}
