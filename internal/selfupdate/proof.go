package selfupdate

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	ProofDomain = "terrascale.orchestrator.version-proof"
	ProofSchema = "terrascale.orchestrator.version-proof.v1"
	// ProofLifetime bounds a version proof so only a fresh one confirms.
	ProofLifetime = 10 * time.Minute
	proofClock    = time.Minute
)

// VersionProof is signed by the new process once it is healthy. It names
// the activation, the exact binary digest the process executes and its
// process identity; the watchdog and rollout gates verify it.
type VersionProof struct {
	Schema       string    `json:"schema"`
	ActivationID string    `json:"activation_id"`
	Unit         string    `json:"unit"`
	BinarySHA256 string    `json:"binary_sha256"`
	ProcessID    int64     `json:"process_id"`
	ObservedAt   time.Time `json:"observed_at"`
}

func proofScope(activationID, digest string) trust.Scope {
	return trust.Scope{
		Domain: ProofDomain, DeploymentID: activationID, Cell: "local",
		Environment: "node", Role: "version-proof", Slot: digest,
	}
}

// SignVersionProof signs proof with the process's own identity key.
func SignVersionProof(proof VersionProof, privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if proof.Schema != ProofSchema || !activationIDRE.MatchString(proof.ActivationID) || !unitRE.MatchString(proof.Unit) ||
		!digestRE.MatchString(proof.BinarySHA256) || proof.ProcessID <= 0 || proof.ObservedAt.IsZero() {
		return nil, fmt.Errorf("%w: version proof", ErrInvalid)
	}
	payload, err := trust.EncodePayload(proof)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.Sign(payload, proofScope(proof.ActivationID, proof.BinarySHA256), now, now.Add(ProofLifetime), privateKey)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

// VerifyVersionProof accepts only a currently valid proof, signed by
// publicKey, for exactly this activation, unit and target digest, issued
// after the activation moved the current link.
func VerifyVersionProof(wire []byte, publicKey ed25519.PublicKey, activation Activation, now time.Time) (VersionProof, error) {
	if err := activation.validate(); err != nil {
		return VersionProof{}, err
	}
	keys, err := trust.ParseKeyring(publicKey)
	if err != nil {
		return VersionProof{}, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VersionProof{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, proofScope(activation.ActivationID, activation.Target), keys, now,
		trust.Policy{MaxLifetime: ProofLifetime, ClockSkew: proofClock})
	if err != nil {
		return VersionProof{}, err
	}
	var proof VersionProof
	if err := protocol.DecodeStrict(payload, &proof, maxStateBytes); err != nil {
		return VersionProof{}, err
	}
	if proof.Schema != ProofSchema || proof.ActivationID != activation.ActivationID || proof.Unit != activation.Unit ||
		proof.BinarySHA256 != activation.Target || proof.ProcessID <= 0 ||
		envelope.IssuedAt.Before(activation.ActivatedAt.Truncate(time.Second)) || proof.ObservedAt.Before(activation.ActivatedAt) {
		return VersionProof{}, fmt.Errorf("%w: version proof is not fresh for this activation", ErrInvalid)
	}
	// A process that became ready only after its proof window must not be
	// confirmed by a late check. A check after the deadline still accepts a
	// proof produced in time.
	if envelope.IssuedAt.After(activation.Deadline) || proof.ObservedAt.After(activation.Deadline) {
		return VersionProof{}, fmt.Errorf("%w: version proof was produced after the activation deadline", ErrInvalid)
	}
	return proof, nil
}

// EmitProof is called by a healthy process. When an activation for unit is
// pending and this process runs its target, it writes a signed proof to
// proofFile. It returns false when there is nothing to confirm.
func EmitProof(layout Layout, unit, proofFile string, privateKey ed25519.PrivateKey, now time.Time) (bool, error) {
	if !filepath.IsAbs(proofFile) {
		return false, fmt.Errorf("%w: proof file must be absolute", ErrInvalid)
	}
	if err := layout.validate(); err != nil {
		return false, err
	}
	activation, pending, err := layout.Pending()
	if err != nil || !pending || activation.Unit != unit {
		return false, err
	}
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return false, err
	}
	digest, _, err := hashFile(executable)
	if err != nil {
		return false, err
	}
	if digest != activation.Target {
		return false, nil
	}
	wire, err := SignVersionProof(VersionProof{
		Schema: ProofSchema, ActivationID: activation.ActivationID, Unit: unit,
		BinarySHA256: digest, ProcessID: int64(os.Getpid()), ObservedAt: now.UTC(),
	}, privateKey, now)
	if err != nil {
		return false, err
	}
	return true, writeFileAtomic(proofFile, wire, 0o644)
}

func readProof(path string) ([]byte, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	wire, err := readBounded(path, trust.MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 {
		return nil, errors.New("empty version proof")
	}
	return wire, nil
}
