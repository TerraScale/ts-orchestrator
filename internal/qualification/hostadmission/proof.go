// Package hostadmission admits only finite qualification startup observations.
// A qualification seal is never a production identity or mutation capability.
package hostadmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	MaxProofBytes = 256 << 10
	BindingSchema = "terrascale.test.image-qualification.host-reader.v1"
	ProofSchema   = "terrascale.test.image-qualification.reader-proof.v1"
	maxLifetime   = 72 * time.Hour
	maxAdmission  = time.Hour
)

var ErrAdmission = errors.New("finite qualification reader admission rejected")
var runIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// Proof retains original authority and its exact original-signer attenuation.
// Public fields cannot construct StartupReader; ReadAdmission checks live facts.
type Proof struct {
	Schema      string `json:"schema"`
	Preparation []byte `json:"preparation"`
	Approval    []byte `json:"approval"`
	Delegation  []byte `json:"delegation,omitempty"`
	Binding     []byte `json:"binding"`
}

type BoundHost struct {
	Name       string `json:"name"`
	InstanceID string `json:"instance_id"`
	ImageID    string `json:"image_id"`
	PrivateIP  string `json:"private_ip"`
}

// Binding narrows the prelaunch plan with privately observed SDK launch results.
// It is signed by the original qualifier, never by a new root or local marker.
type Binding struct {
	Schema            string      `json:"schema"`
	Purpose           string      `json:"purpose"`
	RunID             string      `json:"run_id"`
	PreparationSHA256 string      `json:"preparation_sha256"`
	ApprovalSHA256    string      `json:"approval_sha256"`
	HostName          string      `json:"host_name"`
	Hosts             []BoundHost `json:"hosts"`
}

type verified struct {
	proof    Proof
	approval qualification.Approval
	binding  Binding
	host     BoundHost
	deadline time.Time
	issuedAt time.Time
	digest   string
}

func fingerprint(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func validHash(value string) bool {
	wire, err := hex.DecodeString(value)
	return err == nil && len(wire) == 32 && hex.EncodeToString(wire) == value
}

func verifyEnvelope(wire, delegation []byte, roots trust.Keyring, scope trust.Scope, now time.Time) (trust.Envelope, error) {
	e, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return e, err
	}
	policy := trust.Policy{MaxLifetime: maxLifetime}
	var payload []byte
	if len(delegation) == 0 {
		payload, err = trust.VerifyCurrent(e, scope, roots, now, policy)
	} else {
		de, decodeErr := trust.DecodeEnvelope(delegation)
		if decodeErr != nil {
			return e, decodeErr
		}
		vd, verifyErr := trust.VerifyDelegationCurrent(de, roots, now, policy)
		if verifyErr != nil {
			return e, verifyErr
		}
		payload, err = trust.VerifyDelegatedCurrent(e, scope, vd, now, policy)
	}
	if err != nil || !bytes.Equal(payload, e.Payload) {
		return e, errors.Join(ErrAdmission, err)
	}
	return e, nil
}

func verifyProof(wire []byte, roots trust.Keyring, now time.Time) (verified, error) {
	var v verified
	if protocol.DecodeStrict(wire, &v.proof, MaxProofBytes) != nil || v.proof.Schema != ProofSchema {
		return v, ErrAdmission
	}
	e, err := trust.DecodeEnvelope(v.proof.Approval)
	if err != nil || protocol.DecodeStrict(e.Payload, &v.approval, trust.MaxPayloadBytes) != nil {
		return v, ErrAdmission
	}
	a := v.approval
	if !runIDPattern.MatchString(a.RunID) || a.Purpose != qualification.RootCredentialBoundaryPurpose ||
		a.Candidate.Role != release.FoundationWriterRole || qualification.ValidatePurpose(a.Candidate, a.Purpose) != nil ||
		!release.ValidRegion(a.Candidate.Cell) || !release.ValidEnvironment(a.Candidate.Environment) ||
		!release.ValidSourceRevision(a.Candidate.SourceRevision) || !validHash(a.Candidate.ArtifactSHA256) || !validHash(a.Candidate.QualificationSHA256) ||
		a.Schema != "terrascale.test.image-qualification.v1" || a.Tenancy == a.Compartment || a.MaxSpendMicros <= 0 || a.MaxSpendMicros > 100_000_000 || len(a.Hosts) != 4 {
		return v, ErrAdmission
	}
	scope := qualification.Scope(a.RunID, a.Candidate, "disposable-host")
	ae, err := verifyEnvelope(v.proof.Approval, v.proof.Delegation, roots, scope, now)
	if err != nil {
		return v, err
	}
	ps := scope
	ps.Role = "disposable-principal"
	pe, err := verifyEnvelope(v.proof.Preparation, v.proof.Delegation, roots, ps, now)
	if err != nil {
		return v, err
	}
	var p qualification.Preparation
	if protocol.DecodeStrict(pe.Payload, &p, trust.MaxPayloadBytes) != nil || p.Schema != "terrascale.test.image-qualification.principal.v1" ||
		p.Purpose != a.Purpose || p.Candidate != a.Candidate || p.RunID != a.RunID || pe.KeyID != ae.KeyID ||
		p.Tenancy != a.Tenancy || p.Compartment != a.Compartment || p.Subnet != a.Subnet || p.Namespace != a.Namespace || p.Bucket != a.Bucket ||
		p.OCIRegion != a.OCIRegion || p.IAMRegion != a.IAMRegion || p.PeerCIDR != a.PeerCIDR || p.RunnerCIDR != a.RunnerCIDR || p.VCNCIDR != a.VCNCIDR ||
		p.BinarySHA256 != a.BinarySHA256 || p.KernelSHA256 != a.KernelSHA256 || p.KernelRelease != a.KernelRelease || p.ContainerdSHA256 != a.ContainerdSHA256 ||
		p.RuncSHA256 != a.RuncSHA256 || p.RunnerSHA256 != a.RunnerSHA256 || p.MaxSpendMicros != a.MaxSpendMicros || p.ImageBytes != a.ImageBytes ||
		!slices.Equal(p.Hosts, a.Hosts) || !p.CleanupUntil.Equal(pe.ExpiresAt) || !a.CleanupUntil.Equal(p.CleanupUntil) ||
		ae.ExpiresAt.After(p.ExpiresAt) || !p.ExpiresAt.After(pe.IssuedAt) || p.ExpiresAt.Sub(pe.IssuedAt) > 48*time.Hour ||
		p.CleanupUntil.Before(p.ExpiresAt) || p.CleanupUntil.Sub(p.ExpiresAt) > 24*time.Hour {
		return v, ErrAdmission
	}
	for _, digest := range []string{a.BinarySHA256, a.KernelSHA256, a.ContainerdSHA256, a.RuncSHA256, a.RunnerSHA256} {
		if !validHash(digest) {
			return v, ErrAdmission
		}
	}
	be, err := verifyEnvelope(v.proof.Binding, v.proof.Delegation, roots, scope, now)
	if err != nil {
		return v, err
	}
	b := &v.binding
	if protocol.DecodeStrict(be.Payload, b, trust.MaxPayloadBytes) != nil || b.Schema != BindingSchema || b.Purpose != a.Purpose || b.RunID != a.RunID ||
		be.KeyID != ae.KeyID || b.PreparationSHA256 != fingerprint(v.proof.Preparation) || b.ApprovalSHA256 != fingerprint(v.proof.Approval) ||
		be.IssuedAt.Before(ae.IssuedAt) || be.IssuedAt.Before(pe.IssuedAt) || be.ExpiresAt.After(ae.ExpiresAt) || be.ExpiresAt.After(p.ExpiresAt) ||
		be.ExpiresAt.Sub(be.IssuedAt) > maxAdmission || be.ExpiresAt.After(ae.IssuedAt.Add(maxAdmission)) || len(b.Hosts) != 4 {
		return v, ErrAdmission
	}
	peers, err := netip.ParsePrefix(a.PeerCIDR)
	if err != nil || !peers.IsValid() || !peers.Addr().IsPrivate() {
		return v, ErrAdmission
	}
	ids, ips, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var image string
	for i, h := range b.Hosts {
		spec := a.Hosts[i]
		ip, err := netip.ParseAddr(h.PrivateIP)
		role := "manager"
		if i == 3 {
			role = "worker"
		}
		if err != nil || !peers.Contains(ip) || h.Name != spec.Name || spec.Role != role || names[h.Name] || h.Name == "" || ids[h.InstanceID] || ips[h.PrivateIP] ||
			!release.ValidOCIImageIDForRegion(h.ImageID, a.Candidate.Cell) || image != "" && h.ImageID != image || !validInstanceID(h.InstanceID) ||
			spec.Shape == "" || spec.AvailabilityDomain == "" || spec.FaultDomain == "" || spec.OCPUs <= 0 || spec.MemoryGB <= 0 || spec.BootGB < 50 {
			return v, ErrAdmission
		}
		image = h.ImageID
		ids[h.InstanceID] = true
		ips[h.PrivateIP] = true
		names[h.Name] = true
		if h.Name == b.HostName {
			v.host = h
		}
	}
	if v.host.InstanceID == "" {
		return v, ErrAdmission
	}
	v.issuedAt = maxTime(pe.IssuedAt, ae.IssuedAt, be.IssuedAt)
	v.deadline = minTime(p.ExpiresAt, ae.ExpiresAt, be.ExpiresAt)
	if len(v.proof.Delegation) > 0 {
		de, err := trust.DecodeEnvelope(v.proof.Delegation)
		if err != nil {
			return v, err
		}
		v.issuedAt = maxTime(v.issuedAt, de.IssuedAt)
		v.deadline = minTime(v.deadline, de.ExpiresAt)
	}
	if now.Before(v.issuedAt) || !now.Before(v.deadline) {
		return v, ErrAdmission
	}
	v.digest = fingerprint(wire)
	return v, nil
}

func minTime(values ...time.Time) time.Time {
	t := values[0]
	for _, v := range values[1:] {
		if v.Before(t) {
			t = v
		}
	}
	return t
}
func maxTime(values ...time.Time) time.Time {
	t := values[0]
	for _, v := range values[1:] {
		if v.After(t) {
			t = v
		}
	}
	return t
}
func validInstanceID(id string) bool {
	return regexp.MustCompile(`^ocid1\.instance\.oc1\.[a-z0-9-]+\.[a-z0-9-]+$`).MatchString(id)
}
