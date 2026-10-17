package imagequalification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/crypto/ssh"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/native"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

type rootCredentialPaths struct {
	PrincipalDirectory, Approval, Journal, EvidenceDirectory    string
	Disk, CIQualification, PrivateKey, Worker, Containerd, Runc string
}

type rootCredentialResult struct {
	Report host.Report
	Gate   release.ProductionGateEvidence
}

// runRootCredentialBoundary owns the actual finite lifecycle. Source presence
// neither invokes this private coordinator nor grants live signing/cloud authority.
func runRootCredentialBoundary(ctx context.Context, preparationWire, delegationWire []byte, roots trust.Keyring, issuer *ociclient.Factory, signer ed25519.PrivateKey, paths rootCredentialPaths) (result rootCredentialResult, runErr error) {
	now := time.Now().UTC()
	envelope, err := trust.DecodeEnvelope(preparationWire)
	if err != nil {
		return result, err
	}
	var original principal.Preparation
	if err := protocol.DecodeStrict(envelope.Payload, &original, trust.MaxPayloadBytes); err != nil {
		return result, err
	}
	v, err := principal.VerifyPreparation(preparationWire, delegationWire, roots, original.RunID, now)
	if err != nil {
		return result, err
	}
	if original.Purpose != qualification.RootCredentialBoundaryPurpose {
		return result, errors.New("root coordinator requires original root-credential-boundary purpose")
	}
	if handled, err := recoverRootCredentialBoundary(ctx, v, preparationWire, delegationWire, roots, issuer, paths); handled {
		return result, err
	}
	if len(signer) != ed25519.PrivateKeySize {
		return result, errors.New("original qualifier signing key required")
	}
	signerID, err := trust.KeyID(signer.Public().(ed25519.PublicKey))
	if err != nil || signerID != envelope.KeyID {
		return result, errors.New("root coordinator signer differs from original qualifier")
	}
	prep := v.Preparation()
	public, err := rootCredentialInputs(prep, paths)
	if err != nil {
		return result, err
	}
	producer := principal.New(issuer)
	var p Prepared
	var preparedPrincipal principal.Result
	defer func() {
		cleanup, stop := context.WithDeadline(context.Background(), prep.CleanupUntil)
		defer stop()
		runErr = errors.Join(runErr, producer.CleanupReaders(cleanup, v, paths.PrincipalDirectory))
		settled := p.approvalSHA256 == ""
		if p.approvalSHA256 != "" {
			p.readerIAM = nil
			scope, err := p.ConfinementScope(paths.Journal)
			var confined confinement.Verified
			if err == nil {
				confined, err = confinement.Observe(cleanup, issuer, preparedPrincipal.CandidateFactory(), scope)
			}
			var c *cloud
			if err == nil {
				c, err = newConfinedCloud(cleanup, p, confined, paths.Journal)
			}
			if err == nil {
				var observer *ociclient.Factory
				observer, err = issuer.ForRegion(p.approval.OCIRegion)
				if err == nil {
					err = c.superviseRetainedImage(ctx, paths.Journal, observer)
				}
			}
			settled = err == nil
			runErr = errors.Join(runErr, err)
		}
		if settled {
			_, err := producer.Cleanup(cleanup, v, paths.PrincipalDirectory)
			runErr = errors.Join(runErr, err)
		}
	}()
	preparedPrincipal, err = producer.Prepare(ctx, v, paths.PrincipalDirectory)
	if err != nil {
		return result, err
	}
	if wire, readErr := os.ReadFile(paths.Approval); readErr == nil {
		p, err = Prepare(wire, delegationWire, roots, prep.Candidate, prep.RunID, paths.Disk, paths.CIQualification, time.Now().UTC())
		if err == nil {
			p.principalWire = append([]byte(nil), preparationWire...)
		}
		if err == nil {
			hostEnvelope, decodeErr := trust.DecodeEnvelope(wire)
			if decodeErr != nil || hostEnvelope.KeyID != envelope.KeyID || hostEnvelope.IssuedAt.Before(envelope.IssuedAt) || hostEnvelope.ExpiresAt.After(prep.ExpiresAt) {
				err = errors.New("retained host approval changes original signer or creation interval")
			}
		}
		if err == nil {
			err = preparedPrincipal.ValidatePreparation(v, time.Now())
		}
		if err == nil {
			want, encodeErr := json.Marshal(approvalFromPrincipal(prep, preparedPrincipal.Receipt()), json.Deterministic(true))
			got, gotErr := json.Marshal(p.approval, json.Deterministic(true))
			if encodeErr != nil || gotErr != nil || !bytes.Equal(want, got) {
				err = errors.New("retained host approval differs from exact original preparation and actual principal")
			}
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		var wire []byte
		p, wire, err = PrepareFromPrincipal(preparationWire, delegationWire, roots, preparedPrincipal, signer, prep.RunID, paths.Disk, paths.CIQualification, time.Now().UTC())
		if err == nil {
			err = retainBytes(paths.Approval, wire)
		}
	} else {
		err = readErr
	}
	if err != nil {
		return result, err
	}
	phase, cancel := context.WithDeadline(ctx, p.approval.ImageRetainUntil)
	defer cancel()
	scope, err := p.ConfinementScope(paths.Journal)
	if err != nil {
		return result, err
	}
	confined, err := confinement.Observe(phase, issuer, preparedPrincipal.CandidateFactory(), scope)
	if err != nil {
		return result, err
	}
	c, err := newConfinedCloud(phase, p, confined, paths.Journal)
	if err != nil {
		return result, err
	}
	j, err := c.prepareResources(phase, paths.Journal, public)
	if err != nil {
		return result, err
	}
	var observed []hostObservation
	var nativeHosts []host.Host
	for _, spec := range p.approval.Hosts {
		for {
			instance, err := c.ownedInstance(phase, j, spec)
			if err != nil {
				return result, err
			}
			if instance.LifecycleState == core.InstanceLifecycleStateRunning {
				break
			}
			if instance.LifecycleState != core.InstanceLifecycleStateProvisioning && instance.LifecycleState != core.InstanceLifecycleStateStarting {
				return result, errors.New("root credential host did not enter RUNNING")
			}
			if err := pauseConsole(phase); err != nil {
				return result, err
			}
		}
		h, key, err := c.consoleKey(phase, paths.Journal, spec)
		if err != nil {
			return result, err
		}
		observed = append(observed, h)
		nativeHosts = append(nativeHosts, host.Host{OCID: h.InstanceID, Address: h.PrivateIP, SSHHostKey: key, ExpectedIdentity: host.Identity{Architecture: prep.Candidate.Architecture, KernelRelease: prep.KernelRelease, KernelSHA256: prep.KernelSHA256, BinarySHA256: prep.BinarySHA256, ContainerdSHA256: prep.ContainerdSHA256, RuncSHA256: prep.RuncSHA256, InstanceID: h.InstanceID, ImageOCID: j.ImageID}})
	}
	proofs, err := c.readerProofs(phase, j, confined, signer, hostadmission.ReaderIAM{})
	if err != nil {
		return result, err
	}
	planProof := proofs[nativeHosts[0].OCID]
	plan, err := hostadmission.VerifyReaderPlan(planProof, roots, time.Now())
	if err != nil {
		return result, err
	}
	iam, err := producer.PrepareReaders(phase, v, paths.PrincipalDirectory, planProof)
	if err != nil {
		return result, err
	}
	if err := iam.Validate(v, plan, time.Now()); err != nil {
		return result, err
	}
	var ids []string
	for _, h := range plan.Hosts() {
		ids = append(ids, h.InstanceID)
	}
	p.readerIAM = &confinement.ReaderIAM{DynamicGroupID: iam.IAM().DynamicGroupID, PolicyID: iam.IAM().PolicyID, Rule: qualification.ReaderMatchingRule(ids), ExpiresAt: plan.ExpiresAt()}
	scope, err = p.ConfinementScope(paths.Journal)
	if err != nil {
		return result, err
	}
	confined, err = confinement.Observe(phase, issuer, preparedPrincipal.CandidateFactory(), scope)
	if err != nil {
		return result, err
	}
	c, err = newConfinedCloud(phase, p, confined, paths.Journal)
	if err != nil {
		return result, err
	}
	proofs, err = c.readerProofs(phase, j, confined, signer, iam.IAM())
	if err != nil {
		return result, err
	}
	candidate := prep.Candidate
	candidate.ImageOCID = j.ImageID
	request := native.Request{RunID: prep.RunID, Candidate: candidate, ImageOCID: j.ImageID, Hosts: nativeHosts, SSHUser: "root", PrivateKeyPath: paths.PrivateKey, WorkerPath: paths.Worker, WorkerSHA256: prep.RunnerSHA256, ContainerdPath: paths.Containerd, RuncPath: paths.Runc, RootCredentialProofs: proofs, RootCredentialNamespaceSHA256: hashBytes([]byte(prep.Namespace))}
	var evidence release.RootCredentialBoundaryEvidence
	result.Report, evidence, err = native.RunRootCredentialBoundary(phase, request)
	if err != nil {
		return result, err
	}
	j, err = c.load(paths.Journal)
	if err != nil {
		return result, err
	}
	result.Gate, err = retainRootCredentialEvidence(p, result.Report, evidence, j, observed, proofs, paths.EvidenceDirectory, time.Now().UTC())
	if err != nil {
		return result, err
	}
	j.RetainedReaderProof, j.RetainedAt, j.RootGateSHA256 = proofs[nativeHosts[0].OCID], time.Now().UTC(), result.Gate.SHA256
	if _, err := c.retainImage(j); err != nil {
		return result, err
	}
	return result, checkpoint(paths.Journal, j)
}

func rootCredentialInputs(p principal.Preparation, paths rootCredentialPaths) (string, error) {
	if p.Purpose != qualification.RootCredentialBoundaryPurpose || !time.Now().Before(p.ImageTransferUntil) || paths.PrincipalDirectory == "" || paths.Approval == "" || paths.Journal == "" || paths.EvidenceDirectory == "" {
		return "", errors.New("current original root purpose and durable local paths required")
	}
	for path, digest := range map[string]string{paths.Worker: p.RunnerSHA256, paths.Containerd: p.ContainerdSHA256, paths.Runc: p.RuncSHA256} {
		if err := netBirdFile(path, digest); err != nil {
			return "", err
		}
	}
	if err := verifyDisk(paths.Disk, Approval{Candidate: p.Candidate, ImageBytes: p.ImageBytes}); err != nil {
		return "", err
	}
	info, err := os.Lstat(paths.PrivateKey)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("ephemeral private key must be a regular owner-only file")
	}
	wire, err := os.ReadFile(paths.PrivateKey)
	if err != nil {
		return "", err
	}
	defer clear(wire)
	key, err := ssh.ParsePrivateKey(wire)
	if err != nil || key.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return "", errors.New("ephemeral Ed25519 SSH key required")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), nil
}
