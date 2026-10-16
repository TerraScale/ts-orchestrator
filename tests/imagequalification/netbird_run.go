package imagequalification

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/crypto/ssh"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/protocol"
)

// Paths select local, independently approved bytes, never qualification settings.
type netBirdPaths struct {
	Journal, EvidenceDirectory, PrivateKey, Worker, Client string
	Containerd, Runc                                       string
	Archives                                               map[string]string
}

type netBirdResult struct {
	Report           host.Report
	ObservationsPath string
	Qualification    release.ProductionQualification
}

// runNetBird remains private: source availability grants no live cloud authority.
// MaxSpendMicros binds authorization; these observations do not measure actual cost.
// The shared image importer currently supports native ARM64/A1 only.
func runNetBird(ctx context.Context, p Prepared, verified confinement.Verified, paths netBirdPaths) (result netBirdResult, runErr error) {
	artifacts, publicKey, err := netBirdInputs(p, paths)
	if err != nil {
		return result, err
	}
	c, err := newConfinedCloud(ctx, p, verified, paths.Journal)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithDeadline(ctx, p.expires)
	defer cancel()
	var observations []hostObservation
	defer func() {
		deadline := time.Now().Add(5 * time.Minute)
		if p.approval.CleanupUntil.Before(deadline) {
			deadline = p.approval.CleanupUntil
		}
		cleanup, stop := context.WithDeadline(context.Background(), deadline)
		defer stop()
		runErr = errors.Join(runErr, c.cleanup(cleanup, paths.Journal))
		if result.Report.RunID == "" {
			return
		}
		j, err := c.load(paths.Journal)
		if err != nil {
			runErr = errors.Join(runErr, err)
			return
		}
		result.Qualification, result.ObservationsPath, err = retainNetBirdProof(cleanup, p, verified, result.Report, j, observations, paths.EvidenceDirectory, time.Now().UTC())
		runErr = errors.Join(runErr, err)
	}()
	j, err := c.prepareResources(ctx, paths.Journal, publicKey)
	if err != nil {
		return result, err
	}
	req := netbird.Request{RunID: p.approval.RunID, Candidate: p.approval.Candidate, ImageOCID: j.ImageID,
		PrivateKeyPath: paths.PrivateKey, WorkerPath: paths.Worker, WorkerSHA256: p.approval.RunnerSHA256,
		ContainerdPath: paths.Containerd, RuncPath: paths.Runc, Artifacts: artifacts,
		ClientPath: paths.Client, ClientSHA256: p.approval.ClientSHA256,
		RemovePrimary: func(ctx context.Context, id string) (netbird.Removal, error) {
			return c.removeNetBirdPrimary(ctx, paths.Journal, id)
		}}
	for i, spec := range p.approval.Hosts {
		for {
			instance, err := c.ownedInstance(ctx, j, spec)
			if err != nil {
				return result, err
			}
			if instance.LifecycleState == core.InstanceLifecycleStateRunning {
				break
			}
			if instance.LifecycleState != core.InstanceLifecycleStateProvisioning && instance.LifecycleState != core.InstanceLifecycleStateStarting {
				return result, errors.New("dedicated NetBird host did not enter RUNNING")
			}
			if err := pauseConsole(ctx); err != nil {
				return result, err
			}
		}
		observed, key, err := c.consoleKey(ctx, paths.Journal, spec)
		if err != nil {
			return result, err
		}
		observations = append(observations, observed)
		req.Hosts[i] = host.Host{OCID: observed.InstanceID, Address: observed.PrivateIP, SSHHostKey: key,
			ExpectedIdentity: host.Identity{Architecture: p.approval.Candidate.Architecture,
				KernelRelease: p.approval.KernelRelease, KernelSHA256: p.approval.KernelSHA256,
				BinarySHA256: p.approval.BinarySHA256, ContainerdSHA256: p.approval.ContainerdSHA256,
				RuncSHA256: p.approval.RuncSHA256, InstanceID: observed.InstanceID, ImageOCID: j.ImageID}}
	}
	result.Report, runErr = netbird.Run(ctx, req)
	return result, runErr
}

func netBirdInputs(p Prepared, paths netBirdPaths) ([]netbird.Artifact, string, error) {
	a := p.approval
	if err := a.validate(); err != nil {
		return nil, "", err
	}
	if a.Candidate.Role != "netbird-manager" || hashBytes(p.approvalWire) != p.approvalSHA256 || p.approvalSHA256 == "" || paths.Journal == "" || paths.EvidenceDirectory == "" || paths.Containerd == "" || paths.Runc == "" || len(paths.Archives) != len(a.ContainerArtifacts) {
		return nil, "", errors.New("dedicated NetBird requires sealed approval and exact local artifact paths")
	}
	if err := netBirdFile(paths.Worker, a.RunnerSHA256); err != nil {
		return nil, "", fmt.Errorf("NetBird worker: %w", err)
	}
	if err := netBirdFile(paths.Client, a.ClientSHA256); err != nil {
		return nil, "", fmt.Errorf("NetBird client: %w", err)
	}
	var artifacts []netbird.Artifact
	for _, approved := range a.ContainerArtifacts {
		path := paths.Archives[approved.Role]
		if err := netBirdFile(path, approved.ArchiveSHA256); err != nil {
			return nil, "", fmt.Errorf("NetBird %s archive: %w", approved.Role, err)
		}
		artifacts = append(artifacts, netbird.Artifact{Artifact: protocol.Artifact{Role: approved.Role, Image: approved.Image, ArchiveSHA256: approved.ArchiveSHA256}, ArchivePath: path})
	}
	wire, err := os.ReadFile(paths.PrivateKey)
	if err != nil {
		return nil, "", errors.New("ephemeral SSH private key is unavailable")
	}
	defer clear(wire)
	key, err := ssh.ParsePrivateKey(wire)
	if err != nil || key.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, "", errors.New("ephemeral Ed25519 SSH private key is required")
	}
	return artifacts, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), nil
}

func netBirdFile(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("approved artifact must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != expected {
		return errors.New("artifact differs from signed approval")
	}
	return nil
}

// A provider 404 cannot prove removal. Every poll authenticates the exact owned
// instance; only an actual TERMINATED response permits replacement restore.
func (c *cloud) removeNetBirdPrimary(ctx context.Context, path, id string) (netbird.Removal, error) {
	var removed netbird.Removal
	a := c.prepared.approval
	if a.Candidate.Role != "netbird-manager" || len(a.Hosts) != 2 || a.Hosts[0].Role != "netbird-primary" {
		return removed, errors.New("dedicated NetBird primary approval is required")
	}
	j, err := c.load(path)
	if err != nil {
		return removed, err
	}
	spec := a.Hosts[0]
	if id == "" || j.Hosts[spec.Name] != id || id == j.Hosts[a.Hosts[1].Name] {
		return removed, errors.New("only the exact approved primary can be removed")
	}
	requested := false
	for {
		if err := c.check(ctx, false); err != nil {
			return removed, err
		}
		instance, err := c.ownedInstance(ctx, j, spec)
		if err != nil {
			return removed, err
		}
		if instance.LifecycleState == core.InstanceLifecycleStateTerminated {
			j.Terminated[spec.Name] = true
			if err := checkpoint(path, j); err != nil {
				return removed, err
			}
			return netbird.Removal{InstanceID: id, State: "TERMINATED", ObservedAt: c.now().UTC()}, nil
		}
		if !requested && instance.LifecycleState != core.InstanceLifecycleStateTerminating {
			_, err := c.compute.TerminateInstance(ociclient.RequestContext(ctx), core.TerminateInstanceRequest{InstanceId: new(id), PreserveBootVolume: new(false)})
			if err != nil {
				return removed, err
			}
			requested = true
			continue
		}
		if err := pauseConsole(ctx); err != nil {
			return removed, err
		}
	}
}
