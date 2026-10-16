package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sync/errgroup"
)

func (c command) containerApply(args []string) error {
	return c.containerApplyWith(args, deployEnv{storage: operatorObjectStorage})
}

// containerApplyWith consumes retained signed bundles and standard OCI layouts;
// it never reads a source checkout, signing key or sequence allocator.
func (c command) containerApplyWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("container-apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "retained signed container bundle with OCI layout and evidence")
	rootPath := flags.String("root-key", "", "existing trusted root public key outside the bundle")
	namespace := flags.String("namespace", "", "regional Object Storage namespace")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *rootPath == "" || !validStorageToken(*namespace) || flags.NArg() != 0 {
		return errors.New("container-apply requires --dir, --root-key and --namespace")
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(*directory)
	if err != nil {
		return err
	}
	type target struct {
		bundle   release.ContainerBundle
		verified release.VerifiedContainer
		scope    release.ContainerTarget
	}
	var targets []target
	var source, repository, tree, role, environment string
	var sequence uint64
	budget := rollout.ObservationBudget
	if env.timeout > 0 {
		budget = min(budget, env.timeout)
	}
	now := time.Now().UTC()
	deadline := now.Add(budget)
	for _, entry := range entries {
		if !entry.IsDir() || !validRegion(entry.Name()) {
			continue
		}
		architectures, err := os.ReadDir(filepath.Join(*directory, entry.Name()))
		if err != nil {
			return err
		}
		for _, architecture := range architectures {
			if !architecture.IsDir() || !slices.Contains([]string{"amd64", "arm64"}, architecture.Name()) {
				continue
			}
			wire, err := readBoundedRegular(filepath.Join(*directory, entry.Name(), architecture.Name(), "container.json"), releasechannel.MaxContainerBundleBytes)
			if err != nil {
				return err
			}
			var bundle release.ContainerBundle
			if err := protocol.DecodeStrict(wire, &bundle, releasechannel.MaxContainerBundleBytes); err != nil {
				return err
			}
			envelope, err := trust.DecodeEnvelope(bundle.Claim)
			if err != nil {
				return err
			}
			var claim release.ContainerClaim
			if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
				return err
			}
			scope := release.ContainerTarget{Cell: entry.Name(), Environment: claim.Environment, Role: claim.Role, Architecture: architecture.Name()}
			verified, err := release.VerifyContainerCurrent(c.ctx, bundle, roots, scope, now, deadline, containerEvidenceReader(filepath.Join(*directory, "production")))
			if err != nil {
				return err
			}
			claim = verified.Claim()
			if role == "" {
				source, repository, tree, role, environment, sequence = claim.SourceRevision, claim.SourceRepository, claim.SourceTreeSHA256, claim.Role, claim.Environment, claim.ReleaseSequence
			}
			if source != claim.SourceRevision || repository != claim.SourceRepository || tree != claim.SourceTreeSHA256 || role != claim.Role || environment != claim.Environment || sequence != claim.ReleaseSequence {
				return errors.New("container bundle mixes source identities, roles, environments or sequences")
			}
			repositoryImage, _, ok := strings.Cut(claim.Image, "@sha256:")
			if !ok {
				return errors.New("container image has no immutable digest")
			}
			inspected, err := release.InspectContainerImageLayout(c.ctx, filepath.Join(*directory, "oci-layout"), repositoryImage+"@sha256:"+claim.QualificationSHA256, claim.Architecture)
			if err != nil {
				return err
			}
			if inspected.Image != claim.Image {
				return errors.New("retained OCI layout root differs from signed child image")
			}
			targets = append(targets, target{bundle: bundle, verified: verified, scope: scope})
		}
	}
	if len(targets) == 0 {
		return errors.New("container bundle contains no regions or architectures")
	}
	progress := &deploymentWriter{Writer: c.output}
	failures := make([]error, len(targets))
	var group errgroup.Group
	group.SetLimit(4)
	for index, target := range targets {
		group.Go(func() error {
			ctx, cancel := context.WithTimeout(c.ctx, budget)
			defer cancel()
			regional := c
			regional.ctx = ctx
			apply := func() error {
				claim := target.verified.Claim()
				deadline := time.Now().UTC().Add(budget)
				location, err := channelLocation(env, target.scope.Cell, *namespace)
				if err != nil {
					return err
				}
				admitted, err := deploymentScope(ctx, location, target.scope.Cell)
				if err != nil {
					return err
				}
				if admitted.Environment != claim.Environment || !slices.Contains(admitted.Architectures, claim.Architecture) {
					return errors.New("container differs from admitted regional scope")
				}
				if err := regional.uploadContainerEvidence(*directory, location, target.verified, roots, deadline); err != nil {
					return err
				}
				if err := releasechannel.PublishContainer(ctx, location, target.bundle, roots, target.scope, time.Now().UTC(), deadline, func(ctx context.Context, digest string) (io.ReadCloser, error) {
					return releasechannel.ReadContainerEvidence(ctx, location, claim.Role, digest)
				}); err != nil {
					return err
				}
				fmt.Fprintf(progress, "%s %s %s published signed OCI %s\n", claim.Cell, claim.Role, claim.Architecture, claim.Image)
				return awaitContainer(ctx, location, target.verified, deadline, progress)
			}
			if err := apply(); err != nil {
				failures[index] = fmt.Errorf("%s %s %s: %w", target.scope.Cell, target.scope.Role, target.scope.Architecture, err)
				fmt.Fprintf(progress, "%s %s %s failed: %v\n", target.scope.Cell, target.scope.Role, target.scope.Architecture, err)
			}
			return nil
		})
	}
	_ = group.Wait()
	return errors.Join(failures...)
}

func (c command) uploadContainerEvidence(directory string, location releasechannel.Location, verified release.VerifiedContainer, roots trust.Keyring, deadline time.Time) error {
	claim := verified.Claim()
	_, digest, _ := strings.Cut(claim.Image, "@sha256:")
	expected := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: digest, QualificationSHA256: claim.QualificationSHA256, Cell: claim.Cell, Environment: claim.Environment, Runtime: release.ProductionRuntime, Architecture: claim.Architecture, Role: claim.Role}
	proof, err := release.VerifyProductionCurrent(claim.Production.Qualification, claim.Production.Delegation, roots, expected, deadline)
	if err != nil {
		return err
	}
	type retained struct {
		path, digest string
		size         int64
	}
	objects := make([]retained, 0, len(proof.Evidence)+2)
	for _, evidence := range proof.Evidence {
		objects = append(objects, retained{filepath.Join(directory, "production", "objects", evidence.SHA256), evidence.SHA256, evidence.Bytes})
	}
	// Retain the actual immutable root/index and child bytes alongside the signed
	// runtime gates; they remain standard OCI blobs with their original digests.
	for _, metadata := range []string{claim.QualificationSHA256, digest} {
		objects = append(objects, retained{filepath.Join(directory, "oci-layout", "blobs", "sha256", metadata), metadata, 0})
	}
	for _, object := range objects {
		file, size, sum, err := c.openHashedArtifact(object.path, release.MaxProductionEvidenceBytes)
		if err != nil {
			return err
		}
		if hex.EncodeToString(sum) != object.digest || object.size != 0 && size != object.size {
			file.Close()
			return errors.New("retained OCI qualification bytes changed")
		}
		putErr := putImmutable(c.ctx, location.Client, location.Namespace, location.Bucket, releasechannel.ContainerEvidenceObject(claim.Role, object.digest), file, size, sum)
		if err := errors.Join(putErr, file.Close()); err != nil {
			return err
		}
	}
	return nil
}

func awaitContainer(ctx context.Context, location releasechannel.Location, verified release.VerifiedContainer, deadline time.Time, output io.Writer) error {
	claim := verified.Claim()
	for {
		status, found, err := releasechannel.ReadContainerStatus(ctx, location, claim.Role, claim.Architecture)
		if err != nil {
			return err
		}
		if found && status.Schema == releasechannel.ContainerStatusSchema && status.Cell == claim.Cell && status.Environment == claim.Environment && status.Role == claim.Role && status.Architecture == claim.Architecture && status.Image == claim.Image && status.ReleaseSequence == claim.ReleaseSequence && status.Fingerprint == verified.Fingerprint() {
			switch status.State {
			case releasechannel.StateComplete:
				fmt.Fprintf(output, "%s %s %s complete: %s\n", claim.Cell, claim.Role, claim.Architecture, claim.Image)
				return nil
			case releasechannel.StateFailed:
				return fmt.Errorf("%w: %s", releasechannel.ErrFailed, status.Reason)
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w: container did not become ready before deadline", releasechannel.ErrFailed)
		}
		timer := time.NewTimer(min(5*time.Second, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
