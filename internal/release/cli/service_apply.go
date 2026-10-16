package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const serviceBundleSchema = "terrascale.release.service-bundle.v1"

// serviceBundle carries the existing controller claim and its public authorization.
// Architecture is checked against the executable, never trusted independently.
type serviceBundle struct {
	Schema       string         `json:"schema"`
	Cell         string         `json:"cell"`
	Environment  string         `json:"environment"`
	Role         string         `json:"role"`
	Architecture string         `json:"architecture"`
	Delegation   jsontext.Value `json:"delegation"`
	Claim        jsontext.Value `json:"claim"`
	Migration    jsontext.Value `json:"sequence_migration"`
}

func (bundle serviceBundle) verify(ctx context.Context, roots trust.Keyring, cell string, now time.Time) (delivery.ArtifactRecord, error) {
	if bundle.Schema != serviceBundleSchema || bundle.Cell != cell || !validRegion(cell) || !validEnvironment(bundle.Environment) ||
		!slices.Contains([]string{"amd64", "arm64"}, bundle.Architecture) {
		return delivery.ArtifactRecord{}, errors.New("invalid service bundle scope")
	}
	delegation, public, expires, err := release.VerifyReleaseDelegationCurrent(bundle.Delegation, roots, bundle.Environment, now)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	actor, err := release.DelegatedReleaseActor(public)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	codec := delivery.Ed25519Codec{Cell: strings.ToLower(cell), MaxLifetime: 5 * time.Minute,
		Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: actor, PublicKey: public}}, Now: func() time.Time { return now }}
	record, _, err := codec.VerifyArchivedArtifact(ctx, bundle.Claim)
	if err != nil {
		return delivery.ArtifactRecord{}, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(bundle.Claim, &envelope, delivery.MaxArtifactClaimBytes); err != nil {
		return delivery.ArtifactRecord{}, err
	}
	var grant trust.Envelope
	if err := protocol.DecodeStrict(bundle.Delegation, &grant, trust.MaxEnvelopeBytes); err != nil {
		return delivery.ArtifactRecord{}, err
	}
	if envelope.IssuedAt.After(now) || envelope.IssuedAt.Before(grant.IssuedAt) || envelope.ExpiresAt.After(expires) || record.Role != bundle.Role ||
		record.ProductionQualificationSHA256 == "" || record.Environment != bundle.Environment || !delegation.MayRelease(record.Role, record.Source.Repository) ||
		!slices.Contains(delegation.Architectures, bundle.Architecture) {
		return delivery.ArtifactRecord{}, errors.New("service claim exceeds its root delegation or bundle scope")
	}
	if err := verifyServiceSequence(bundle, record, roots, now); err != nil {
		return delivery.ArtifactRecord{}, err
	}
	return record, nil
}

func serviceProductionCandidate(bundle serviceBundle, record delivery.ArtifactRecord) (release.ProductionExpectation, error) {
	content, err := record.ContentManifestDigest()
	if err != nil {
		return release.ProductionExpectation{}, err
	}
	return release.ProductionExpectation{SourceRevision: record.Source.Commit, ArtifactSHA256: record.Digest,
		QualificationSHA256: content, Cell: bundle.Cell, Environment: record.Environment,
		Runtime: release.ProductionRuntime, Architecture: bundle.Architecture, Role: record.Role}, nil
}

func (c command) serviceApply(args []string) error {
	return c.serviceApplyWith(args, deployEnv{storage: operatorObjectStorage})
}

// serviceApplyWith consumes only retained signed artifacts and existing public trust.
func (c command) serviceApplyWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("service-apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "signed bundle: CELL/service.json and binaries/SHA256")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM outside the bundle")
	namespace := flags.String("namespace", "", "Object Storage namespace of regional head buckets")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *rootPath == "" || !validStorageToken(*namespace) || flags.NArg() != 0 {
		return errors.New("service-apply requires --dir, --root-key and --namespace")
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
		bundle serviceBundle
		record delivery.ArtifactRecord
	}
	var targets []target
	inspected := make(map[string]binaryReceipt)
	var source delivery.ArtifactSource
	var role string
	var sequence uint64
	// Reject tampered local inputs before constructing any regional client.
	for _, entry := range entries {
		if !entry.IsDir() || !validRegion(entry.Name()) {
			continue
		}
		wire, err := readBoundedRegular(filepath.Join(*directory, entry.Name(), "service.json"), releasechannel.MaxChannelBytes)
		if err != nil {
			return err
		}
		var bundle serviceBundle
		if err := protocol.DecodeStrict(wire, &bundle, releasechannel.MaxChannelBytes); err != nil {
			return err
		}
		record, err := bundle.verify(c.ctx, roots, entry.Name(), time.Now().UTC())
		if err != nil {
			return fmt.Errorf("%s signed service bundle: %w", entry.Name(), err)
		}
		if role == "" {
			role, source, sequence = record.Role, record.Source, record.ReleaseSequence
		}
		if role != record.Role || source != record.Source || sequence != record.ReleaseSequence {
			return errors.New("service bundle mixes roles, source identities or release sequences")
		}
		binary, found := inspected[record.Digest]
		if !found {
			binary, err = c.inspectBinary(filepath.Join(*directory, "binaries", record.Digest), defaultGoVersion, record.Source.Commit)
			if err != nil {
				return err
			}
			inspected[record.Digest] = binary
		}
		if binary.SHA256 != record.Digest || binary.Bytes != record.Size || binary.GOARCH != bundle.Architecture {
			return errors.New("service executable differs from signed bytes or architecture")
		}
		targets = append(targets, target{bundle, record})
	}
	if len(targets) == 0 {
		return errors.New("service bundle contains no regions")
	}
	budget := rollout.ObservationBudget
	if env.timeout > 0 {
		budget = min(budget, env.timeout)
	}
	progress := &deploymentWriter{Writer: c.output}
	failures := make([]error, len(targets))
	var regions errgroup.Group
	regions.SetLimit(4)
	for index, target := range targets {
		regions.Go(func() error {
			deadline := time.Now().UTC().Add(budget)
			ctx, cancel := context.WithDeadline(c.ctx, deadline)
			defer cancel()
			regional := c
			regional.ctx = ctx
			apply := func() error {
				bundle, record := target.bundle, target.record
				candidate, err := serviceProductionCandidate(bundle, record)
				if err != nil {
					return err
				}
				if err := regional.verifyProductionCandidate(filepath.Join(*directory, "production"), roots, candidate, deadline); err != nil {
					return err
				}
				location, err := channelLocation(env, bundle.Cell, *namespace)
				if err != nil {
					return err
				}
				scope, err := deploymentScope(ctx, location, bundle.Cell)
				if err != nil {
					return err
				}
				if scope.Environment != record.Environment || !slices.Contains(scope.Architectures, bundle.Architecture) {
					return errors.New("service bundle differs from admitted regional scope")
				}
				if err := verifyServiceSequence(bundle, record, roots, deadline); err != nil {
					return err
				}
				if _, _, _, err := release.VerifyReleaseDelegationCurrent(bundle.Delegation, roots, bundle.Environment, deadline); err != nil {
					return err
				}
				if _, err := bundle.verify(ctx, roots, bundle.Cell, time.Now().UTC()); err != nil {
					return err
				}
				var envelope protocol.Envelope
				if err := protocol.DecodeStrict(bundle.Claim, &envelope, delivery.MaxArtifactClaimBytes); err != nil {
					return err
				}
				if !time.Now().Before(envelope.ExpiresAt) {
					current, found, err := releasechannel.ReadServiceClaim(ctx, location, role)
					if err != nil {
						return err
					}
					status, observed, err := releasechannel.ReadServiceStatus(ctx, location, role)
					if err != nil {
						return err
					}
					if found && observed && bytes.Equal(current, bundle.Claim) && status.Schema == releasechannel.ServiceStatusSchema && status.Cell == bundle.Cell && status.Role == role && status.Digest == record.Digest && status.IssuedAt.Equal(envelope.IssuedAt) && status.State == releasechannel.StateComplete && status.ReleaseSequence == record.ReleaseSequence {
						fmt.Fprintf(progress, "%s %s already complete: %s\n", bundle.Cell, role, record.Digest)
						return nil
					}
					return fmt.Errorf("%w: fresh service admission requires an unexpired claim", protocol.ErrExpired)
				}
				if original := envelope.IssuedAt.Add(rollout.ObservationBudget); original.Before(deadline) {
					deadline = original
				}
				file, size, digest, err := regional.openHashedArtifact(filepath.Join(*directory, "binaries", record.Digest), releasechannel.MaxServiceBinaryBytes)
				if err != nil {
					return err
				}
				defer file.Close()
				if size != record.Size || hex.EncodeToString(digest) != record.Digest {
					return errors.New("service executable changed after bundle verification")
				}
				if err := regional.uploadServiceQualification(filepath.Join(*directory, "production"), location, roots, candidate, record.ProductionQualificationSHA256, deadline); err != nil {
					return err
				}
				if err := putImmutable(ctx, location.Client, location.Namespace, location.Bucket,
					releasechannel.ServiceBinaryObject(role, record.Digest), file, size, digest); err != nil {
					return err
				}
				migration, err := trust.DecodeEnvelope(bundle.Migration)
				if err != nil {
					return err
				}
				if err := releasechannel.PublishServiceSequenced(ctx, location, role, bundle.Claim, migration, roots, time.Now().UTC()); err != nil {
					return err
				}
				issued, err := releasechannel.ClaimIssuedAt(bundle.Claim)
				if err != nil {
					return err
				}
				fmt.Fprintf(progress, "%s %s published signed service %s\n", bundle.Cell, role, record.Digest)
				return releasechannel.AwaitServiceSequenced(ctx, location, bundle.Cell, role, record.Digest, issued, record.ReleaseSequence,
					5*time.Second, deadline, progress)
			}
			if err := apply(); err != nil {
				failures[index] = fmt.Errorf("%s %s: %w", target.bundle.Cell, role, err)
				fmt.Fprintf(progress, "%s %s failed: %v\n", target.bundle.Cell, role, err)
			}
			return nil
		})
	}
	_ = regions.Wait()
	return errors.Join(failures...)
}

func verifyServiceSequence(bundle serviceBundle, record delivery.ArtifactRecord, roots trust.Keyring, now time.Time) error {
	envelope, err := trust.DecodeEnvelope(bundle.Migration)
	if err != nil {
		return err
	}
	migration, err := release.VerifySequenceMigrationCurrent(envelope, roots, record.Role, record.Environment, now)
	if err != nil {
		return err
	}
	digest, err := trust.Fingerprint(envelope)
	if err != nil {
		return err
	}
	var claim protocol.Envelope
	if err := protocol.DecodeStrict(bundle.Claim, &claim, delivery.MaxArtifactClaimBytes); err != nil {
		return err
	}
	if claim.IssuedAt.Before(envelope.IssuedAt) || claim.ExpiresAt.After(envelope.ExpiresAt) || claim.KeyID != migration.SignerKeyID || record.ReleaseSequence <= migration.SequenceFloor || record.SequenceMigrationSHA256 != digest {
		return errors.New("service claim differs from its signed sequence migration")
	}
	return nil
}
