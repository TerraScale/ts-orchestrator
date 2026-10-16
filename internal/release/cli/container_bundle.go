package cli

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) containerBundle(args []string) error {
	return c.containerBundleWith(args, deployEnv{secret: readVaultSecret, discover: discoverServingCells, storage: operatorObjectStorage})
}

// containerBundleWith consumes standard OCI Image Layout bytes, never native
// tar/binary hashes. Independent qualification precedes access to the online key.
func (c command) containerBundleWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("container-bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "output signed container bundle")
	layout := flags.String("oci-layout", "", "retained standard OCI Image Layout directory")
	image := flags.String("image", "", "canonical repository@sha256:root from CI")
	role := flags.String("role", "", "first-party service role")
	repository := flags.String("repository", "", "HTTPS source repository")
	commit := flags.String("commit", "", "exact source revision")
	checkout := flags.String("source-checkout", "", "checkout proving exact source tree")
	environment := flags.String("environment", "", "admitted environment")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM")
	delegationPath := flags.String("delegation", "", "root-signed OCI release delegation")
	migrationPath := flags.String("sequence-migration", "", "root-signed signer sequence migration")
	evidenceDir := flags.String("production-evidence-dir", "", "retained independent production evidence")
	keyPath := flags.String("signing-key", "", "owner-only delegated Ed25519 private key PEM")
	keySecret := flags.String("signing-key-secret", "", "existing OCI Vault signing secret")
	vaultID := flags.String("vault-id", "", "existing OCI Vault")
	var cells, architectures stringList
	flags.Var(&cells, "cell", "target cell; default every discovered serving cell")
	flags.Var(&architectures, "arch", "target architecture; default both Linux architectures")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *layout == "" || *image == "" || *role == "" || *repository == "" || !release.ValidSourceRevision(*commit) || *checkout == "" || !validEnvironment(*environment) || *rootPath == "" || *delegationPath == "" || *migrationPath == "" || *evidenceDir == "" || (*keyPath == "") == (*keySecret == "") || (*keySecret == "") != (*vaultID == "") || flags.NArg() != 0 {
		return errors.New("container-bundle requires --dir, --oci-layout, --image, --role, --repository, --commit, --source-checkout, --environment, --root-key, --delegation, --sequence-migration, --production-evidence-dir and one signing key source")
	}
	cells, err := deploymentCells(c.ctx, cells, env.discover)
	if err != nil {
		return err
	}
	if len(architectures) == 0 {
		architectures = []string{"amd64", "arm64"}
	}
	slices.Sort(cells)
	slices.Sort(architectures)
	for index, architecture := range architectures {
		if !slices.Contains([]string{"amd64", "arm64"}, architecture) || index > 0 && architectures[index-1] == architecture {
			return errors.New("unsupported or duplicate OCI architecture")
		}
	}
	tree, err := release.SourceTreeDigest(c.ctx, *checkout, *commit)
	if err != nil {
		return err
	}
	// The existing source validator enforces an HTTPS repository and exact tree.
	source := containerSource{Repository: *repository, Commit: *commit, TreeDigest: tree}
	if err := validateContainerSource(source); err != nil {
		return err
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	delegationWire, err := readBoundedRegular(*delegationPath, trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	grant, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	deadline := now.Add(rollout.ObservationBudget)
	delegation, err := trust.VerifyDelegationCurrent(grant, roots, deadline, trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime})
	if err != nil {
		return err
	}
	migrationWire, err := readBoundedRegular(*migrationPath, trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	migrationEnvelope, err := trust.DecodeEnvelope(migrationWire)
	if err != nil {
		return err
	}
	migration, err := release.VerifySequenceMigrationHistorical(migrationEnvelope, roots, *role, *environment)
	if err != nil {
		return err
	}
	migrationSHA, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		return err
	}
	type candidate struct {
		claim  release.ContainerClaim
		bundle release.ContainerBundle
	}
	targets := make([]candidate, 0, len(cells)*len(architectures))
	for _, architecture := range architectures {
		inspected, err := release.InspectContainerImageLayout(c.ctx, *layout, *image, architecture)
		if err != nil {
			return err
		}
		qualification := inspected.IndexSHA256
		if qualification == "" {
			qualification = inspected.ManifestSHA256
		}
		for _, cell := range cells {
			claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: inspected.Image, SourceRevision: *commit, SourceRepository: *repository, SourceTreeSHA256: tree, Cell: cell, Environment: *environment, Role: *role, Architecture: architecture, QualificationSHA256: qualification}
			scope := release.ContainerScope(release.ContainerTarget{Cell: cell, Environment: *environment, Role: *role, Architecture: architecture})
			if !containerDelegationAllows(delegation, scope) {
				return errors.New("OCI candidate exceeds its root signing capability")
			}
			expected := release.ProductionExpectation{SourceRevision: *commit, ArtifactSHA256: inspected.ManifestSHA256, QualificationSHA256: qualification, Cell: cell, Environment: *environment, Runtime: release.ProductionRuntime, Architecture: architecture, Role: *role}
			if err := c.verifyProductionCandidate(*evidenceDir, roots, expected, deadline); err != nil {
				return err
			}
			claim.Production, err = readProductionProof(*evidenceDir, cell, architecture)
			if err != nil {
				return err
			}
			targets = append(targets, candidate{claim: claim, bundle: release.ContainerBundle{Delegation: delegationWire, Migration: migrationWire}})
		}
	}
	var private ed25519.PrivateKey
	if *keyPath != "" {
		private, err = readDelegatedPrivateKey(*keyPath)
	} else {
		var data []byte
		data, err = env.secret(c.ctx, *vaultID, *keySecret)
		if err == nil {
			private, err = parseDelegatedPrivateKey(data)
		}
		clear(data)
	}
	if err != nil {
		return err
	}
	defer clear(private)
	signerID, err := trust.KeyID(private.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	if signerID != delegation.SubjectKeyID() || signerID != migration.SignerKeyID {
		return trust.ErrKeyMismatch
	}
	deadline = time.Now().UTC().Add(rollout.ObservationBudget)
	if _, err := trust.VerifyDelegationCurrent(grant, roots, deadline, trust.Policy{MaxLifetime: release.MaxUpdateReceiptLifetime}); err != nil {
		return err
	}
	for _, target := range targets {
		_, child, _ := strings.Cut(target.claim.Image, "@sha256:")
		expected := release.ProductionExpectation{SourceRevision: target.claim.SourceRevision, ArtifactSHA256: child, QualificationSHA256: target.claim.QualificationSHA256, Cell: target.claim.Cell, Environment: target.claim.Environment, Runtime: release.ProductionRuntime, Architecture: target.claim.Architecture, Role: target.claim.Role}
		if err := c.verifyProductionCandidate(*evidenceDir, roots, expected, deadline); err != nil {
			return err
		}
	}
	client, err := env.storage(migration.Region)
	if err != nil {
		return err
	}
	location := release.SequenceLocation{Client: client, Namespace: migration.Namespace, Bucket: migration.Bucket}
	if err := location.ImportMigration(c.ctx, migrationEnvelope, roots, *role, *environment, now); err != nil {
		return err
	}
	family, err := targets[0].claim.WorkerFamilyDigest()
	if err != nil {
		return err
	}
	for _, target := range targets[1:] {
		candidate, err := target.claim.WorkerFamilyDigest()
		if err != nil {
			return err
		}
		if candidate != family {
			return errors.New("container targets do not share one source and OCI index family")
		}
	}
	sequence, reservation, err := location.AllocateWithEvidence(c.ctx, release.SequenceIdentity{Role: *role, Environment: *environment, SourceRevision: *commit, ManifestSHA256: family}, roots, private)
	if err != nil {
		return err
	}
	issued := time.Now().UTC()
	expires := grant.ExpiresAt
	if !deadline.Before(expires) {
		return errors.New("container delegation expires before operation deadline")
	}
	for index := range targets {
		target := &targets[index]
		target.bundle.Sequence = slices.Clone(reservation)
		target.claim.ReleaseSequence = sequence
		target.claim.SequenceMigrationSHA256 = migrationSHA
		payload, err := trust.EncodePayload(target.claim)
		if err != nil {
			return err
		}
		scope := release.ContainerTarget{Cell: target.claim.Cell, Environment: *environment, Role: *role, Architecture: target.claim.Architecture}
		envelope, err := trust.Sign(payload, release.ContainerScope(scope), issued, expires, private)
		if err != nil {
			return err
		}
		target.bundle.Claim, err = trust.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		if _, err := release.VerifyContainerCurrent(c.ctx, target.bundle, roots, scope, issued, deadline, containerEvidenceReader(*evidenceDir), location); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(*directory, 0o700); err != nil {
		return err
	}
	for _, target := range targets {
		destination := filepath.Join(*directory, target.claim.Cell, target.claim.Architecture)
		if err := os.MkdirAll(destination, 0o700); err != nil {
			return err
		}
		wire, err := json.Marshal(target.bundle, json.Deterministic(true))
		if err != nil {
			return err
		}
		if len(wire) > releasechannel.MaxContainerBundleBytes {
			return errors.New("signed OCI bundle exceeds durable intent bound")
		}
		if err := c.writeNew(filepath.Join(destination, "container.json"), wire, 0o600); err != nil {
			return err
		}
	}
	if filepath.Clean(*evidenceDir) != filepath.Join(filepath.Clean(*directory), "production") {
		if err := os.CopyFS(filepath.Join(*directory, "production"), os.DirFS(*evidenceDir)); err != nil {
			return fmt.Errorf("retain container evidence: %w", err)
		}
	}
	if filepath.Clean(*layout) != filepath.Join(filepath.Clean(*directory), "oci-layout") {
		if err := os.CopyFS(filepath.Join(*directory, "oci-layout"), os.DirFS(*layout)); err != nil {
			return fmt.Errorf("retain standard OCI layout: %w", err)
		}
	}
	_, err = fmt.Fprintf(c.output, "%s signed OCI container bundle: sequence %d %s\n", *role, sequence, *directory)
	return err
}

func containerDelegationAllows(delegation trust.VerifiedDelegation, scope trust.Scope) bool {
	for _, capability := range delegation.Capabilities() {
		if capability.Domain == scope.Domain && capability.DeploymentID == scope.DeploymentID && capability.Cell == scope.Cell && capability.Environment == scope.Environment && capability.Role == scope.Role && slices.Contains(capability.Slots, scope.Slot) && slices.Contains(capability.Actions, "sign") {
			return true
		}
	}
	return false
}
