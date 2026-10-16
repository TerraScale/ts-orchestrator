package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) serviceBundle(args []string) error {
	return c.serviceBundleWith(args, deployEnv{secret: readVaultSecret, discover: discoverServingCells, storage: operatorObjectStorage})
}

// serviceBundleWith is the source-aware producer; apply never calls it.
func (c command) serviceBundleWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("service-bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "output bundle including prequalified production/CELL/ARCH evidence")
	binaryPath := flags.String("binary", "", "CI-built static service executable")
	role := flags.String("role", "", "native service role")
	repository := flags.String("repository", "", "authorized HTTPS source repository")
	commit := flags.String("commit", "", "exact source revision")
	checkout := flags.String("source-checkout", "", "checkout used to verify the source tree")
	environment := flags.String("environment", "", "admitted target environment")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM")
	delegationPath := flags.String("update-delegation", "", "root-signed service release delegation")
	migrationPath := flags.String("sequence-migration", "", "root-signed signer-sequence migration")

	evidenceDir := flags.String("production-evidence-dir", "", "retained production qualification; default DIR/production")
	keyPath := flags.String("signing-key", "", "owner-only delegated Ed25519 PKCS#8 private key PEM")
	keySecret := flags.String("signing-key-secret", "", "OCI Vault secret holding the delegated key")
	vaultID := flags.String("vault-id", "", "OCI Vault containing the signing key secret")
	var cells stringList
	flags.Var(&cells, "cell", "target cell; repeatable; default every discovered serving cell")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *binaryPath == "" || *role == "" || *repository == "" || !release.ValidSourceRevision(*commit) ||
		*checkout == "" || !validEnvironment(*environment) || *rootPath == "" || *delegationPath == "" ||
		*migrationPath == "" || (*keyPath == "") == (*keySecret == "") ||
		(*keySecret == "") != (*vaultID == "") || flags.NArg() != 0 {
		return errors.New("service-bundle requires --dir, --binary, --role, --repository, --commit, --source-checkout, --environment, --root-key, --update-delegation, --sequence-migration and one signing key source")
	}
	cells, err := deploymentCells(c.ctx, cells, env.discover)
	if err != nil {
		return err
	}
	binary, err := c.inspectBinary(*binaryPath, defaultGoVersion, *commit)
	if err != nil {
		return err
	}
	tree, err := release.SourceTreeDigest(c.ctx, *checkout, *commit)
	if err != nil {
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
	migrationWire, err := readBoundedRegular(*migrationPath, trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	migrationEnvelope, err := trust.DecodeEnvelope(migrationWire)
	if err != nil {
		return err
	}
	migrationDigest, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		return err
	}
	migration, err := release.VerifySequenceMigrationHistorical(migrationEnvelope, roots, *role, *environment)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	delegation, public, expires, err := release.VerifyReleaseDelegationCurrent(delegationWire, roots, *environment, now.Add(rollout.ObservationBudget))
	if err != nil {
		return err
	}
	if !delegation.MayRelease(*role, *repository) || !slices.Contains(delegation.Architectures, binary.GOARCH) {
		return errors.New("service candidate exceeds its root delegation")
	}
	if *evidenceDir == "" {
		*evidenceDir = filepath.Join(*directory, "production")
	}
	type target struct {
		bundle serviceBundle
		record delivery.ArtifactRecord
	}
	targets := make([]target, 0, len(cells))
	var failures []error
	slices.Sort(cells)
	// Inspect and qualify every exact candidate before reading any signing key.
	for _, cell := range cells {
		record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{
			Source: delivery.ArtifactSource{Repository: *repository, Commit: *commit, TreeDigest: tree},
			Cell:   strings.ToLower(cell), Role: *role, Environment: *environment}, binary.SHA256, binary.Bytes)
		if err != nil {
			return err
		}
		bundle := serviceBundle{Schema: serviceBundleSchema, Cell: cell, Environment: *environment, Role: *role,
			Architecture: binary.GOARCH, Delegation: delegationWire, Migration: migrationWire}
		candidate, err := serviceProductionCandidate(bundle, record)
		if err != nil {
			return err
		}
		if err := c.verifyProductionCandidate(*evidenceDir, roots, candidate, now.Add(rollout.ObservationBudget)); err != nil {
			failures = append(failures, fmt.Errorf("%s %s: %w", cell, *role, err))
			fmt.Fprintf(c.output, "%s %s qualification refused: %v\n", cell, *role, err)
			continue
		}
		qualificationWire, err := readBoundedRegular(filepath.Join(*evidenceDir, cell, binary.GOARCH, "production.json"), trust.MaxEnvelopeBytes)
		if err != nil {
			return err
		}
		qualificationEnvelope, err := trust.DecodeEnvelope(qualificationWire)
		if err != nil {
			return err
		}
		record.ProductionQualificationSHA256, err = trust.Fingerprint(qualificationEnvelope)
		if err != nil {
			return err
		}
		targets = append(targets, target{bundle, record})
	}
	if len(targets) == 0 {
		return errors.Join(failures...)
	}
	var private ed25519.PrivateKey
	if *keyPath != "" {
		private, err = readDelegatedPrivateKey(*keyPath)
	} else {
		var data []byte
		if data, err = env.secret(c.ctx, *vaultID, *keySecret); err == nil {
			private, err = parseDelegatedPrivateKey(data)
			clear(data)
		}
	}
	if err != nil {
		return err
	}
	defer clear(private)
	if !private.Public().(ed25519.PublicKey).Equal(public) {
		return trust.ErrKeyMismatch
	}
	actor, err := release.DelegatedReleaseActor(public)
	if err != nil {
		return err
	}
	sequenceClient, err := env.storage(migration.Region)
	if err != nil {
		return err
	}
	sequenceLocation := release.SequenceLocation{Client: sequenceClient, Namespace: migration.Namespace, Bucket: migration.Bucket}
	if err := sequenceLocation.ImportMigration(c.ctx, migrationEnvelope, roots, *role, *environment, time.Now().UTC()); err != nil {
		return err
	}
	content := sha256.New()
	for _, target := range targets {
		digest, err := target.record.ContentManifestDigest()
		if err != nil {
			return err
		}
		content.Write([]byte(digest))
	}
	sequence, err := sequenceLocation.Allocate(c.ctx, release.SequenceIdentity{Role: *role, Environment: *environment,
		SourceRevision: *commit, ManifestSHA256: hex.EncodeToString(content.Sum(nil))}, roots, private)
	if err != nil {
		return err
	}
	issued := time.Now().UTC()
	if !issued.Add(5 * time.Minute).Before(expires) {
		return errors.New("release delegation expires before service admission")
	}
	for index := range targets {
		target := &targets[index]
		target.record, err = delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Source: target.record.Source, Cell: target.record.Cell,
			Role: *role, Environment: *environment, ReleaseSequence: sequence, SequenceMigrationSHA256: migrationDigest, ProductionQualificationSHA256: target.record.ProductionQualificationSHA256}, binary.SHA256, binary.Bytes)
		if err != nil {
			return err
		}
		codec := delivery.Ed25519Codec{Cell: target.record.Cell, Actor: actor, PrivateKey: private,
			Lifetime: 5 * time.Minute, MaxLifetime: 5 * time.Minute, Now: func() time.Time { return issued }}
		target.bundle.Claim, err = codec.SignArtifact(c.ctx, target.record)
		if err != nil {
			return err
		}
		if _, err := target.bundle.verify(c.ctx, roots, target.bundle.Cell, issued); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(*directory, "binaries"), 0o700); err != nil {
		return err
	}
	file, size, sum, err := c.openHashedArtifact(*binaryPath, release.MaxArtifactBytes)
	if err != nil {
		return err
	}
	defer file.Close()
	if hex.EncodeToString(sum) != binary.SHA256 || size != binary.Bytes {
		return errors.New("service executable changed after qualification")
	}
	outputPath := filepath.Join(*directory, "binaries", binary.SHA256)
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, file)
	closeErr := errors.Join(output.Sync(), output.Close())
	if err := errors.Join(copyErr, closeErr); err != nil {
		os.Remove(outputPath)
		return err
	}
	for _, target := range targets {
		if err := os.MkdirAll(filepath.Join(*directory, target.bundle.Cell), 0o700); err != nil {
			return err
		}
		wire, err := json.Marshal(target.bundle, json.Deterministic(true))
		if err != nil {
			return err
		}
		if err := c.writeNew(filepath.Join(*directory, target.bundle.Cell, "service.json"), wire, 0o600); err != nil {
			return err
		}
	}
	if filepath.Clean(*evidenceDir) != filepath.Join(filepath.Clean(*directory), "production") {
		if err := os.CopyFS(filepath.Join(*directory, "production"), os.DirFS(*evidenceDir)); err != nil {
			return fmt.Errorf("retain production evidence: %w", err)
		}
	}
	_, err = fmt.Fprintf(c.output, "%s signed service bundle: %s %s\n", *role, binary.SHA256, *directory)
	return errors.Join(append(failures, err)...)
}
