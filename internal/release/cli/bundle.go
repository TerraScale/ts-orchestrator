package cli

import (
	"context"
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
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/commandio"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) bundle(args []string) error {
	return c.bundleWith(args, deployEnv{check: c.verifyGitHubQualification, inspect: c.inspectBinary, git: runGit,
		storage: operatorObjectStorage, secret: readVaultSecret, discover: discoverServingCells})
}

// bundleWith retains all consumer inputs locally; only the canonical signer
// sequence store is written. Regional publication belongs to apply.
func (c command) bundleWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "retained qualified binaries and qualification.json")
	output := flags.String("out", "", "new signed bundle directory; never overwritten")
	evidenceDir := flags.String("production-evidence-dir", "", "retained production evidence; default DIR/production")
	revision := flags.String("source-revision", "", "expected exact Git revision")
	delegationPath := flags.String("update-delegation", "", "root-signed update delegation")
	delegationSecret := flags.String("update-delegation-secret", "", "Vault update delegation secret")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM")
	keyPath := flags.String("signing-key", "", "owner-only update leaf private key PEM")
	keySecret := flags.String("signing-key-secret", "", "Vault update leaf secret")
	vaultID := flags.String("vault-id", "", "Vault containing the signing inputs")
	checkout := flags.String("source-checkout", "", "producer checkout used to prove lineage")
	namespace := flags.String("namespace", "", "Object Storage namespace")
	migrationPath := flags.String("sequence-migration", "", "root-signed canonical signer sequence migration")
	environment := flags.String("environment", "", "target environment; default signed migration environment")
	var cells, architectures stringList
	flags.Var(&cells, "cell", "target region; repeatable; default every serving region")
	flags.Var(&architectures, "arch", "target architecture; repeatable; default regional scope")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *output == "" || !release.ValidSourceRevision(*revision) || *rootPath == "" || *checkout == "" ||
		*migrationPath == "" || !validStorageToken(*namespace) || (*delegationPath == "") == (*delegationSecret == "") ||
		(*keyPath == "") == (*keySecret == "") || (*keySecret == "" && *delegationSecret == "") != (*vaultID == "") ||
		*environment != "" && !validEnvironment(*environment) || flags.NArg() != 0 {
		return errors.New("bundle requires --dir, --out, --source-revision, --root-key, --source-checkout, --namespace, --sequence-migration, an update delegation and a signing key; Vault secrets require --vault-id")
	}
	for i, architecture := range architectures {
		if !slices.Contains([]string{"amd64", "arm64"}, architecture) || slices.Contains(architectures[:i], architecture) {
			return errors.New("unsupported or duplicate architecture")
		}
	}
	if _, err := os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bundle output must not exist: %s", *output)
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	migrationEnvelope, err := readEnvelope(*migrationPath)
	if err != nil {
		return err
	}
	if *environment == "" {
		*environment = migrationEnvelope.Scope.Environment
	}
	migration, err := release.VerifySequenceMigrationHistorical(migrationEnvelope, roots, "orchestrator", *environment)
	if err != nil {
		return err
	}
	if migration.Namespace != *namespace {
		return errors.New("sequence migration names another namespace")
	}
	migrationWire, err := trust.EncodeEnvelope(migrationEnvelope)
	if err != nil {
		return err
	}
	migrationDigest, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		return err
	}
	qualificationWire, err := readBoundedRegular(filepath.Join(*directory, "qualification.json"), release.MaxQualificationBytes)
	if err != nil {
		return err
	}
	qualification, digest, err := release.DecodeQualification(qualificationWire)
	if err != nil {
		return err
	}
	if qualification.SourceRevision != *revision {
		return errors.New("qualification names another source revision")
	}
	if err := env.check(qualification, digest); err != nil {
		return err
	}
	cells, err = deploymentCells(c.ctx, cells, env.discover)
	if err != nil {
		return err
	}
	if *evidenceDir == "" {
		*evidenceDir = filepath.Join(*directory, "production")
	}
	stage, err := os.MkdirTemp(filepath.Dir(*output), ".release-bundle-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Mkdir(filepath.Join(stage, "binaries"), 0o700); err != nil {
		return err
	}
	if err := c.writeNew(filepath.Join(stage, "qualification.json"), qualificationWire, 0o600); err != nil {
		return err
	}
	// Inspect immutable staged bytes once, before any regional admission or key read.
	binaries := make(map[string]binaryReceipt)
	for _, artifact := range qualification.Artifacts {
		if len(architectures) > 0 && !slices.Contains(architectures, artifact.Architecture) {
			continue
		}
		path := filepath.Join(stage, "binaries", artifact.SHA256)
		if err := c.copyBundleArtifact(binaryPath(*directory, artifact.Architecture), path, artifact.SHA256, artifact.Bytes, maxArtifactBytes); err != nil {
			return err
		}
		binary, err := env.inspect(path, qualification.GoVersion, *revision)
		if err != nil {
			return err
		}
		binary.QualificationSHA256 = digest
		if err := qualification.MatchBinary(binary, digest); err != nil {
			return err
		}
		if binary.GOARCH != artifact.Architecture {
			return errors.New("qualified binary architecture differs from retained artifact")
		}
		binaries[binary.GOARCH] = binary
	}
	var private ed25519.PrivateKey
	defer func() { clear(private) }()
	// No signing credential is accessed until a region's retained proofs pass.
	type signingInputs struct {
		delegation trust.Envelope
		wire       []byte
		sequence   uint64
	}
	credentials := sync.OnceValues(func() (signingInputs, error) {
		signerCtx, cancel := context.WithTimeout(c.ctx, rollout.QualificationBudget)
		defer cancel()
		delegation, err := bundleDelegation(signerCtx, *delegationPath, *delegationSecret, *vaultID, env)
		if err != nil {
			return signingInputs{}, err
		}
		wire, err := trust.EncodeEnvelope(delegation)
		if err != nil {
			return signingInputs{}, err
		}
		if *keyPath != "" {
			private, err = readDelegatedPrivateKey(*keyPath)
		} else {
			var data []byte
			data, err = env.secret(signerCtx, *vaultID, *keySecret)
			if err == nil {
				private, err = parseDelegatedPrivateKey(data)
			}
			clear(data)
		}
		if err != nil {
			return signingInputs{}, err
		}
		client, err := env.storage(migration.Region)
		if err != nil {
			return signingInputs{}, err
		}
		location := release.SequenceLocation{Client: client, Namespace: migration.Namespace, Bucket: migration.Bucket}
		if err := location.ImportMigration(signerCtx, migrationEnvelope, roots, "orchestrator", *environment, time.Now().UTC()); err != nil {
			return signingInputs{}, err
		}
		sequence, err := location.Allocate(signerCtx, release.SequenceIdentity{Role: "orchestrator", Environment: *environment,
			SourceRevision: *revision, ManifestSHA256: digest}, roots, private)
		return signingInputs{delegation, wire, sequence}, err
	})
	lineage := &deploymentLineage{checker: gitLineage{ctx: c.ctx, checkout: *checkout, run: env.git}, results: make(map[[3]string]error)}
	progress := &deploymentWriter{Writer: c.output}
	failures := make([]error, len(cells))
	completed := make([]bool, len(cells))
	var snapshot sync.Mutex
	budget := rollout.ObservationBudget
	if env.timeout > 0 {
		budget = min(budget, env.timeout)
	}
	var regions errgroup.Group
	regions.SetLimit(4)
	for index, cell := range cells {
		regions.Go(func() error {
			ctx, cancel := context.WithTimeout(c.ctx, budget)
			defer cancel()
			regional := c
			regional.ctx = ctx
			produce := func() error {
				targetArchitectures := []string(architectures)
				if len(targetArchitectures) == 0 {
					location, err := channelLocation(env, cell, *namespace)
					if err != nil {
						return err
					}
					scope, err := deploymentScope(ctx, location, cell)
					if err != nil {
						return err
					}
					if scope.Environment != *environment {
						return errors.New("regional environment differs from signed migration")
					}
					targetArchitectures = scope.Architectures
				}
				targetBinaries := make(map[string]binaryReceipt, len(targetArchitectures))
				for _, architecture := range targetArchitectures {
					binary, found := binaries[architecture]
					if !found {
						return fmt.Errorf("no qualified %s binary", architecture)
					}
					targetBinaries[architecture] = binary
				}
				// Snapshot only authenticated evidence, then admit the exact retained copy.
				snapshot.Lock()
				err := regional.snapshotBundleProduction(*evidenceDir, filepath.Join(stage, "production"), roots, cell, *environment, targetBinaries)
				snapshot.Unlock()
				if err != nil {
					return err
				}
				deadline := time.Now().UTC().Add(rollout.ObservationBudget)
				if err := regional.verifyProductionArtifacts(filepath.Join(stage, "production"), roots, cell, *environment, targetBinaries, deadline); err != nil {
					return err
				}
				inputs, err := credentials()
				if err != nil {
					return err
				}
				now := time.Now().UTC()
				channel := releasechannel.Channel{Schema: releasechannel.ChannelSchema, Cell: cell, Environment: *environment,
					SourceRevision: *revision, RunNumber: qualification.Verification.RunNumber, Delegation: inputs.wire,
					ReleaseSequence: inputs.sequence, SequenceMigration: migrationWire}
				for _, architecture := range targetArchitectures {
					envelope, err := release.SignBinaryUpdateReceiptSequenced(targetBinaries[architecture], qualification, digest,
						cell, *environment, lineage, inputs.delegation, roots, private, now, 7*24*time.Hour, inputs.sequence, migrationDigest)
					if err != nil {
						return err
					}
					proof, err := readProductionProof(filepath.Join(stage, "production"), cell, architecture)
					if err != nil {
						return err
					}
					envelope, err = release.AttachProductionQualification(envelope, proof, inputs.wire, roots, private,
						release.UpdateExpectation{Environment: *environment, Cell: cell, Architecture: architecture}, now)
					if err != nil {
						return err
					}
					wire, err := trust.EncodeEnvelope(envelope)
					if err != nil {
						return err
					}
					channel.Receipts = append(channel.Receipts, wire)
				}
				if _, err := channel.Verify(roots, cell, *environment, deadline); err != nil {
					return err
				}
				wire, err := json.Marshal(channel, json.Deterministic(true))
				if err != nil {
					return err
				}
				if err := os.Mkdir(filepath.Join(stage, cell), 0o700); err != nil {
					return err
				}
				if err := regional.writeNew(filepath.Join(stage, cell, "channel.json"), wire, 0o600); err != nil {
					return err
				}
				completed[index] = true
				fmt.Fprintf(progress, "%s bundled signed release %d %s\n", cell, inputs.sequence, *revision)
				return nil
			}
			if err := produce(); err != nil {
				failures[index] = fmt.Errorf("%s: %w", cell, err)
				fmt.Fprintf(progress, "%s bundle refused: %v\n", cell, err)
			}
			return nil
		})
	}
	_ = regions.Wait()
	if !slices.Contains(completed, true) {
		return errors.Join(failures...)
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := syncBundleDirectories(stage); err != nil {
		return err
	}
	// RENAME_NOREPLACE publishes the entire directory atomically without a
	// check/rename race that could overwrite another producer's bundle.
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, *output, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish new bundle: %w", err)
	}
	if err := syncBundleDirectory(filepath.Dir(*output)); err != nil {
		return err
	}
	fmt.Fprintf(progress, "signed bundle retained: %s\n", *output)
	return errors.Join(failures...)
}

func bundleDelegation(ctx context.Context, path, secret, vaultID string, env deployEnv) (trust.Envelope, error) {
	if path != "" {
		return readEnvelope(path)
	}
	data, err := env.secret(ctx, vaultID, secret)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.DecodeEnvelope(data)
}

func (c command) copyBundleArtifact(source, destination, digest string, size, maximum int64) error {
	if size <= 0 || size > maximum {
		return errors.New("bundle artifact size exceeds its bound")
	}
	input, err := openRegular(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer output.Close()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, hash), commandio.Reader(c.ctx, io.LimitReader(input, size+1)))
	if err != nil {
		return err
	}
	if count != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("retained artifact bytes differ from qualification")
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	return output.Close()
}

func (c command) snapshotBundleProduction(source, destination string, roots trust.Keyring, cell, environment string, binaries map[string]binaryReceipt) error {
	for architecture, binary := range binaries {
		proof, err := readProductionProof(source, cell, architecture)
		if err != nil {
			return fmt.Errorf("%w: %s %s record: %w", release.ErrProductionQualification, cell, architecture, err)
		}
		expected := release.ProductionExpectation{SourceRevision: binary.SourceRevision, ArtifactSHA256: binary.SHA256,
			QualificationSHA256: binary.QualificationSHA256, Cell: cell, Environment: environment,
			Runtime: release.ProductionRuntime, Architecture: architecture, Role: "orchestrator"}
		record, err := release.VerifyProductionCurrent(proof.Qualification, proof.Delegation, roots, expected, time.Now().UTC())
		if err != nil {
			return err
		}
		directory := filepath.Join(destination, cell, architecture)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := c.writeNew(filepath.Join(directory, "production.json"), proof.Qualification, 0o600); err != nil {
			return err
		}
		if len(proof.Delegation) > 0 {
			if err := c.writeNew(filepath.Join(directory, "delegation.json"), proof.Delegation, 0o600); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Join(destination, "objects"), 0o700); err != nil {
			return err
		}
		for _, evidence := range record.Evidence {
			path := filepath.Join(destination, "objects", evidence.SHA256)
			if _, err := os.Lstat(path); err == nil {
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := c.copyBundleArtifact(filepath.Join(source, "objects", evidence.SHA256), path, evidence.SHA256, evidence.Bytes, release.MaxProductionEvidenceBytes); err != nil {
				return fmt.Errorf("%w: %s %s evidence: %w", release.ErrProductionQualification, cell, evidence.Gate, err)
			}
		}
	}
	return nil
}

func syncBundleDirectories(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if err := syncBundleDirectories(filepath.Join(directory, entry.Name())); err != nil {
				return err
			}
		}
	}
	return syncBundleDirectory(directory)
}

func syncBundleDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
