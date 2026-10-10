package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// deployEnv holds the deploy command's external boundaries.
type deployEnv struct {
	// timeout shortens the fixed observation budget in tests.
	timeout time.Duration
	check   func(release.Qualification, string) error
	inspect func(string, string, string) (binaryReceipt, error)
	git     func(context.Context, ...string) (string, error)
	// storage returns the Object Storage client of a cell's region.
	storage func(cell string) (releasechannel.ObjectClient, error)
	// secret reads one Vault secret.
	secret   func(ctx context.Context, vaultID, name string) ([]byte, error)
	discover func(context.Context) ([]string, error)
}

func (c command) deploy(args []string) error {
	return c.deployWith(args, deployEnv{check: c.verifyForgejoQualification, inspect: c.inspectBinary, git: runGit,
		storage: operatorObjectStorage, secret: readVaultSecret, discover: discoverServingCells})
}

// deployWith signs and deploys one CI-qualified release independently in
// every cell with the online update leaf. Each cell owns
// its quorum, health gates and rollback. A failed cell fails the command
// after every other started deployment has finished.
func (c command) deployWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("deploy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "retained CI release: qualification.json and terrascale-orchestrator-linux-<arch>")
	sourceRevision := flags.String("source-revision", "", "expected exact Git revision")
	delegationPath := flags.String("update-delegation", "", "root-signed binary update delegation")
	delegationSecret := flags.String("update-delegation-secret", "", "OCI Vault secret holding the root-signed release delegation, instead of --update-delegation")
	rootPath := flags.String("root-key", "", "root public key PEM")
	keyPath := flags.String("signing-key", "", "owner-only update leaf Ed25519 PKCS#8 private key PEM")
	keySecret := flags.String("signing-key-secret", "", "OCI Vault secret holding the update leaf key, instead of --signing-key")
	vaultID := flags.String("vault-id", "", "OCI Vault of --signing-key-secret and --update-delegation-secret")
	environment := flags.String("environment", "", "production or canary; default the region's admitted scope")
	checkout := flags.String("source-checkout", "", "repository checkout used to prove lineage")
	namespace := flags.String("namespace", "", "Object Storage namespace of the regions' head buckets")
	validFor := flags.Duration("valid-for", 7*24*time.Hour, "receipt validity, bounded by delegation expiry")
	poll := flags.Duration("poll", 30*time.Second, "how often a cell's status is read")
	var cells, architectures stringList
	flags.Var(&cells, "cell", "cell to deploy to concurrently; repeatable; default every serving cell")
	flags.Var(&architectures, "arch", "amd64 or arm64; repeatable; default each region's architectures")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || !release.ValidSourceRevision(*sourceRevision) || (*delegationPath == "") == (*delegationSecret == "") || *rootPath == "" ||
		(*keyPath == "") == (*keySecret == "") || (*keySecret == "" && *delegationSecret == "") != (*vaultID == "") ||
		*environment != "" && !validEnvironment(*environment) || *checkout == "" || !validStorageToken(*namespace) ||
		*poll <= 0 || flags.NArg() != 0 {
		return errors.New("deploy requires --dir, --source-revision, --update-delegation or --update-delegation-secret, --root-key, --signing-key or --signing-key-secret, --vault-id with any secret, --source-checkout and --namespace")
	}
	targetCells, err := deploymentCells(c.ctx, cells, env.discover)
	if err != nil {
		return err
	}
	cells = targetCells
	for _, architecture := range architectures {
		if architecture != "amd64" && architecture != "arm64" {
			return fmt.Errorf("unsupported architecture %q", architecture)
		}
	}
	qualification, qualificationDigest, err := readQualification(filepath.Join(*directory, "qualification.json"))
	if err != nil {
		return err
	}
	if qualification.SourceRevision != *sourceRevision {
		return errors.New("qualification names another source revision")
	}
	if err := env.check(qualification, qualificationDigest); err != nil {
		return err
	}
	var delegation trust.Envelope
	if *delegationPath != "" {
		delegation, err = readEnvelope(*delegationPath)
	} else {
		var data []byte
		if data, err = env.secret(c.ctx, *vaultID, *delegationSecret); err == nil {
			delegation, err = trust.DecodeEnvelope(data)
		}
	}
	if err != nil {
		return fmt.Errorf("read the update delegation: %w", err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
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
		return fmt.Errorf("read the update leaf key: %w", err)
	}
	defer clear(private)

	regionTimeout := rollout.ObservationBudget
	if env.timeout > 0 {
		regionTimeout = min(regionTimeout, env.timeout)
	}
	started := time.Now()
	ctx, cancel := context.WithDeadline(c.ctx, started.Add(regionTimeout))
	defer cancel()
	c.ctx = ctx
	lineage := &deploymentLineage{checker: gitLineage{ctx: ctx, checkout: *checkout, run: env.git},
		results: make(map[[3]string]error)}
	progress := &deploymentWriter{Writer: c.output}
	failures := make([]error, len(cells))
	var regions errgroup.Group
	for index, cell := range cells {
		regions.Go(func() (regionErr error) {
			defer func() {
				if regionErr != nil {
					failures[index] = fmt.Errorf("%s: %w", cell, regionErr)
					fmt.Fprintf(progress, "%s failed: %v\n", cell, regionErr)
				}
			}()
			cellStarted := time.Now()
			location, err := channelLocation(env, cell, *namespace)
			if err != nil {
				return err
			}
			cellEnvironment, cellArchitectures := *environment, []string(architectures)
			if cellEnvironment == "" || len(cellArchitectures) == 0 {
				scope, err := deploymentScope(c.ctx, location, cell)
				if err != nil {
					return err
				}
				if cellEnvironment == "" {
					cellEnvironment = scope.Environment
				}
				if len(cellArchitectures) == 0 {
					cellArchitectures = scope.Architectures
				}
			}
			binaries := make(map[string]binaryReceipt, len(cellArchitectures))
			channel := releasechannel.Channel{Schema: releasechannel.ChannelSchema, Cell: cell, Environment: cellEnvironment,
				SourceRevision: *sourceRevision, RunNumber: qualification.Verification.RunNumber, Delegation: delegationWire}
			for _, architecture := range cellArchitectures {
				receipt, err := env.inspect(binaryPath(*directory, architecture), defaultGoVersion, *sourceRevision)
				if err != nil {
					return err
				}
				receipt.QualificationSHA256 = qualificationDigest
				if err := qualification.MatchBinary(receipt, qualificationDigest); err != nil {
					return err
				}
				if receipt.GOARCH != architecture {
					return fmt.Errorf("%s binary is built for %s", architecture, receipt.GOARCH)
				}
				binaries[architecture] = receipt
				envelope, err := release.SignBinaryUpdateReceipt(binaries[architecture], qualification, qualificationDigest, cell,
					cellEnvironment, lineage, delegation, roots, private, started.UTC(), *validFor)
				if err != nil {
					return fmt.Errorf("sign %s: %w", architecture, err)
				}
				wire, err := trust.EncodeEnvelope(envelope)
				if err != nil {
					return err
				}
				channel.Receipts = append(channel.Receipts, wire)
			}
			// Receipts must remain valid through the shared rollout deadline.
			if _, err := channel.Verify(roots, cell, cellEnvironment, started.UTC().Add(regionTimeout)); err != nil {
				return fmt.Errorf("receipts would expire during rollout; renew the update delegation: %w", err)
			}
			for _, architecture := range cellArchitectures {
				if err := c.uploadBinary(location, binaryPath(*directory, architecture), binaries[architecture].SHA256); err != nil {
					return fmt.Errorf("upload the %s binary to %s: %w", architecture, channel.Cell, err)
				}
			}
			if err := releasechannel.Publish(c.ctx, location, channel); err != nil {
				return fmt.Errorf("publish to %s: %w", channel.Cell, err)
			}
			fmt.Fprintf(progress, "%s published: run %d %s\n", channel.Cell, channel.RunNumber, channel.SourceRevision)
			if err := releasechannel.Await(c.ctx, location, channel, *poll, started.Add(regionTimeout), progress); err != nil {
				return err
			}
			fmt.Fprintf(progress, "%s rolled out in %s\n", channel.Cell, time.Since(cellStarted).Round(time.Second))
			return nil
		})
	}
	// Do not cancel a healthy cell's rollout when another cell rolls back.
	_ = regions.Wait()
	if err := errors.Join(failures...); err != nil {
		return fmt.Errorf("fleet rollout failed: %w", err)
	}
	_, err = fmt.Fprintf(c.output, "fleet complete: run %d %s in %s after %s\n", qualification.Verification.RunNumber,
		*sourceRevision, strings.Join(cells, " "), time.Since(started).Round(time.Second))
	return err
}

// Share each lineage proof and serialize fetches so parallel signers cannot
// race Git's ref locks or repeat the same network request per architecture.
type deploymentLineage struct {
	sync.Mutex
	checker release.LineageChecker
	results map[[3]string]error
}

func (lineage *deploymentLineage) CheckLineage(base, revision, ref string) error {
	lineage.Lock()
	defer lineage.Unlock()
	key := [3]string{base, revision, ref}
	if err, found := lineage.results[key]; found {
		return err
	}
	err := lineage.checker.CheckLineage(base, revision, ref)
	lineage.results[key] = err
	return err
}

// deploymentWriter serializes progress from independent regional waits.
type deploymentWriter struct {
	sync.Mutex
	io.Writer
}

func (writer *deploymentWriter) Write(data []byte) (int, error) {
	writer.Lock()
	defer writer.Unlock()
	return writer.Writer.Write(data)
}

func binaryPath(directory, architecture string) string {
	return filepath.Join(directory, "terrascale-orchestrator-linux-"+architecture)
}

// uploadBinary stores the binary under its digest unless the bucket already
// holds exactly those bytes.
func (c command) uploadBinary(location releasechannel.Location, path, sha256 string) error {
	file, size, digest, err := c.openHashedArtifact(path, maxArtifactBytes)
	if err != nil {
		return err
	}
	defer file.Close()
	if hex.EncodeToString(digest) != sha256 {
		return errors.New("binary changed after it was inspected")
	}
	return putImmutable(c.ctx, location.Client, location.Namespace, location.Bucket,
		releasechannel.BinaryObject(sha256), file, size, digest)
}

func channelLocation(env deployEnv, cell, namespace string) (releasechannel.Location, error) {
	bucket, err := releasechannel.BucketName(cell)
	if err != nil {
		return releasechannel.Location{}, err
	}
	client, err := env.storage(cell)
	if err != nil {
		return releasechannel.Location{}, err
	}
	return releasechannel.Location{Client: client, Namespace: namespace, Bucket: bucket}, nil
}

func (c command) fleetStatus(args []string) error {
	return c.fleetStatusWith(args, deployEnv{storage: operatorObjectStorage, discover: discoverServingCells})
}

// fleetStatusWith prints one JSON line per cell: the release in its channel
// and the status its leader reports, or with --role each named service
// role's status instead. It fails if any cell cannot be read.
func (c command) fleetStatusWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("fleet-status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	namespace := flags.String("namespace", "", "Object Storage namespace of the regions' head buckets")
	requirePins := flags.Bool("require-pins", false, "refuse missing statuses or release pins before CI pruning")
	var cells stringList
	flags.Var(&cells, "cell", "cell to show; repeatable; default every cell")
	var roles stringList
	flags.Var(&roles, "role", "service role whose status to show instead of the orchestrator channel; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !validStorageToken(*namespace) || flags.NArg() != 0 {
		return errors.New("fleet-status requires --namespace")
	}
	for _, role := range roles {
		if !validStorageToken(role) {
			return fmt.Errorf("invalid --role %q", role)
		}
	}
	targetCells, err := deploymentCells(c.ctx, cells, env.discover)
	if err != nil {
		return err
	}
	cells = targetCells
	type line struct {
		Cell    string                 `json:"cell"`
		Channel *channelSummary        `json:"channel,omitempty"`
		Status  *releasechannel.Status `json:"status,omitempty"`
		// Services are the --role statuses, in flag order.
		Services []releasechannel.ServiceStatus `json:"services,omitempty"`
		Error    string                         `json:"error,omitempty"`
	}
	var failed []string
	for _, cell := range cells {
		out := line{Cell: cell}
		err := func() error {
			location, err := channelLocation(env, cell, *namespace)
			if err != nil {
				return err
			}
			for _, role := range roles {
				status, found, err := releasechannel.ReadServiceStatus(c.ctx, location, role)
				if err != nil {
					return err
				}
				if found {
					out.Services = append(out.Services, status)
				}
				if *requirePins && (!found || status.Schema != releasechannel.ServiceStatusSchema || status.Cell != cell ||
					status.Role != role || status.Pins == nil) {
					return fmt.Errorf("%s %s has no release pins from its leader", cell, role)
				}
				if *requirePins {
					if err := status.Pins.ValidateFresh(status.UpdatedAt, time.Now().UTC()); err != nil {
						return err
					}
				}
			}
			if len(roles) > 0 {
				return nil
			}
			channel, found, err := releasechannel.ReadChannel(c.ctx, location)
			if err != nil {
				return err
			}
			if found {
				out.Channel = &channelSummary{SourceRevision: channel.SourceRevision, RunNumber: channel.RunNumber}
			}
			status, found, err := releasechannel.ReadStatus(c.ctx, location)
			if found {
				out.Status = &status
			}
			if err == nil && *requirePins && (!found || status.Schema != releasechannel.StatusSchema || status.Cell != cell || status.Pins == nil) {
				return fmt.Errorf("%s has no release pins from its leader", cell)
			}
			if err == nil && *requirePins {
				return status.Pins.ValidateFresh(status.UpdatedAt, time.Now().UTC())
			}
			return err
		}()
		if err != nil {
			out.Error = err.Error()
			failed = append(failed, cell)
		}
		if err := json.MarshalWrite(c.output, out); err != nil {
			return err
		}
		if _, err := io.WriteString(c.output, "\n"); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not read the release status of %s", strings.Join(failed, " "))
	}
	return nil
}

type channelSummary struct {
	SourceRevision string `json:"source_revision"`
	RunNumber      int64  `json:"run_number"`
}

func operatorObjectStorage(cell string) (releasechannel.ObjectClient, error) {
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(cell))
	if err != nil {
		return nil, err
	}
	return factory.ObjectStorage()
}

// readVaultSecret reads a secret with the operator's OCI configuration
// (OCI_CONFIG_FILE in CI) from the Vault's own region.
func readVaultSecret(ctx context.Context, vaultID, name string) ([]byte, error) {
	parts := strings.Split(vaultID, ".")
	if len(parts) < 5 || parts[1] != "vault" || !catalog.IsOCIRegion(parts[3]) {
		return nil, errors.New("--vault-id must be a regional Vault OCID")
	}
	factory, err := ociclient.OperatorConfig(parts[3])
	if err != nil {
		return nil, err
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, err
	}
	value, err := vaultsecret.Read(ctx, bundles, vaultID, name)
	return []byte(value), err
}
