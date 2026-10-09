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
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// deployEnv holds the deploy command's external boundaries.
type deployEnv struct {
	check   func(release.Qualification, string) error
	inspect func(string, string, string) (binaryReceipt, error)
	git     func(context.Context, ...string) (string, error)
	// storage returns the Object Storage client of a cell's region.
	storage func(cell string) (releasechannel.ObjectClient, error)
	// secret reads one Vault secret.
	secret func(ctx context.Context, vaultID, name string) ([]byte, error)
}

func (c command) deploy(args []string) error {
	return c.deployWith(args, deployEnv{check: c.verifyForgejoQualification, inspect: c.inspectBinary, git: runGit,
		storage: operatorObjectStorage, secret: readVaultSecret})
}

// deployWith signs one CI-qualified release for every cell with the online
// update leaf, then deploys it one cell at a time in the order given, the
// first cell being the canary: it uploads the binaries, publishes the cell's
// release channel and waits until the cell's controllers report the rollout
// complete before the next cell sees the release. A cell that rolls the
// release back, or does not finish in time, stops the fleet rollout and
// fails the command.
func (c command) deployWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("deploy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "retained CI release: qualification.json and terrascale-orchestrator-linux-<arch>")
	sourceRevision := flags.String("source-revision", "", "expected exact Git revision")
	delegationPath := flags.String("update-delegation", "", "root-signed binary update delegation")
	rootPath := flags.String("root-key", "", "root public key PEM")
	keyPath := flags.String("signing-key", "", "owner-only update leaf Ed25519 PKCS#8 private key PEM")
	keySecret := flags.String("signing-key-secret", "", "OCI Vault secret holding the update leaf key, instead of --signing-key")
	vaultID := flags.String("vault-id", "", "OCI Vault of --signing-key-secret")
	environment := flags.String("environment", "", "production or canary")
	checkout := flags.String("source-checkout", "", "repository checkout used to prove lineage")
	namespace := flags.String("namespace", "", "Object Storage namespace of the regions' head buckets")
	validFor := flags.Duration("valid-for", 7*24*time.Hour, "receipt validity, bounded by delegation expiry")
	regionTimeout := flags.Duration("region-timeout", 2*time.Hour, "how long one cell may take to report the rollout complete")
	poll := flags.Duration("poll", 30*time.Second, "how often a cell's status is read")
	var cells, architectures stringList
	flags.Var(&cells, "cell", "cell to deploy to, in order; the first is the canary; repeatable")
	flags.Var(&architectures, "arch", "amd64 or arm64; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || !release.ValidSourceRevision(*sourceRevision) || *delegationPath == "" || *rootPath == "" ||
		(*keyPath == "") == (*keySecret == "") || (*keySecret == "") != (*vaultID == "") ||
		!validEnvironment(*environment) || *checkout == "" || !validStorageToken(*namespace) ||
		len(cells) == 0 || len(architectures) == 0 || *regionTimeout <= 0 || *poll <= 0 || flags.NArg() != 0 {
		return errors.New("deploy requires --dir, --source-revision, --update-delegation, --root-key, --signing-key or --signing-key-secret with --vault-id, --environment, --source-checkout, --namespace, --cell and --arch")
	}
	for _, cell := range cells {
		if !validRegion(cell) {
			return fmt.Errorf("unsupported cell %q", cell)
		}
	}
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
	binaries := map[string]binaryReceipt{}
	for _, architecture := range architectures {
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
	}
	if err := env.check(qualification, qualificationDigest); err != nil {
		return err
	}
	delegation, err := readEnvelope(*delegationPath)
	if err != nil {
		return err
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

	// Sign every cell first, so a cell outside the delegation fails before
	// any region sees the release.
	lineage := gitLineage{ctx: c.ctx, checkout: *checkout, run: env.git}
	channels := make([]releasechannel.Channel, 0, len(cells))
	for _, cell := range cells {
		channel := releasechannel.Channel{Schema: releasechannel.ChannelSchema, Cell: cell, Environment: *environment,
			SourceRevision: *sourceRevision, RunNumber: qualification.Verification.RunNumber, Delegation: delegationWire}
		for _, architecture := range architectures {
			envelope, err := release.SignBinaryUpdateReceipt(binaries[architecture], qualification, qualificationDigest, cell,
				*environment, lineage, delegation, roots, private, time.Now().UTC(), *validFor)
			if err != nil {
				return fmt.Errorf("sign %s %s: %w", cell, architecture, err)
			}
			wire, err := trust.EncodeEnvelope(envelope)
			if err != nil {
				return err
			}
			channel.Receipts = append(channel.Receipts, wire)
		}
		if _, err := channel.Verify(roots, cell, *environment, time.Now().UTC()); err != nil {
			return fmt.Errorf("signed %s channel fails consumer verification: %w", cell, err)
		}
		channels = append(channels, channel)
	}
	clear(private)

	for _, channel := range channels {
		// A region verifies the receipts while it rolls the release out, so
		// they must stay valid for the whole wait, however late it starts.
		if _, err := channel.Verify(roots, channel.Cell, *environment, time.Now().UTC().Add(*regionTimeout)); err != nil {
			return fmt.Errorf("%s receipts would expire during its rollout; renew the update delegation: %w", channel.Cell, err)
		}
		location, err := channelLocation(env, channel.Cell, *namespace)
		if err != nil {
			return err
		}
		for _, architecture := range architectures {
			if err := c.uploadBinary(location, binaryPath(*directory, architecture), binaries[architecture].SHA256); err != nil {
				return fmt.Errorf("upload the %s binary to %s: %w", architecture, channel.Cell, err)
			}
		}
		if err := releasechannel.Publish(c.ctx, location, channel); err != nil {
			return fmt.Errorf("publish to %s: %w", channel.Cell, err)
		}
		fmt.Fprintf(c.output, "%s published: run %d %s\n", channel.Cell, channel.RunNumber, channel.SourceRevision)
		if err := releasechannel.Await(c.ctx, location, channel, *poll, time.Now().Add(*regionTimeout), c.output); err != nil {
			return fmt.Errorf("fleet rollout stopped: %w", err)
		}
	}
	_, err = fmt.Fprintf(c.output, "fleet complete: run %d %s in %s\n", qualification.Verification.RunNumber,
		*sourceRevision, strings.Join(cells, " "))
	return err
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
	return c.fleetStatusWith(args, operatorObjectStorage)
}

// fleetStatusWith prints one JSON line per cell: the release in its channel
// and the status its leader reports, or with --role each named service
// role's status instead. It fails if any cell cannot be read.
func (c command) fleetStatusWith(args []string, storage func(string) (releasechannel.ObjectClient, error)) error {
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
	if len(cells) == 0 {
		cells = catalog.Cells()
	}
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
			location, err := channelLocation(deployEnv{storage: storage}, cell, *namespace)
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
