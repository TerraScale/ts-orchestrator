package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
)

func (c command) serviceDeploy(args []string) error {
	return c.serviceDeployWith(args, deployEnv{storage: operatorObjectStorage, secret: readVaultSecret})
}

// serviceDeployWith deploys one CI-built release of a native service role
// (TS-610) to every independent cell concurrently:
// for each cell it signs a delivery artifact claim with the role's scoped
// release key, uploads the binary to the cell's head bucket, publishes the
// claim in the role's release channel and waits until the cell's leader
// reports the role serving it. Failure does not interrupt another cell's
// healthy rollout; the command waits for every cell before returning.
func (c command) serviceDeployWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("service-deploy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	role := flags.String("role", "", "native service role, e.g. terrabase or ts-auth")
	binaryPath := flags.String("binary", "", "the release executable")
	repository := flags.String("repository", "", "HTTPS source repository the cells let the actor release")
	commit := flags.String("commit", "", "source commit SHA")
	checkout := flags.String("source-checkout", "", "checkout containing --commit, for the source tree digest")
	environment := flags.String("environment", "", "production or canary")
	actor := flags.String("actor", "", "the release key's trusted signer actor")
	keyPath := flags.String("signing-key", "", "owner-only Ed25519 PKCS#8 private key PEM of --actor")
	keySecret := flags.String("signing-key-secret", "", "OCI Vault secret holding the key, instead of --signing-key")
	vaultID := flags.String("vault-id", "", "OCI Vault of --signing-key-secret")
	namespace := flags.String("namespace", "", "Object Storage namespace of the regions' head buckets")
	regionTimeout := flags.Duration("region-timeout", 30*time.Minute, "how long one cell may take to report the release")
	poll := flags.Duration("poll", 5*time.Second, "how often a cell's status is read")
	var cells stringList
	flags.Var(&cells, "cell", "cell to deploy to concurrently; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *role == "" || *binaryPath == "" || *repository == "" || !release.ValidSourceRevision(*commit) || *checkout == "" ||
		!validEnvironment(*environment) || *actor == "" || (*keyPath == "") == (*keySecret == "") ||
		(*keySecret == "") != (*vaultID == "") || !validStorageToken(*namespace) || len(cells) == 0 ||
		*regionTimeout <= 0 || *poll <= 0 || flags.NArg() != 0 {
		return errors.New("service-deploy requires --role, --binary, --repository, --commit, --source-checkout, --environment, --actor, --signing-key or --signing-key-secret with --vault-id, --namespace and --cell")
	}
	for _, cell := range cells {
		if !validRegion(cell) {
			return fmt.Errorf("unsupported cell %q", cell)
		}
	}
	file, size, sum, err := c.openHashedArtifact(*binaryPath, releasechannel.MaxServiceBinaryBytes)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := hex.EncodeToString(sum)
	tree, err := release.SourceTreeDigest(c.ctx, *checkout, *commit)
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
		return fmt.Errorf("read the release key: %w", err)
	}
	defer clear(private)
	locations := make([]releasechannel.Location, len(cells))
	for index, cell := range cells {
		locations[index], err = channelLocation(env, cell, *namespace)
		if err != nil {
			return err
		}
	}

	// The elapsed times measure CI green to rolled out (TS-623): the job
	// starts once the tests passed.
	started := time.Now()
	progress := &deploymentWriter{Writer: c.output}
	var regions errgroup.Group
	for index, cell := range cells {
		regions.Go(func() error {
			cellStarted := time.Now()
			// The NATS cell is the lower-case logical cell.
			request := delivery.ArtifactClaimRequest{Source: delivery.ArtifactSource{Repository: *repository, Commit: *commit,
				TreeDigest: tree}, Cell: strings.ToLower(cell), Role: *role, Environment: *environment}
			record, err := delivery.NewArtifactRecord(request, digest, size)
			if err != nil {
				return err
			}
			location := locations[index]
			// ReadAt keeps parallel uploads on the inspected inode with independent offsets.
			if err := putImmutable(c.ctx, location.Client, location.Namespace, location.Bucket,
				releasechannel.ServiceBinaryObject(*role, digest), io.NewSectionReader(file, 0, size), size, sum); err != nil {
				return fmt.Errorf("upload the binary to %s: %w", cell, err)
			}
			// Sign right before publishing: the leader admits a claim only
			// within an hour of its issuance.
			codec := delivery.Ed25519Codec{Cell: request.Cell, Actor: *actor, PrivateKey: private, Lifetime: time.Minute,
				MaxLifetime: 5 * time.Minute}
			claim, err := codec.SignArtifact(c.ctx, record)
			if err != nil {
				return fmt.Errorf("sign the %s claim: %w", cell, err)
			}
			issued, err := releasechannel.ClaimIssuedAt(claim)
			if err != nil {
				return err
			}
			if err := releasechannel.PublishService(c.ctx, location, *role, claim); err != nil {
				return fmt.Errorf("publish to %s: %w", cell, err)
			}
			fmt.Fprintf(progress, "%s %s published: %s %s\n", cell, *role, digest, *commit)
			if err := releasechannel.AwaitService(c.ctx, location, cell, *role, digest, issued, *poll,
				time.Now().Add(*regionTimeout), progress); err != nil {
				fmt.Fprintf(progress, "%s %s failed: %v\n", cell, *role, err)
				return err
			}
			fmt.Fprintf(progress, "%s %s rolled out in %s\n", cell, *role, time.Since(cellStarted).Round(time.Second))
			return nil
		})
	}
	if err := regions.Wait(); err != nil {
		return fmt.Errorf("service rollout failed after %s: %w", time.Since(started).Round(time.Second), err)
	}
	_, err = fmt.Fprintf(c.output, "%s complete: %s %s in %s after %s\n", *role, digest, *commit, strings.Join(cells, " "),
		time.Since(started).Round(time.Second))
	return err
}
