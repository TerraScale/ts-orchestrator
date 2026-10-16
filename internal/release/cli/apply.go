package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) apply(args []string) error {
	return c.applyWith(args, deployEnv{inspect: c.inspectBinary, storage: operatorObjectStorage, discover: discoverServingCells})
}

// applyWith consumes signed releases; source fetching and signing belong to the producer.
func (c command) applyWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "signed bundle: CELL/channel.json and binaries/SHA256")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM, outside the bundle")
	namespace := flags.String("namespace", "", "Object Storage namespace of the regional head buckets")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *rootPath == "" || !validStorageToken(*namespace) || flags.NArg() != 0 {
		return errors.New("apply requires --dir, --root-key and --namespace")
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	cells, err := deploymentCells(c.ctx, nil, env.discover)
	if err != nil {
		return err
	}
	budget := rollout.ObservationBudget
	if env.timeout > 0 {
		budget = min(budget, env.timeout)
	}
	deadline := time.Now().UTC().Add(budget)
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()
	c.ctx = ctx
	type target struct {
		location releasechannel.Location
		channel  releasechannel.Channel
		binaries map[string]binaryReceipt
	}
	targets := make([]target, 0, len(cells))
	var revision string
	var sequence int64
	// Verify the whole bundle before writing any region's objects or channel.
	for _, cell := range cells {
		location, err := channelLocation(env, cell, *namespace)
		if err != nil {
			return err
		}
		scope, err := deploymentScope(ctx, location, cell)
		if err != nil {
			return fmt.Errorf("%s: %w", cell, err)
		}
		data, err := readBoundedRegular(filepath.Join(*directory, cell, "channel.json"), releasechannel.MaxChannelBytes)
		if err != nil {
			return err
		}
		var channel releasechannel.Channel
		if err := protocol.DecodeStrict(data, &channel, releasechannel.MaxChannelBytes); err != nil {
			return err
		}
		verified, err := channel.Verify(roots, cell, scope.Environment, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("%s signed channel: %w", cell, err)
		}
		if _, err := channel.Verify(roots, cell, scope.Environment, deadline); err != nil {
			return fmt.Errorf("%s signed channel would expire during rollout: %w", cell, err)
		}
		if revision == "" {
			revision, sequence = channel.SourceRevision, channel.RunNumber
		}
		if channel.SourceRevision != revision || channel.RunNumber != sequence {
			return errors.New("bundle mixes source revisions or release sequences")
		}
		if len(verified) != len(scope.Architectures) {
			return fmt.Errorf("%s bundle architectures differ from regional scope", cell)
		}
		binaries := make(map[string]binaryReceipt, len(verified))
		for _, architecture := range scope.Architectures {
			proof, found := verified[architecture]
			if !found {
				return fmt.Errorf("%s bundle lacks %s", cell, architecture)
			}
			receipt := proof.Receipt()
			observed, err := env.inspect(filepath.Join(*directory, "binaries", receipt.SHA256), receipt.GoVersion, revision)
			if err != nil {
				return err
			}
			observed.QualificationSHA256 = receipt.QualificationSHA256
			if observed != receipt {
				return fmt.Errorf("%s %s bytes or build metadata differ from signed receipt", cell, architecture)
			}
			binaries[architecture] = receipt
		}
		targets = append(targets, target{location, channel, binaries})
	}
	progress := &deploymentWriter{Writer: c.output}
	failures := make([]error, len(targets))
	var regions errgroup.Group
	for index, target := range targets {
		regions.Go(func() error {
			apply := func() error {
				for _, receipt := range target.binaries {
					if err := c.uploadBinary(target.location, filepath.Join(*directory, "binaries", receipt.SHA256), receipt.SHA256); err != nil {
						return err
					}
				}
				if err := releasechannel.Publish(ctx, target.location, target.channel); err != nil {
					return err
				}
				fmt.Fprintf(progress, "%s published signed release %d %s\n", target.channel.Cell, sequence, revision)
				return releasechannel.Await(ctx, target.location, target.channel, 5*time.Second, deadline, progress)
			}
			if err := apply(); err != nil {
				failures[index] = fmt.Errorf("%s: %w", target.channel.Cell, err)
			}
			return nil
		})
	}
	_ = regions.Wait()
	return errors.Join(failures...)
}
