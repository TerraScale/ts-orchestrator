package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) apply(args []string) error {
	return c.applyWith(args, deployEnv{inspect: c.inspectBinary, storage: operatorObjectStorage})
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
	entries, err := os.ReadDir(*directory)
	if err != nil {
		return err
	}
	var cells []string
	for _, entry := range entries {
		if entry.IsDir() && validRegion(entry.Name()) {
			cells = append(cells, entry.Name())
		}
	}
	cells, err = deploymentCells(c.ctx, cells, nil)
	if err != nil {
		return err
	}
	budget := rollout.ObservationBudget
	if env.timeout > 0 {
		budget = min(budget, env.timeout)
	}
	type target struct {
		channel  releasechannel.Channel
		binaries map[string]binaryReceipt
	}
	targets := make([]target, 0, len(cells))
	var revision string
	var sequence int64
	inspected := make(map[string]binaryReceipt)
	// Verify the whole bundle before writing any region's objects or channel.
	for _, cell := range cells {
		data, err := readBoundedRegular(filepath.Join(*directory, cell, "channel.json"), releasechannel.MaxChannelBytes)
		if err != nil {
			return err
		}
		var channel releasechannel.Channel
		if err := protocol.DecodeStrict(data, &channel, releasechannel.MaxChannelBytes); err != nil {
			return err
		}
		verified, err := channel.Verify(roots, cell, channel.Environment, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("%s signed channel: %w", cell, err)
		}
		if revision == "" {
			revision, sequence = channel.SourceRevision, channel.RunNumber
		}
		if channel.SourceRevision != revision || channel.RunNumber != sequence {
			return errors.New("bundle mixes source revisions or release sequences")
		}
		binaries := make(map[string]binaryReceipt, len(verified))
		for architecture, proof := range verified {
			receipt := proof.Receipt()
			observed, found := inspected[receipt.SHA256]
			if !found {
				var err error
				observed, err = env.inspect(filepath.Join(*directory, "binaries", receipt.SHA256), receipt.GoVersion, revision)
				if err != nil {
					return err
				}
				inspected[receipt.SHA256] = observed
			}
			observed.QualificationSHA256 = receipt.QualificationSHA256
			if observed != receipt {
				return fmt.Errorf("%s %s bytes or build metadata differ from signed receipt", cell, architecture)
			}
			binaries[architecture] = receipt
		}
		targets = append(targets, target{channel, binaries})
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
				location, err := channelLocation(env, target.channel.Cell, *namespace)
				if err != nil {
					return err
				}
				scope, err := deploymentScope(ctx, location, target.channel.Cell)
				if err != nil {
					return err
				}
				if _, err := target.channel.Verify(roots, target.channel.Cell, scope.Environment, deadline); err != nil {
					return fmt.Errorf("signed channel must remain valid through rollout: %w", err)
				}
				if len(target.binaries) != len(scope.Architectures) {
					return errors.New("bundle architectures differ from regional scope")
				}
				for _, architecture := range scope.Architectures {
					if _, found := target.binaries[architecture]; !found {
						return fmt.Errorf("bundle lacks %s", architecture)
					}
				}
				for _, receipt := range target.binaries {
					if err := regional.uploadBinary(location, filepath.Join(*directory, "binaries", receipt.SHA256), receipt.SHA256); err != nil {
						return err
					}
				}
				if err := releasechannel.Publish(ctx, location, target.channel); err != nil {
					return err
				}
				fmt.Fprintf(progress, "%s published signed release %d %s\n", target.channel.Cell, sequence, revision)
				return releasechannel.Await(ctx, location, target.channel, 5*time.Second, deadline, progress)
			}
			if err := apply(); err != nil {
				failures[index] = fmt.Errorf("%s: %w", target.channel.Cell, err)
				fmt.Fprintf(progress, "%s failed: %v\n", target.channel.Cell, err)
			}
			return nil
		})
	}
	_ = regions.Wait()
	return errors.Join(failures...)
}
