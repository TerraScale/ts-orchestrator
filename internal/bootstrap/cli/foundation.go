package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const maxFoundationBundleBytes = 3 << 20

func (c command) signFoundationAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-foundation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "prepared reviewed foundation grant JSON")
	chainPath := flags.String("root-chain", "", "canonical existing root rotation chain")
	privatePath := flags.String("signing-key", "", "owner-only existing offline root private key PEM")
	outputPath := flags.String("out", "", "new public signed foundation bundle")
	var rootPaths stringListFlag
	flags.Var(&rootPaths, "root-key", "independently trusted genesis public key PEM; repeat for each root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *chainPath == "" || *privatePath == "" || *outputPath == "" || len(rootPaths) == 0 || len(rootPaths) > bootstrapstart.MaxRootFiles || flags.NArg() != 0 {
		return errors.New("sign-foundation requires --candidate, --root-chain, --root-key, --signing-key and --out")
	}
	grantWire, err := c.readBoundedRegular(*candidatePath, maxFoundationBundleBytes)
	if err != nil {
		return err
	}
	var prepared region.FoundationPreparation
	if err := protocol.DecodeStrict(grantWire, &prepared, maxFoundationBundleBytes); err != nil {
		return fmt.Errorf("decode prepared foundation: %w", err)
	}
	chainWire, err := c.readBoundedRegular(*chainPath, trust.MaxRootChainBytes)
	if err != nil {
		return err
	}
	roots := trust.Keyring{}
	for _, path := range rootPaths {
		public, err := readRootPublicKey(path)
		if err != nil {
			return err
		}
		parsed, err := trust.ParseKeyring(public)
		if err != nil {
			return err
		}
		for id, key := range parsed {
			roots[id] = key
		}
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	now = now.Round(0).UTC()
	bundle, err := region.SignFoundationDiscovery(c.ctx, prepared.Grant, prepared.Anchor, chainWire, roots, private, now, now.Add(bootstrap.DefaultBootstrapAnchorValidity))
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(bundle)
	if err != nil || len(wire) > maxFoundationBundleBytes {
		return errors.Join(errors.New("foundation bundle exceeds its document bound"), err)
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "signed foundation installation=%s generation=%d regions=GRU,SFO,FRA\n", prepared.Grant.InstallationID, prepared.Grant.Generation)
	return err
}

func (c command) publishFoundation(args []string) error {
	flags := flag.NewFlagSet("publish-foundation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "public bundle from the existing offline foundation ceremony")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || flags.NArg() != 0 {
		return errors.New("publish-foundation requires --bundle")
	}
	wire, err := c.readBoundedRegular(*bundlePath, maxFoundationBundleBytes)
	if err != nil {
		return err
	}
	var bundle region.RetainedFoundation
	if err := protocol.DecodeStrict(wire, &bundle, maxFoundationBundleBytes); err != nil {
		return err
	}
	roots, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	factory, err := ociclient.OperatorConfig("sa-saopaulo-1")
	if err != nil {
		return err
	}
	if err := region.PublishFoundationBundle(c.ctx, factory, roots, bundle); err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.output, "published exact signed foundation bundle")
	return err
}
