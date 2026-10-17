package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const maxFoundationBundleBytes = 3 << 20

func (c command) foundation(args []string) error {
	if len(args) < 2 || args[1] == "" {
		return errors.New("usage: bootstrap foundation prepare APPROVAL --out CANDIDATE | sign CANDIDATE --root-chain CHAIN --root-key KEY --signing-key KEY --out BUNDLE")
	}
	switch args[0] {
	case "prepare":
		return c.prepareFoundation(args[1:])
	case "sign":
		return c.signFoundationAt(args[1:], time.Now().UTC())
	default:
		return errors.New("foundation requires prepare or sign")
	}
}

func (c command) signFoundationAt(args []string, now time.Time) error {
	if len(args) == 0 || args[0] == "" {
		return errors.New("foundation sign requires a reviewed candidate")
	}
	candidatePath, args := args[0], args[1:]
	flags := flag.NewFlagSet("foundation sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	chainPath := flags.String("root-chain", "", "canonical existing root rotation chain")
	privatePath := flags.String("signing-key", "", "owner-only existing offline root private key PEM")
	outputPath := flags.String("out", "", "new public signed foundation bundle")
	var rootPaths stringListFlag
	flags.Var(&rootPaths, "root-key", "independently trusted genesis public key PEM; repeat for each root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if candidatePath == "" || *chainPath == "" || *privatePath == "" || *outputPath == "" || len(rootPaths) == 0 || len(rootPaths) > bootstrapstart.MaxRootFiles || flags.NArg() != 0 {
		return errors.New("foundation sign requires CANDIDATE, --root-chain, --root-key, --signing-key and --out")
	}
	grantWire, err := c.readBoundedRegular(candidatePath, maxFoundationBundleBytes)
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
	bundle, err := region.SignFoundationPreparation(c.ctx, prepared, chainWire, roots, private, now)
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
	if prepared.LedgerProtection != nil {
		_, err = fmt.Fprintf(c.output, "signed existing GRU ledger rule protection installation=%s locks=%s\n", prepared.LedgerProtection.InstallationID, prepared.LedgerProtection.LockedAt.Format(time.RFC3339))
		return err
	}
	_, err = fmt.Fprintf(c.output, "signed foundation installation=%s generation=%d regions=GRU,SFO,FRA\n", prepared.Grant.InstallationID, prepared.Grant.Generation)
	return err
}

func (c command) prepareFoundation(args []string) error {
	if len(args) == 0 || args[0] == "" {
		return errors.New("foundation prepare requires an initial approval")
	}
	approvalPath, args := args[0], args[1:]
	flags := flag.NewFlagSet("foundation prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("out", "", "new public candidate for the existing offline root ceremony")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outputPath == "" || flags.NArg() != 0 {
		return errors.New("foundation prepare requires APPROVAL and --out")
	}
	wire, err := c.readBoundedRegular(approvalPath, maxFoundationBundleBytes)
	if err != nil {
		return err
	}
	var approval region.FoundationPreparationInput
	if err := protocol.DecodeStrict(wire, &approval, maxFoundationBundleBytes); err != nil {
		return fmt.Errorf("decode initial foundation approval: %w", err)
	}
	roots, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	factory, err := ociclient.OperatorConfig("sa-saopaulo-1")
	if err != nil {
		return err
	}
	prepared, err := region.PrepareFoundationGrantSDK(c.ctx, approval, factory, roots)
	if err != nil {
		return err
	}
	wire, err = protocol.EncodeJSON(prepared)
	if err != nil || len(wire) > maxFoundationBundleBytes {
		return errors.Join(errors.New("prepared foundation exceeds its document bound"), err)
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	if prepared.LedgerProtection != nil {
		_, err = fmt.Fprintf(c.output, "prepared unsigned existing GRU ledger rule protection installation=%s\n", prepared.LedgerProtection.InstallationID)
		return err
	}
	_, err = fmt.Fprintf(c.output, "prepared unsigned foundation installation=%s regions=GRU,SFO,FRA hosts=4\n", prepared.Grant.InstallationID)
	return err
}
