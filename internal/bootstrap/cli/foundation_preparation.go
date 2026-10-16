package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) prepareFoundation(args []string) error {
	roots, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	factory, err := ociclient.OperatorConfig("sa-saopaulo-1")
	if err != nil {
		return err
	}
	return c.prepareFoundationWith(args, factory, roots)
}

func (c command) prepareFoundationWith(args []string, factory *ociclient.Factory, roots trust.Keyring) error {
	flags := flag.NewFlagSet("prepare-foundation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	approvalPath := flags.String("approval", "", "single public initial tenancy, spending and authority approval")
	outputPath := flags.String("out", "", "new public combined foundation candidate for the offline root ceremony")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *approvalPath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("prepare-foundation requires --approval and --out")
	}
	wire, err := c.readBoundedRegular(*approvalPath, maxFoundationBundleBytes)
	if err != nil {
		return err
	}
	var approval region.FoundationPreparationInput
	if err := protocol.DecodeStrict(wire, &approval, maxFoundationBundleBytes); err != nil {
		return fmt.Errorf("decode initial foundation approval: %w", err)
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
	_, err = fmt.Fprintf(c.output, "prepared unsigned foundation installation=%s regions=GRU,SFO,FRA hosts=4\n", prepared.Grant.InstallationID)
	return err
}
