package finalcapture

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const Mode = "capture-final-control-state"

// Command is a finite local owner operation. All runtime paths and inventories
// come from the verified plan; arguments supply only admitted signed material.
func Command(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet(Mode, flag.ContinueOnError)
	set.SetOutput(stderr)
	planPath := set.String("plan", "", "signed finite storage plan")
	ownerPath := set.String("owner-public-key", "", "owner P256 public key")
	cutPath := set.String("cut-receipt", "", "signed stopped-store copy receipt")
	sourcePath := set.String("source-state-receipt", "", "signed quiescent source evidence")
	keyPath := set.String("receipt-private-key", "", "source host receipt P256 key")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *planPath == "" || *ownerPath == "" || *cutPath == "" || *sourcePath == "" || *keyPath == "" {
		return errors.New("finalcapture: explicit signed plan, owner key, cut receipt, source state receipt and source signer required")
	}
	public, err := bootstrapcredentials.ReadFile(*ownerPath, false, 4096)
	if err != nil {
		return err
	}
	raw, err := bootstrapcredentials.ReadFile(*planPath, true, controltransition.MaximumBytes)
	if err != nil {
		return err
	}
	v, err := controltransition.VerifyPlan(public, raw)
	if err != nil {
		return err
	}
	cut, err := bootstrapcredentials.ReadFile(*cutPath, true, controltransition.CutReceiptMaximumBytes)
	if err != nil {
		return err
	}
	source, err := bootstrapcredentials.ReadFile(*sourcePath, true, controltransition.MaximumBytes)
	if err != nil {
		return err
	}
	key, err := bootstrapcredentials.ReadFile(*keyPath, true, 16384)
	if err != nil {
		return err
	}
	defer clear(key)
	signer, err := security.ParseCommandSignatureSignerPEM(key)
	if err != nil {
		return err
	}
	defer signer.Close()
	receipt, err := Run(ctx, Config{Plan: v, CutReceipt: cut, SourceStateReceipt: source, Signer: signer})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, controltransition.Digest(receipt))
	return err
}
