package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// signSlotRetirementAt root-signs a controller's retirement request for one
// exact lost managed peer instance. The operator restates the slot, attempt
// and instance so a mistaken or swapped request cannot be signed blindly.
func (c command) signSlotRetirementAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-slot-retirement", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "controller-rendered <slot>.retirement-request.json")
	slot := flags.String("slot", "", "controller slot being retired, restated by the operator")
	attempt := flags.Uint64("attempt", 0, "ledger attempt being retired, restated by the operator")
	instance := flags.String("instance", "", "retired instance OCID, independently confirmed TERMINATED")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root private key PEM")
	outputPath := flags.String("out", "", "new signed <slot>.retirement envelope")
	validFor := flags.Duration("valid-for", time.Hour, "retirement validity; at most 24h")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *slot == "" || *attempt == 0 || *instance == "" || *publicPath == "" ||
		*privatePath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-slot-retirement requires --candidate, --slot, --attempt, --instance, --root-key, --signing-key, and --out")
	}
	now = now.Round(0).UTC()
	if now.IsZero() || *validFor <= 0 || *validFor > bootstrap.MaxSlotRetirementLifetime {
		return errors.New("retirement signing time or validity is invalid")
	}
	wire, err := c.readBoundedRegular(*candidatePath, 16<<10)
	if err != nil {
		return err
	}
	var candidate bootstrap.RetirementEvidence
	if err := protocol.DecodeStrict(wire, &candidate, 16<<10); err != nil {
		return err
	}
	canonical, err := protocol.EncodeJSON(candidate)
	if err != nil || !bytes.Equal(wire, canonical) {
		return errors.New("retirement candidate must be canonical JSON")
	}
	if err := bootstrap.ValidateSlotRetirementCandidate(candidate); err != nil {
		return err
	}
	if candidate.Slot != *slot || candidate.PreviousAttempt != *attempt || candidate.PriorInstanceOCID != *instance {
		return errors.New("retirement candidate differs from the operator-confirmed slot, attempt, or instance")
	}
	if now.Sub(candidate.ObservedAt) > bootstrap.MaxSlotRetirementLifetime {
		return errors.New("retirement candidate observation is stale; let the controller render a fresh request")
	}
	public, err := readRootPublicKey(*publicPath)
	if err != nil {
		return err
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return errors.New("root signing key does not match public key")
	}
	signed, err := bootstrap.SignSlotRetirement(candidate, now, now.Add(*validFor), private)
	if err != nil {
		return err
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, encoded, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed slot retirement slot=%s attempt=%d instance=%s digest=%x expires=%s\n",
		candidate.Slot, candidate.PreviousAttempt, candidate.PriorInstanceOCID, sha256.Sum256(encoded),
		now.Add(*validFor).Format(time.RFC3339))
	return nil
}
