package cli

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type identityRekeySignFlags struct {
	candidate, expectation, chain, key, out *string
	roots                                   stringListFlag
	validFor                                *time.Duration
}

func addIdentityRekeySignFlags(flags *flag.FlagSet, lifetime time.Duration) *identityRekeySignFlags {
	f := &identityRekeySignFlags{
		candidate:   flags.String("candidate", "", "reviewed canonical unsigned v1 payload"),
		expectation: flags.String("expectation", "", "independently reviewed canonical CheckpointExpectation JSON"),
		chain:       flags.String("root-chain", "", "canonical adopted root chain for the proposed deployment (including an empty chain)"),
		key:         flags.String("signing-key", "", "owner-only current root Ed25519 PKCS#8 private key PEM"),
		out:         flags.String("out", "", "create-only signed envelope output"),
		validFor:    flags.Duration("valid-for", lifetime, "signature lifetime"),
	}
	flags.Var(&f.roots, "root-key", "independently trusted genesis Ed25519 public key PEM (repeatable)")
	return f
}

func (c command) readIdentityRekeyPayload(path string, maximum int, destination any) ([]byte, error) {
	wire, err := c.readBoundedRegular(path, int64(maximum))
	if err != nil {
		return nil, err
	}
	if err := protocol.DecodeStrict(wire, destination, maximum); err != nil {
		return nil, err
	}
	canonical, err := protocol.EncodeJSON(destination)
	if err != nil || !bytes.Equal(wire, canonical) {
		return nil, errors.New("identity rekey input must be canonical JSON")
	}
	return wire, nil
}

func (c command) identityRekeySignInputs(flags *flag.FlagSet, f *identityRekeySignFlags, maximumLifetime time.Duration) (
	identityrekey.CheckpointExpectation, bootstrapstart.TrustInputs, ed25519.PrivateKey, error,
) {
	fail := func(err error) (identityrekey.CheckpointExpectation, bootstrapstart.TrustInputs, ed25519.PrivateKey, error) {
		return identityrekey.CheckpointExpectation{}, bootstrapstart.TrustInputs{}, nil, err
	}
	if flags.NArg() != 0 || *f.candidate == "" || *f.expectation == "" || *f.chain == "" || *f.key == "" || *f.out == "" ||
		len(f.roots) == 0 || len(f.roots) > bootstrapstart.MaxRootFiles || *f.validFor <= 0 || *f.validFor > maximumLifetime {
		return fail(errors.New("identity rekey signing requires --candidate, --expectation, --root-chain, --root-key, --signing-key, --out and a bounded positive --valid-for"))
	}
	var expected identityrekey.CheckpointExpectation
	if _, err := c.readIdentityRekeyPayload(*f.expectation, identityrekey.MaxCheckpointBytes, &expected); err != nil {
		return fail(err)
	}
	var keys []ed25519.PublicKey
	rootBytes := 0
	for _, path := range f.roots {
		wire, err := c.readBoundedRegular(path, bootstrapstart.MaxRootBytes)
		if err != nil {
			return fail(err)
		}
		rootBytes += len(wire)
		if rootBytes > bootstrapstart.MaxRootsTotal {
			return fail(errors.New("identity rekey genesis exceeds aggregate root key bound"))
		}
		key, err := parseRootPublicKey(wire)
		if err != nil {
			return fail(err)
		}
		keys = append(keys, key)
	}
	genesis, err := trust.ParseKeyring(keys...)
	if err != nil {
		return fail(err)
	}
	chainWire, err := c.readBoundedRegular(*f.chain, trust.MaxRootChainBytes)
	if err != nil {
		return fail(err)
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return fail(err)
	}
	identity := trust.ChainIdentity{DeploymentID: expected.DeploymentID, Environment: expected.Environment, Cell: strings.ToLower(expected.Cell)}
	roots, err := trust.VerifyRootChain(genesis, identity, chain)
	if err != nil {
		return fail(err)
	}
	key, err := readRootPrivateKey(*f.key)
	if err != nil {
		return fail(err)
	}
	public := key.Public().(ed25519.PublicKey)
	id, err := trust.KeyID(public)
	if err != nil || !bytes.Equal(roots.Current[id], public) {
		clear(key)
		return fail(trust.ErrUntrustedKey)
	}
	return expected, bootstrapstart.TrustInputs{ChainIdentity: identity, Genesis: genesis, Chain: chain, Roots: roots}, key, nil
}

func (c command) signAcceptedIdentityCheckpointAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-accepted-identity-checkpoint", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	f := addIdentityRekeySignFlags(flags, identityrekey.MaxCheckpointLifetime)
	if err := flags.Parse(args); err != nil {
		return err
	}
	expected, inputs, key, err := c.identityRekeySignInputs(flags, f, identityrekey.MaxCheckpointLifetime)
	if err != nil {
		return err
	}
	defer clear(key)
	var checkpoint identityrekey.AcceptedIdentityCheckpoint
	if _, err := c.readIdentityRekeyPayload(*f.candidate, identityrekey.MaxCheckpointBytes, &checkpoint); err != nil {
		return err
	}
	now = now.Round(0).UTC()
	envelope, err := identityrekey.IssueAcceptedIdentityCheckpoint(checkpoint, now, now.Add(*f.validFor), key)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	if _, err := identityrekey.VerifyAcceptedIdentityCheckpoint(wire, inputs.Genesis, inputs.Chain, expected, now); err != nil {
		return err
	}
	return c.writeIdentityRekeyEnvelope(*f.out, envelope)
}

func (c command) readIdentityRekeyCheckpoint(path string, inputs bootstrapstart.TrustInputs,
	expected identityrekey.CheckpointExpectation, now time.Time,
) (identityrekey.VerifiedIdentityCheckpoint, error) {
	wire, err := c.readBoundedRegular(path, identityrekey.MaxCheckpointWireBytes)
	if err != nil {
		return identityrekey.VerifiedIdentityCheckpoint{}, err
	}
	return identityrekey.VerifyAcceptedIdentityCheckpoint(wire, inputs.Genesis, inputs.Chain, expected, now)
}

func (c command) readIdentityRekeyHostObservation(path string, checkpoint identityrekey.VerifiedIdentityCheckpoint) (identityrekey.HostStateObservation, error) {
	var observed identityrekey.HostStateObservation
	if _, err := c.readIdentityRekeyPayload(path, identityrekey.MaxHostStatePlanBytes, &observed); err != nil {
		return observed, err
	}
	target := checkpoint.Checkpoint()
	if !checkpoint.IsVerified() || observed.OperationID != target.OperationID || observed.DeploymentID != target.DeploymentID ||
		observed.ClusterID != target.ClusterID || observed.Environment != target.Environment || observed.Cell != target.Cell ||
		observed.CheckpointSHA256 != checkpoint.Fingerprint() {
		return observed, trust.ErrScopeMismatch
	}
	return observed, nil
}

func (c command) signHostStateHandoffPlanAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-host-state-handoff-plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	f := addIdentityRekeySignFlags(flags, time.Hour)
	checkpointPath := flags.String("checkpoint", "", "current root-signed v1 accepted checkpoint")
	observationPath := flags.String("observation", "", "independently reviewed canonical host inventory and actual agent drain timestamps")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *checkpointPath == "" || *observationPath == "" {
		return errors.New("sign-host-state-handoff-plan requires --checkpoint and --observation")
	}
	expected, inputs, key, err := c.identityRekeySignInputs(flags, f, time.Hour)
	if err != nil {
		return err
	}
	defer clear(key)
	now = now.Round(0).UTC()
	checkpoint, err := c.readIdentityRekeyCheckpoint(*checkpointPath, inputs, expected, now)
	if err != nil {
		return err
	}
	observed, err := c.readIdentityRekeyHostObservation(*observationPath, checkpoint)
	if err != nil {
		return err
	}
	var plan identityrekey.HostStateHandoffPlan
	if _, err := c.readIdentityRekeyPayload(*f.candidate, identityrekey.MaxHostStatePlanBytes, &plan); err != nil {
		return err
	}
	envelope, err := identityrekey.SignHostStateHandoffPlan(plan, now, now.Add(*f.validFor), key)
	if err != nil {
		return err
	}
	if _, err := identityrekey.VerifyHostStateHandoffPlan(envelope, inputs.Roots.Current, observed, now); err != nil {
		return err
	}
	return c.writeIdentityRekeyEnvelope(*f.out, envelope)
}

func (c command) signIdentityResetAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-identity-reset", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	f := addIdentityRekeySignFlags(flags, time.Hour)
	checkpointPath := flags.String("checkpoint", "", "current root-signed v1 accepted checkpoint")
	observationPath := flags.String("observation", "", "independently reviewed canonical host inventory")
	hostPlanPath := flags.String("host-plan", "", "current root-signed v1 host handoff plan")
	replicas := flags.Int("replicas", 0, "independently observed existing control stream quorum")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *checkpointPath == "" || *observationPath == "" || *hostPlanPath == "" || *replicas == 0 {
		return errors.New("sign-identity-reset requires --checkpoint, --observation, --host-plan and --replicas")
	}
	expected, inputs, key, err := c.identityRekeySignInputs(flags, f, time.Hour)
	if err != nil {
		return err
	}
	defer clear(key)
	now = now.Round(0).UTC()
	checkpoint, err := c.readIdentityRekeyCheckpoint(*checkpointPath, inputs, expected, now)
	if err != nil {
		return err
	}
	observed, err := c.readIdentityRekeyHostObservation(*observationPath, checkpoint)
	if err != nil {
		return err
	}
	hostWire, err := c.readBoundedRegular(*hostPlanPath, trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	hostEnvelope, err := trust.DecodeEnvelope(hostWire)
	if err != nil {
		return err
	}
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(hostEnvelope, inputs.Roots.Current, observed, now)
	if err != nil {
		return err
	}
	var reset authority.IdentityReset
	if _, err := c.readIdentityRekeyPayload(*f.candidate, 512<<10, &reset); err != nil {
		return err
	}
	envelope, err := authority.SignIdentityReset(reset, now, now.Add(*f.validFor), key)
	if err != nil {
		return err
	}
	target := authority.IdentityResetTarget{OperationID: expected.OperationID, DeploymentID: expected.DeploymentID,
		ClusterID: expected.ClusterID, Scope: strings.ToLower(expected.Cell), Environment: expected.Environment,
		CheckpointSHA256: checkpoint.Fingerprint(), HostStatePlanSHA256: hostPlan.Fingerprint(), Replicas: *replicas}
	verified, err := authority.VerifyIdentityReset(envelope, inputs.Roots.Current, target, now)
	if err != nil {
		return err
	}
	if err := hostPlan.MatchIdentityReset(verified); err != nil {
		return err
	}
	return c.writeIdentityRekeyEnvelope(*f.out, envelope)
}

func (c command) writeIdentityRekeyEnvelope(path string, envelope trust.Envelope) error {
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := c.writeNew(path, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed %s deployment=%s cell=%s expires=%s\n", envelope.Scope.Domain,
		envelope.Scope.DeploymentID, envelope.Scope.Cell, envelope.ExpiresAt.Format(time.RFC3339))
	return nil
}
