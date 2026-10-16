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
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var founderPlanPolicy = trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew}

func (c command) signFounderPlanAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-founder-plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed canonical founder plan payload JSON")
	identityPath := flags.String("identity", "", "canonical baked deployment identity JSON")
	anchorPath := flags.String("anchor", "", "current root-signed genesis anchor")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root private key PEM")
	outputPath := flags.String("out", "", "new root-signed founder plan envelope")
	validFor := flags.Duration("valid-for", 24*time.Hour, "plan validity")
	var manifestPaths stringListFlag
	flags.Var(&manifestPaths, "manifest", "root-signed controller manifest; repeat for each of three slots")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *identityPath == "" || *anchorPath == "" || *publicPath == "" ||
		*privatePath == "" || *outputPath == "" || len(manifestPaths) != 3 || flags.NArg() != 0 {
		return errors.New("sign-founder-plan requires --candidate, --identity, --anchor, --root-key, --signing-key, --out, and three --manifest files")
	}
	now = now.Round(0).UTC()
	if now.IsZero() || *validFor <= 0 || *validFor > founderPlanPolicy.MaxLifetime {
		return errors.New("founder plan signing time or validity is invalid")
	}
	identity, anchorWire, anchor, roots, public, err := readCurrentFounderAnchor(*identityPath, *anchorPath, *publicPath, now)
	if err != nil {
		return err
	}
	manifestWires, err := readFounderManifestFiles(manifestPaths)
	if err != nil {
		return err
	}
	payload, err := c.readBoundedRegular(*candidatePath, bootstrap.MaxFounderPlanBytes)
	if err != nil {
		return err
	}
	var plan bootstrap.FounderPlan
	if err := protocol.DecodeStrict(payload, &plan, bootstrap.MaxFounderPlanBytes); err != nil {
		return err
	}
	canonical, err := protocol.EncodeJSON(plan)
	if err != nil || !bytes.Equal(payload, canonical) {
		return errors.New("founder plan candidate must be canonical JSON")
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.DeploymentID != identity.DeploymentID || plan.Cell != identity.Cell ||
		plan.Environment != identity.Environment || plan.AnchorSHA256 != anchor.Digest() {
		return errors.New("founder plan differs from baked identity or signed anchor")
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return errors.New("root signing key does not match public key")
	}
	expiresAt := minTime(now.Add(*validFor), anchor.ExpiresAt())
	for _, wire := range manifestWires {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return err
		}
		expiresAt = minTime(expiresAt, envelope.ExpiresAt)
	}
	if !expiresAt.After(now) {
		return errors.New("signed founder materials leave no plan validity")
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrap.FounderPlanDomain,
		DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment,
		Role: "controller", Slot: plan.SeedSlot}, now, expiresAt, private)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	verified, err := bootstrap.VerifyFounderPlan(wire, roots, anchorWire, manifestWires, now, founderPlanPolicy)
	if err != nil {
		return fmt.Errorf("verify newly signed founder plan: %w", err)
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed founder plan seed=%s digest=%s expires=%s\n",
		plan.SeedSlot, verified.Digest(), expiresAt.Format(time.RFC3339))
	return nil
}

func (c command) signInitialFounderSelectionAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-initial-founder-selection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed canonical generation-one selector payload JSON")
	identityPath := flags.String("identity", "", "canonical baked deployment identity JSON")
	anchorPath := flags.String("anchor", "", "current root-signed genesis anchor")
	planPath := flags.String("plan", "", "current root-signed founder plan")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root private key PEM")
	outputPath := flags.String("out", "", "new root-signed generation-one selector")
	validFor := flags.Duration("valid-for", 24*time.Hour, "selector validity")
	var manifestPaths stringListFlag
	flags.Var(&manifestPaths, "manifest", "root-signed controller manifest; repeat for each of three slots")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *identityPath == "" || *anchorPath == "" || *planPath == "" ||
		*publicPath == "" || *privatePath == "" || *outputPath == "" || len(manifestPaths) != 3 || flags.NArg() != 0 {
		return errors.New("sign-initial-founder-selection requires --candidate, --identity, --anchor, --plan, --root-key, --signing-key, --out, and three --manifest files")
	}
	now = now.Round(0).UTC()
	policy := bootstrap.BootstrapAnchorTrustPolicy()
	if now.IsZero() || *validFor <= 0 || *validFor > policy.MaxLifetime {
		return errors.New("initial founder selector signing time or validity is invalid")
	}
	identity, anchorWire, anchor, roots, public, err := readCurrentFounderAnchor(*identityPath, *anchorPath, *publicPath, now)
	if err != nil {
		return err
	}
	planWire, err := c.readBoundedRegular(*planPath, bootstrap.MaxFounderPlanBytes)
	if err != nil {
		return err
	}
	manifestWires, err := readFounderManifestFiles(manifestPaths)
	if err != nil {
		return err
	}
	plan, err := bootstrap.VerifyFounderPlan(planWire, roots, anchorWire, manifestWires, now, founderPlanPolicy)
	if err != nil {
		return fmt.Errorf("verify selected founder plan: %w", err)
	}
	payload, err := c.readBoundedRegular(*candidatePath, 4096)
	if err != nil {
		return err
	}
	selection, err := bootstrapstart.ValidateInitialFounderSelectionCandidate(payload, identity)
	if err != nil {
		return err
	}
	if selection.PlanSHA256 != plan.Digest() || selection.AnchorSHA256 != anchor.Digest() {
		return errors.New("initial selector differs from signed founder plan or anchor")
	}
	anchoredSlots := anchor.Anchor().ControllerSlots
	if len(anchoredSlots) != 3 {
		return errors.New("initial selector requires exactly three anchored controllers")
	}
	for index, pin := range selection.Manifests {
		hash := sha256.Sum256(manifestWires[pin.Slot])
		if pin.Slot != anchoredSlots[index] || fmt.Sprintf("%x", hash) != pin.SHA256 {
			return errors.New("initial selector manifest pin differs from signed controller manifest")
		}
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return errors.New("root signing key does not match public key")
	}
	planEnvelope, err := trust.DecodeEnvelope(planWire)
	if err != nil {
		return err
	}
	expiresAt := minTime(minTime(now.Add(*validFor), anchor.ExpiresAt()), planEnvelope.ExpiresAt)
	for _, wire := range manifestWires {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return err
		}
		expiresAt = minTime(expiresAt, envelope.ExpiresAt)
	}
	if !expiresAt.After(now) {
		return errors.New("signed founder materials leave no selector validity")
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrapstart.FounderSelectionDomain,
		DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment,
		Role: "deployment-anchor", Slot: "region"}, now, expiresAt, private)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	verifiedPayload, err := trust.VerifyCurrent(envelope, envelope.Scope, roots, now, policy)
	if err != nil || !bytes.Equal(verifiedPayload, payload) {
		return errors.New("newly signed founder selector failed verification")
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed initial founder selection generation=1 digest=%x expires=%s\n",
		sha256.Sum256(wire), expiresAt.Format(time.RFC3339))
	return nil
}

func (c command) publishInitialFounderSelectionAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("publish-initial-founder-selection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectionPath := flags.String("selection", "", "root-signed generation-one selector")
	identityPath := flags.String("identity", "", "canonical baked deployment identity JSON")
	anchorPath := flags.String("anchor", "", "current root-signed genesis anchor")
	planPath := flags.String("plan", "", "current root-signed founder plan")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	configPath := flags.String("oci-config", "", "OCI API-key config file")
	profile := flags.String("oci-profile", "DEFAULT", "OCI config profile")
	var manifestPaths stringListFlag
	flags.Var(&manifestPaths, "manifest", "root-signed controller manifest; repeat for each of three slots")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *selectionPath == "" || *identityPath == "" || *anchorPath == "" || *planPath == "" ||
		*publicPath == "" || *configPath == "" || len(manifestPaths) != 3 || flags.NArg() != 0 {
		return errors.New("publish-initial-founder-selection requires --selection, --identity, --anchor, --plan, --root-key, --oci-config, and three --manifest files")
	}
	now = now.Round(0).UTC()
	identity, _, anchor, roots, _, err := readCurrentFounderAnchor(*identityPath, *anchorPath, *publicPath, now)
	if err != nil {
		return err
	}
	selectionWire, err := c.readBoundedRegular(*selectionPath, 4096)
	if err != nil {
		return err
	}
	planWire, err := c.readBoundedRegular(*planPath, bootstrap.MaxFounderPlanBytes)
	if err != nil {
		return err
	}
	manifestWires, err := readFounderManifestFiles(manifestPaths)
	if err != nil {
		return err
	}
	region, err := identity.Cell.OCIRegion()
	if err != nil {
		return err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(
		common.CustomProfileConfigProvider(*configPath, *profile))
	if err != nil {
		return err
	}
	client.SetRegion(region)
	if err := bootstrapstart.PublishInitialFounderSelection(c.ctx, anchor, identity,
		roots, selectionWire, planWire, manifestWires, &client, now); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "published initial founder selection digest=%x\n", sha256.Sum256(selectionWire))
	return nil
}

func readCurrentFounderAnchor(identityPath, anchorPath, publicPath string, now time.Time) (
	bootstrapstart.BakedIdentity, []byte, bootstrap.VerifiedBootstrapAnchor, trust.Keyring, ed25519.PublicKey, error,
) {
	identity, err := readFounderIdentity(identityPath)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, nil, bootstrap.VerifiedBootstrapAnchor{}, nil, nil, err
	}
	public, err := readRootPublicKey(publicPath)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, nil, bootstrap.VerifiedBootstrapAnchor{}, nil, nil, err
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, nil, bootstrap.VerifiedBootstrapAnchor{}, nil, nil, err
	}
	wire, err := readBoundedRegular(anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, nil, bootstrap.VerifiedBootstrapAnchor{}, nil, nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, nil, bootstrap.VerifiedBootstrapAnchor{}, nil, nil, err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, identity.AnchorExpectation(), now,
		bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return bootstrapstart.BakedIdentity{}, nil, bootstrap.VerifiedBootstrapAnchor{}, nil, nil, err
	}
	return identity, wire, anchor, roots, public, nil
}

func readFounderManifestFiles(paths []string) (map[string][]byte, error) {
	manifests := make(map[string][]byte, len(paths))
	for _, path := range paths {
		wire, err := readBoundedRegular(path, bootstrap.MaxManifestBytes)
		if err != nil {
			return nil, err
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return nil, err
		}
		if envelope.Scope.Slot == "" {
			return nil, errors.New("founder manifest has no signed slot")
		}
		if _, exists := manifests[envelope.Scope.Slot]; exists {
			return nil, errors.New("duplicate founder manifest slot")
		}
		manifests[envelope.Scope.Slot] = wire
	}
	return manifests, nil
}
