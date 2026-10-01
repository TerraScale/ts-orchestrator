package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

const (
	seedSlot           = "controller-a"
	seedBundleMaxBytes = 256 << 10
	seedRecordValidity = 23 * time.Hour
	seedBundleVersion  = 1
	peerReceiptDomain  = "terrascale.bootstrap.peer-receipt"
	seedIntentDomain   = "bootstrap-intent"
	seedResultDomain   = "bootstrap-result"
	seedHeadDomain     = "bootstrap-slot-head"
)

var (
	seedDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	seedCreateRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	ErrSeedCLI   = errors.New("first external seed transaction is invalid")
)

type seedInputs struct {
	identity      bootstrapstart.BakedIdentity
	anchorWire    []byte
	anchor        bootstrap.VerifiedBootstrapAnchor
	planWire      []byte
	plan          bootstrap.VerifiedFounderPlan
	planDigest    string
	seedPrivateIP string
	manifestWire  []byte
	manifest      bootstrap.VerifiedManifest
	roots         trust.Keyring
	rootPublic    ed25519.PublicKey
}

type seedReservation struct {
	SchemaVersion      int    `json:"schemaVersion"`
	AnchorSHA256       string `json:"anchorSha256"`
	FounderPlanSHA256  string `json:"founderPlanSha256"`
	ManifestSHA256     string `json:"manifestSha256"`
	ReviewedPlanSHA256 string `json:"reviewedPlanSha256"`
	Slot               string `json:"slot"`
	CreateIdentity     string `json:"createIdentity"`
	IntentWire         []byte `json:"intentWire"`
	InitialHeadWire    []byte `json:"initialHeadWire"`
}

type seedObservation struct {
	SchemaVersion             int       `json:"schemaVersion"`
	ReservationSHA256         string    `json:"reservationSha256"`
	InstanceOCID              string    `json:"instanceOcid"`
	BootstrapCreateKey        string    `json:"bootstrapCreateKey"`
	CompartmentOCID           string    `json:"compartmentOcid"`
	ImageOCID                 string    `json:"imageOcid"`
	ETag                      string    `json:"etag"`
	AvailabilityDomain        string    `json:"availabilityDomain"`
	FaultDomain               string    `json:"faultDomain"`
	Shape                     string    `json:"shape"`
	SubnetOCID                string    `json:"subnetOcid"`
	NetworkSecurityGroupOCIDs []string  `json:"networkSecurityGroupOcids"`
	PrimaryVNICOCID           string    `json:"primaryVnicOcid"`
	PrimaryPrivateIP          string    `json:"primaryPrivateIp"`
	LifecycleState            string    `json:"lifecycleState"`
	ObservedAt                time.Time `json:"observedAt"`
}

type seedCompletion struct {
	SchemaVersion     int             `json:"schemaVersion"`
	ReservationSHA256 string          `json:"reservationSha256"`
	Observation       seedObservation `json:"observation"`
	ReceiptWire       []byte          `json:"receiptWire"`
	ResultWire        []byte          `json:"resultWire"`
	CompletedHeadWire []byte          `json:"completedHeadWire"`
}

func seedDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func minSeedTime(times ...time.Time) time.Time {
	minimum := times[0]
	for _, candidate := range times[1:] {
		if candidate.Before(minimum) {
			minimum = candidate
		}
	}
	return minimum
}

func loadSeedInputs(identityPath, anchorPath, planPath, publicPath string,
	manifestPaths []string, now time.Time,
) (seedInputs, error) {
	if len(manifestPaths) != 3 {
		return seedInputs{}, fmt.Errorf("%w: exactly three signed manifests are required", ErrSeedCLI)
	}
	identity, anchorWire, anchor, roots, public, err := readCurrentFounderAnchor(
		identityPath, anchorPath, publicPath, now)
	if err != nil {
		return seedInputs{}, err
	}
	manifestWires, err := readFounderManifestFiles(manifestPaths)
	if err != nil {
		return seedInputs{}, err
	}
	planWire, err := readBoundedRegular(planPath, bootstrap.MaxFounderPlanBytes)
	if err != nil {
		return seedInputs{}, err
	}
	plan, err := bootstrap.VerifyFounderPlan(planWire, roots, anchorWire, manifestWires, now, founderPlanPolicy)
	if err != nil {
		return seedInputs{}, fmt.Errorf("verify current first-seed founder plan: %w", err)
	}
	if plan.Plan().SeedSlot != seedSlot || !slices.Equal(plan.Plan().ControllerSlots,
		[]string{"controller-a", "controller-b", "controller-c"}) {
		return seedInputs{}, fmt.Errorf("%w: reviewed regional controller-a/b/c topology is required", ErrSeedCLI)
	}
	manifestWire := manifestWires[seedSlot]
	manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		return seedInputs{}, err
	}
	manifestPayload, err := bootstrap.ManifestPayload(manifestEnvelope.Payload)
	if err != nil {
		return seedInputs{}, err
	}
	expected, err := anchor.ManifestExpectation(seedSlot, manifestPayload.ImageOCID)
	if err != nil {
		return seedInputs{}, err
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, roots, expected, now,
		bootstrap.ManifestTrustPolicy())
	if err != nil || manifest.Digest() != plan.Plan().SeedManifestSHA256 {
		return seedInputs{}, fmt.Errorf("%w: verify exact seed manifest: %v", ErrSeedCLI, err)
	}
	return seedInputs{identity: identity, anchorWire: anchorWire, anchor: anchor,
		planWire: planWire, plan: plan, planDigest: plan.Digest(),
		seedPrivateIP: plan.Plan().SeedPrivateIP,
		manifestWire:  manifestWire, manifest: manifest,
		roots: roots, rootPublic: public}, nil
}

// loadCompletedSeedInputs carries only the verified plan digest into an exact,
// read-only completed-slot reconciliation after launch authority has ended.
func loadCompletedSeedInputs(identityPath, anchorPath, planPath, publicPath string,
	manifestPaths []string, now time.Time,
) (seedInputs, bootstrap.VerifiedCompletedFounderPlan, error) {
	if len(manifestPaths) != 3 {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, ErrSeedCLI
	}
	identity, anchorWire, anchor, roots, public, err := readCurrentFounderAnchor(
		identityPath, anchorPath, publicPath, now)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	manifestWires, err := readFounderManifestFiles(manifestPaths)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	planWire, err := readBoundedRegular(planPath, bootstrap.MaxFounderPlanBytes)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	plan, err := bootstrap.VerifyFounderPlanForCompletedPeerContinuation(
		planWire, roots, anchorWire, manifestWires, now, founderPlanPolicy)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	if plan.SeedSlot() != seedSlot || !slices.Equal(anchor.Anchor().ControllerSlots,
		[]string{"controller-a", "controller-b", "controller-c"}) {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, ErrSeedCLI
	}
	planEnvelope, err := trust.DecodeEnvelope(planWire)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	var planPayload bootstrap.FounderPlan
	if err := protocol.DecodeStrict([]byte(planEnvelope.Payload), &planPayload,
		bootstrap.MaxFounderPlanBytes); err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	manifestWire := manifestWires[seedSlot]
	manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	manifestPayload, err := bootstrap.ManifestPayload(manifestEnvelope.Payload)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	expected, err := anchor.ManifestExpectation(seedSlot, manifestPayload.ImageOCID)
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, roots, expected, now,
		bootstrap.ManifestTrustPolicy())
	if err != nil {
		return seedInputs{}, bootstrap.VerifiedCompletedFounderPlan{}, err
	}
	return seedInputs{identity: identity, anchorWire: anchorWire, anchor: anchor,
		planWire: planWire, planDigest: plan.Digest(), manifestWire: manifestWire,
		seedPrivateIP: planPayload.SeedPrivateIP, manifest: manifest,
		roots: roots, rootPublic: public}, plan, nil
}

func readSeedBundle[T any](path string) (T, []byte, error) {
	var value T
	wire, err := readBoundedRegular(path, seedBundleMaxBytes)
	if err != nil {
		return value, nil, err
	}
	if err := protocol.DecodeStrict(wire, &value, seedBundleMaxBytes); err != nil {
		return value, nil, err
	}
	canonical, err := protocol.EncodeJSON(value)
	if err != nil || !bytes.Equal(canonical, wire) {
		return value, nil, fmt.Errorf("%w: bundle must be canonical JSON", ErrSeedCLI)
	}
	return value, wire, nil
}

func writeSeedBundle(path string, value any) error {
	wire, err := protocol.EncodeJSON(value)
	if err != nil || len(wire) > seedBundleMaxBytes {
		return fmt.Errorf("%w: encode bounded seed bundle: %v", ErrSeedCLI, err)
	}
	return writeNew(path, wire, 0o644)
}

func readSeedLedgerSigner(path string, anchor bootstrap.VerifiedBootstrapAnchor) (ed25519.PrivateKey, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open delegated ledger signing key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat delegated ledger signing key: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ledger signer must be an owner-only canonical 64-byte Ed25519 key", ErrSeedCLI)
	}
	wire, err := io.ReadAll(io.LimitReader(file, ed25519.PrivateKeySize+1))
	if err != nil || len(wire) != ed25519.PrivateKeySize {
		clear(wire)
		return nil, fmt.Errorf("%w: read exact delegated ledger signing key: %v", ErrSeedCLI, err)
	}
	private := ed25519.PrivateKey(wire)
	canonical := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	valid := bytes.Equal(private, canonical)
	clear(canonical)
	if !valid {
		clear(private)
		return nil, fmt.Errorf("%w: delegated ledger signing key is not canonical", ErrSeedCLI)
	}
	grant, err := anchor.LedgerDelegation()
	if err != nil {
		clear(private)
		return nil, err
	}
	keyID, err := trust.KeyID(private.Public().(ed25519.PublicKey))
	if err != nil || keyID != grant.SubjectKeyID() {
		clear(private)
		return nil, fmt.Errorf("%w: ledger signer differs from anchor delegation", ErrSeedCLI)
	}
	return private, nil
}

func seedOCIProvider(path, profile string, inputs seedInputs) (common.ConfigurationProvider, error) {
	if path == "" || profile == "" {
		return nil, fmt.Errorf("%w: OCI config and profile are required", ErrSeedCLI)
	}
	provider := common.CustomProfileConfigProvider(path, profile)
	region, err := provider.Region()
	if err != nil {
		return nil, err
	}
	if region != inputs.anchor.Anchor().OCIRegion {
		return nil, fmt.Errorf("%w: OCI profile region differs from signed anchor", ErrSeedCLI)
	}
	return provider, nil
}

func seedObservationFromOCI(reservationSHA string, observed bootstrapstart.InstanceObservation,
	now time.Time,
) seedObservation {
	return seedObservation{SchemaVersion: seedBundleVersion, ReservationSHA256: reservationSHA,
		InstanceOCID: observed.InstanceOCID, BootstrapCreateKey: observed.BootstrapCreateKey,
		CompartmentOCID: observed.CompartmentOCID, ImageOCID: observed.ImageOCID,
		ETag: observed.ETag, AvailabilityDomain: observed.AvailabilityDomain,
		FaultDomain: observed.FaultDomain, Shape: observed.Shape, SubnetOCID: observed.SubnetOCID,
		NetworkSecurityGroupOCIDs: slices.Clone(observed.NSGOCIDs),
		PrimaryVNICOCID:           observed.PrimaryVNICOCID, PrimaryPrivateIP: observed.PrimaryPrivateIP,
		LifecycleState: observed.LifecycleState, ObservedAt: now}
}

func (observation seedObservation) instanceObservation() bootstrapstart.InstanceObservation {
	return bootstrapstart.InstanceObservation{InstanceOCID: observation.InstanceOCID,
		BootstrapCreateKey: observation.BootstrapCreateKey,
		CompartmentOCID:    observation.CompartmentOCID, ImageOCID: observation.ImageOCID,
		ETag: observation.ETag, AvailabilityDomain: observation.AvailabilityDomain,
		FaultDomain: observation.FaultDomain, Shape: observation.Shape,
		SubnetOCID: observation.SubnetOCID, NSGOCIDs: slices.Clone(observation.NetworkSecurityGroupOCIDs),
		PrimaryVNICOCID:  observation.PrimaryVNICOCID,
		PrimaryPrivateIP: observation.PrimaryPrivateIP, PrimaryVNIC: true,
		LifecycleState: observation.LifecycleState}
}

func seedScope(inputs seedInputs) bootstrap.BootstrapScope {
	return bootstrap.BootstrapScope{DeploymentID: inputs.identity.DeploymentID,
		Cell: string(inputs.identity.Cell), Slot: seedSlot}
}

func (c command) signPeerReceiptDelegationAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-peer-receipt-delegation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	identityPath := flags.String("identity", "", "canonical baked deployment identity")
	anchorPath := flags.String("anchor", "", "current signed anchor with exact controller slots")
	publicPath := flags.String("root-key", "", "offline root public PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root private PEM")
	peerPath := flags.String("peer-public-key", "", "distinct delegated founder public PEM")
	outputPath := flags.String("out", "", "new root-signed peer receipt delegation")
	validFor := flags.Duration("valid-for", 24*time.Hour, "delegation validity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *identityPath == "" || *anchorPath == "" || *publicPath == "" || *privatePath == "" ||
		*peerPath == "" || *outputPath == "" || flags.NArg() != 0 || *validFor <= 0 ||
		*validFor > bootstrap.ManifestTrustPolicy().MaxLifetime {
		return fmt.Errorf("%w: peer delegation requires identity, anchor, root keys, peer public key, out, and valid lifetime", ErrSeedCLI)
	}
	identity, _, anchor, roots, public, err := readCurrentFounderAnchor(*identityPath, *anchorPath, *publicPath, now)
	if err != nil {
		return err
	}
	if !slices.Equal(anchor.Anchor().ControllerSlots, []string{"controller-a", "controller-b", "controller-c"}) {
		return fmt.Errorf("%w: peer delegation requires exact reviewed controller slots", ErrSeedCLI)
	}
	peerPublic, err := readRootPublicKey(*peerPath)
	if err != nil {
		return err
	}
	peerKeyID, err := trust.KeyID(peerPublic)
	if err != nil {
		return err
	}
	ledgerGrant, err := anchor.LedgerDelegation()
	if err != nil || peerKeyID == ledgerGrant.SubjectKeyID() || bytes.Equal(peerPublic, public) {
		return fmt.Errorf("%w: founder signer must differ from root and ledger signers", ErrSeedCLI)
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return fmt.Errorf("%w: root signing key mismatch", ErrSeedCLI)
	}
	peerWire, err := trust.EncodeDelegatedPublicKey(peerPublic)
	if err != nil {
		return err
	}
	delegation := trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: peerKeyID, SubjectPublicKey: peerWire,
		Capabilities: []trust.Capability{{Domain: peerReceiptDomain,
			DeploymentID: identity.DeploymentID, Cell: string(identity.Cell),
			Environment: identity.Environment, Role: "controller",
			Slots: []string{"controller-b", "controller-c"}, Actions: []string{"sign"}}}}
	expiresAt := minSeedTime(now.Add(*validFor), anchor.ExpiresAt())
	if !expiresAt.After(now) {
		return fmt.Errorf("%w: peer delegation has no current validity", ErrSeedCLI)
	}
	signed, err := trust.SignDelegation(delegation, now, expiresAt, private)
	if err != nil {
		return err
	}
	if _, err := trust.VerifyDelegationCurrent(signed, roots, now, bootstrap.ManifestTrustPolicy()); err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed peer receipt delegation slots=controller-b,controller-c digest=%s\n", seedDigest(wire))
	return nil
}

type seedInputFlags struct {
	identity *string
	anchor   *string
	plan     *string
	root     *string
	manifest stringListFlag
}

func addSeedInputFlags(flags *flag.FlagSet) *seedInputFlags {
	inputs := &seedInputFlags{
		identity: flags.String("identity", "", "canonical baked deployment identity"),
		anchor:   flags.String("anchor", "", "current signed bootstrap anchor"),
		plan:     flags.String("founder-plan", "", "current root-signed three-slot founder plan"),
		root:     flags.String("root-key", "", "offline root public PEM"),
	}
	flags.Var(&inputs.manifest, "manifest", "signed controller manifest; repeat for each of three slots")
	return inputs
}

func (flags *seedInputFlags) load(now time.Time) (seedInputs, error) {
	if *flags.identity == "" || *flags.anchor == "" || *flags.plan == "" || *flags.root == "" {
		return seedInputs{}, fmt.Errorf("%w: identity, anchor, founder plan, and root key are required", ErrSeedCLI)
	}
	return loadSeedInputs(*flags.identity, *flags.anchor, *flags.plan, *flags.root,
		flags.manifest, now)
}

func seedRecordExpiry(inputs seedInputs, now time.Time) (time.Time, error) {
	planEnvelope, err := trust.DecodeEnvelope(inputs.planWire)
	if err != nil {
		return time.Time{}, err
	}
	manifestEnvelope, err := trust.DecodeEnvelope(inputs.manifestWire)
	if err != nil {
		return time.Time{}, err
	}
	grantEnvelope, err := trust.DecodeEnvelope(inputs.anchor.Anchor().LedgerDelegationWire)
	if err != nil {
		return time.Time{}, err
	}
	expiresAt := minSeedTime(now.Add(seedRecordValidity), inputs.anchor.ExpiresAt(),
		inputs.plan.Plan().LaunchDeadline, planEnvelope.ExpiresAt,
		manifestEnvelope.ExpiresAt, grantEnvelope.ExpiresAt)
	if !expiresAt.After(now) {
		return time.Time{}, fmt.Errorf("%w: current seed proofs leave no signing lifetime", ErrSeedCLI)
	}
	return expiresAt, nil
}

func makeSeedReservation(inputs seedInputs, reviewedPlanDigest, createIdentity string,
	ledgerPrivate ed25519.PrivateKey, now time.Time,
) (seedReservation, error) {
	if !seedDigestRE.MatchString(reviewedPlanDigest) || !seedCreateRE.MatchString(createIdentity) ||
		!inputs.anchor.IsVerified() || inputs.manifest.Digest() == "" || !inputs.plan.IsVerified() {
		return seedReservation{}, ErrSeedCLI
	}
	expiresAt, err := seedRecordExpiry(inputs, now)
	if err != nil {
		return seedReservation{}, err
	}
	records, err := bootstrapstart.BuildExternalSeedReservation(bootstrapstart.ExternalSeedReservationRequest{
		Identity: inputs.identity, Anchor: inputs.anchor, Manifest: inputs.manifest,
		ReviewedPlanSHA256: reviewedPlanDigest, CreateIdentity: createIdentity,
		LedgerPrivate: ledgerPrivate, Now: now, ExpiresAt: expiresAt})
	if err != nil {
		return seedReservation{}, err
	}
	return seedReservation{SchemaVersion: seedBundleVersion, AnchorSHA256: inputs.anchor.Digest(),
		FounderPlanSHA256: inputs.plan.Digest(), ManifestSHA256: inputs.manifest.Digest(),
		ReviewedPlanSHA256: reviewedPlanDigest, Slot: seedSlot, CreateIdentity: createIdentity,
		IntentWire: records.IntentWire, InitialHeadWire: records.InitialHeadWire}, nil
}

func decodeSeedSignedRecord[T any](wire []byte, scope trust.Scope,
	grant trust.VerifiedDelegation, now time.Time, historical bool,
) (T, error) {
	var value T
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return value, err
	}
	var payload []byte
	if historical {
		payload, err = trust.VerifyDelegatedHistorical(envelope, scope, grant,
			bootstrap.ManifestTrustPolicy())
	} else {
		payload, err = trust.VerifyDelegatedCurrent(envelope, scope, grant, now,
			bootstrap.ManifestTrustPolicy())
	}
	if err != nil {
		return value, err
	}
	if err := protocol.DecodeStrict(payload, &value, bootstrap.MaxFounderPlanBytes); err != nil {
		return value, err
	}
	canonical, err := protocol.EncodeJSON(value)
	if err != nil || !bytes.Equal(canonical, payload) {
		return value, fmt.Errorf("%w: signed record payload is not canonical", ErrSeedCLI)
	}
	return value, nil
}

func verifySeedReservation(inputs seedInputs, reservation seedReservation,
	now time.Time, historical bool,
) (bootstrap.SlotState, error) {
	if reservation.SchemaVersion != seedBundleVersion || reservation.Slot != seedSlot ||
		reservation.AnchorSHA256 != inputs.anchor.Digest() ||
		reservation.FounderPlanSHA256 != inputs.planDigest ||
		reservation.ManifestSHA256 != inputs.manifest.Digest() ||
		!seedDigestRE.MatchString(reservation.ReviewedPlanSHA256) ||
		!seedCreateRE.MatchString(reservation.CreateIdentity) {
		return bootstrap.SlotState{}, ErrSeedCLI
	}
	grant, err := inputs.anchor.LedgerDelegation()
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	scope := trust.Scope{DeploymentID: inputs.identity.DeploymentID,
		Cell: string(inputs.identity.Cell), Environment: inputs.identity.Environment,
		Role: "controller", Slot: seedSlot}
	intentScope := scope
	intentScope.Domain = seedIntentDomain
	intent, err := decodeSeedSignedRecord[bootstrap.Intent](reservation.IntentWire, intentScope, grant, now, historical)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	headScope := scope
	headScope.Domain = seedHeadDomain
	head, err := decodeSeedSignedRecord[bootstrap.SlotHead](reservation.InitialHeadWire, headScope, grant, now, historical)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	profile, ok := inputs.manifest.Profile(seedSlot)
	if !ok {
		return bootstrap.SlotState{}, ErrSeedCLI
	}
	profileWire, err := trust.EncodePayload(profile)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	anchor := inputs.anchor.Anchor()
	if intent.SchemaVersion != 1 || intent.Mode != bootstrap.IntentModeExternalSeed ||
		intent.DeploymentID != anchor.DeploymentID || intent.Cell != string(anchor.Cell) ||
		intent.Environment != anchor.Environment || intent.Role != "controller" || intent.Slot != seedSlot ||
		intent.Attempt != 1 || intent.Generation != 1 || intent.ManifestDigest != inputs.manifest.Digest() ||
		intent.ReleaseReceiptDigest != inputs.manifest.Manifest().ReleaseReceiptSHA256 ||
		intent.RegionIntentGeneration != anchor.InitialRegionIntentGeneration ||
		intent.RegionIntentDigest != anchor.InitialRegionIntentSHA256 ||
		intent.ImageOCID != inputs.manifest.Manifest().ImageOCID ||
		intent.LaunchRequestDigest != seedDigest(profileWire) ||
		intent.ReviewedPlanDigest != reservation.ReviewedPlanSHA256 ||
		intent.CreateKey != reservation.CreateIdentity || intent.RetryToken != "" ||
		intent.OCIRegion != anchor.OCIRegion || intent.CompartmentOCID != profile.CompartmentOCID ||
		intent.AvailabilityDomain != profile.AvailabilityDomain || intent.FaultDomain != profile.FaultDomain ||
		intent.SubnetOCID != profile.SubnetOCID || intent.Shape != profile.Shape || intent.Node != seedSlot ||
		!slices.Equal(intent.NetworkSecurityGroupIDs, profile.NetworkSecurityGroupOCIDs) ||
		head.SchemaVersion != 1 || head.DeploymentID != intent.DeploymentID || head.Cell != intent.Cell ||
		head.Environment != intent.Environment || head.Role != intent.Role || head.Slot != seedSlot ||
		head.Attempt != 1 || head.Generation != 1 || head.IntentDigest != seedDigest(reservation.IntentWire) ||
		head.ResultDigest != "" || head.PreviousAttempt != 0 {
		return bootstrap.SlotState{}, ErrSeedCLI
	}
	intentEnvelope, err := trust.DecodeEnvelope(reservation.IntentWire)
	if err != nil || !intent.CreatedAt.Equal(intentEnvelope.IssuedAt) {
		return bootstrap.SlotState{}, ErrSeedCLI
	}
	return bootstrap.SlotState{Intent: intent, IntentRecord: bootstrap.StoredRecord{
		Bytes: slices.Clone(reservation.IntentWire), SHA256: seedDigest(reservation.IntentWire)},
		Head: head, HeadRecord: bootstrap.StoredRecord{Bytes: slices.Clone(reservation.InitialHeadWire),
			SHA256: seedDigest(reservation.InitialHeadWire)}}, nil
}

func (c command) signSeedReservationAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-external-seed-reservation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputFlags := addSeedInputFlags(flags)
	reviewedPlanPath := flags.String("reviewed-plan", "", "reviewed manual seed launch preflight JSON")
	reviewedPlanSHA := flags.String("reviewed-plan-sha256", "", "SHA-256 of the exact reviewed manual seed launch preflight")
	createIdentity := flags.String("create-identity", "", "exact OCI BootstrapCreateKey tag")
	ledgerKey := flags.String("ledger-signing-key", "", "owner-only raw founder-ledger.key from controller material")
	output := flags.String("out", "", "new signed reservation bundle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *reviewedPlanPath == "" || *reviewedPlanSHA == "" || *ledgerKey == "" || *output == "" || flags.NArg() != 0 {
		return fmt.Errorf("%w: reviewed manual seed plan, ledger signing key, and new output are required", ErrSeedCLI)
	}
	inputs, err := inputFlags.load(now)
	if err != nil {
		return err
	}
	_, err = readReviewedSeedPlan(*reviewedPlanPath, *reviewedPlanSHA, *createIdentity, inputs, now, true)
	if err != nil {
		return err
	}
	private, err := readSeedLedgerSigner(*ledgerKey, inputs.anchor)
	if err != nil {
		return err
	}
	defer clear(private)
	reservation, err := makeSeedReservation(inputs, *reviewedPlanSHA, *createIdentity, private, now)
	if err != nil {
		return err
	}
	if _, err := verifySeedReservation(inputs, reservation, now, false); err != nil {
		return err
	}
	if err := writeSeedBundle(*output, reservation); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed external seed reservation slot=%s intent=%s reviewed-plan=%s\n",
		seedSlot, seedDigest(reservation.IntentWire), reservation.ReviewedPlanSHA256)
	return nil
}

func openSeedOperatorLedger(ctx context.Context, inputs seedInputs,
	configPath, profile string,
) (*bootstrap.Ledger, common.ConfigurationProvider, error) {
	provider, err := seedOCIProvider(configPath, profile, inputs)
	if err != nil {
		return nil, nil, err
	}
	ledger, err := bootstrapstart.NewOperatorLedger(ctx, inputs.anchor, inputs.roots, provider)
	if err != nil {
		return nil, nil, err
	}
	return ledger, provider, nil
}

func (c command) publishSeedReservationAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("publish-external-seed-reservation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputFlags := addSeedInputFlags(flags)
	reservationPath := flags.String("reservation", "", "exact signed reservation bundle")
	configPath := flags.String("oci-config", "", "reviewed OCI operator API-key configuration")
	profile := flags.String("oci-profile", "DEFAULT", "reviewed OCI config profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *reservationPath == "" || flags.NArg() != 0 {
		return fmt.Errorf("%w: reservation is required", ErrSeedCLI)
	}
	inputs, err := inputFlags.load(now)
	if err != nil {
		return err
	}
	reservation, _, err := readSeedBundle[seedReservation](*reservationPath)
	if err != nil {
		return err
	}
	if _, err := verifySeedReservation(inputs, reservation, now, false); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()
	ledger, _, err := openSeedOperatorLedger(ctx, inputs, *configPath, *profile)
	if err != nil {
		return err
	}
	state, err := ledger.ReserveSlot(ctx, seedScope(inputs), reservation.IntentWire, reservation.InitialHeadWire)
	if err != nil {
		return err
	}
	if state.IntentRecord.SHA256 != seedDigest(reservation.IntentWire) ||
		state.Head.IntentDigest != state.IntentRecord.SHA256 {
		return fmt.Errorf("%w: persisted reservation differs from signed bundle", ErrSeedCLI)
	}
	fmt.Fprintf(c.output, "reserved external seed slot=%s intent=%s\n", seedSlot, state.IntentRecord.SHA256)
	return nil
}

func matchingSeedReservationState(state bootstrap.SlotState, reservation seedReservation) bool {
	return state.Intent.Mode == bootstrap.IntentModeExternalSeed &&
		state.IntentRecord.SHA256 == seedDigest(reservation.IntentWire) &&
		state.Head.IntentDigest == state.IntentRecord.SHA256 &&
		state.Intent.CreateKey == reservation.CreateIdentity &&
		state.Intent.ReviewedPlanDigest == reservation.ReviewedPlanSHA256
}

func (c command) observeExternalSeedAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("observe-external-seed", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputFlags := addSeedInputFlags(flags)
	reservationPath := flags.String("reservation", "", "published signed reservation bundle")
	reviewedPlanPath := flags.String("reviewed-plan", "", "exact reviewed manual seed launch preflight JSON")
	reviewedPlanSHA := flags.String("reviewed-plan-sha256", "", "SHA-256 of the exact reviewed manual seed launch preflight")
	instanceID := flags.String("instance-ocid", "", "exact manually created OCI seed instance OCID")
	configPath := flags.String("oci-config", "", "reviewed OCI operator API-key configuration")
	profile := flags.String("oci-profile", "DEFAULT", "reviewed OCI config profile")
	output := flags.String("out", "", "new read-only OCI seed observation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *reservationPath == "" || *reviewedPlanPath == "" || *reviewedPlanSHA == "" ||
		*instanceID == "" || *output == "" || flags.NArg() != 0 {
		return fmt.Errorf("%w: reservation, reviewed plan, exact instance OCID, and output are required", ErrSeedCLI)
	}
	inputs, err := inputFlags.load(now)
	if err != nil {
		return err
	}
	reservation, reservationWire, err := readSeedBundle[seedReservation](*reservationPath)
	if err != nil {
		return err
	}
	if _, err := verifySeedReservation(inputs, reservation, now, false); err != nil {
		return err
	}
	if *reviewedPlanSHA != reservation.ReviewedPlanSHA256 {
		return fmt.Errorf("%w: reviewed plan digest differs from signed reservation", ErrSeedCLI)
	}
	reviewed, err := readReviewedSeedPlan(*reviewedPlanPath, *reviewedPlanSHA,
		reservation.CreateIdentity, inputs, now, false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()
	ledger, provider, err := openSeedOperatorLedger(ctx, inputs, *configPath, *profile)
	if err != nil {
		return err
	}
	state, err := ledger.ReadSlot(ctx, seedScope(inputs))
	if err != nil || !matchingSeedReservationState(state, reservation) || state.Head.ResultDigest != "" {
		return fmt.Errorf("%w: exact first-seed reservation is absent or already complete: %v", ErrSeedCLI, err)
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(inputs.identity.Cell, provider)
	if err != nil {
		return err
	}
	observed, err := observer.ObserveInstance(ctx, *instanceID)
	if err != nil {
		return err
	}
	if _, err := bootstrapstart.VerifyExternalSeedObservation(inputs.anchor, inputs.manifest,
		state, observed, inputs.plan.Plan().SeedPrivateIP); err != nil {
		return err
	}
	reader, err := newSeedSizingReader(inputs.anchor.Anchor().OCIRegion, provider)
	if err != nil {
		return err
	}
	if err := reader.verifyReadback(ctx, observed, reviewed); err != nil {
		return err
	}
	observation := seedObservationFromOCI(seedDigest(reservationWire), observed, now)
	if err := writeSeedBundle(*output, observation); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "observed exact external seed slot=%s instance=%s reservation=%s\n",
		seedSlot, observed.InstanceOCID, observation.ReservationSHA256)
	return nil
}

func verifySeedObservation(inputs seedInputs, reservation seedReservation,
	reservationWire []byte, observation seedObservation, now time.Time, allowStale bool,
) (bootstrap.InstanceFacts, bootstrap.SlotState, error) {
	state, err := verifySeedReservation(inputs, reservation, now, false)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.SlotState{}, err
	}
	if observation.SchemaVersion != seedBundleVersion ||
		observation.ReservationSHA256 != seedDigest(reservationWire) ||
		observation.ObservedAt.IsZero() || observation.ObservedAt.Location() != time.UTC ||
		observation.ObservedAt.After(now.Add(bootstrap.ManifestClockSkew)) ||
		!allowStale && now.Sub(observation.ObservedAt) > bootstrap.ExternalSeedObservationMaxAge ||
		observation.InstanceOCID == "" || observation.ETag == "" ||
		observation.PrimaryVNICOCID == "" {
		return bootstrap.InstanceFacts{}, bootstrap.SlotState{}, ErrSeedCLI
	}
	facts, err := bootstrapstart.VerifyExternalSeedObservation(inputs.anchor, inputs.manifest,
		state, observation.instanceObservation(), inputs.seedPrivateIP)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.SlotState{}, err
	}
	return facts, state, nil
}

func makeSeedCompletion(inputs seedInputs, reservation seedReservation, reservationWire []byte,
	observation seedObservation, rootPrivate, ledgerPrivate ed25519.PrivateKey,
	now time.Time,
) (seedCompletion, error) {
	return makeSeedCompletionUsingReceipt(inputs, reservation, reservationWire, observation,
		rootPrivate, ledgerPrivate, nil, now)
}

func makeSeedCompletionUsingReceipt(inputs seedInputs, reservation seedReservation, reservationWire []byte,
	observation seedObservation, rootPrivate, ledgerPrivate ed25519.PrivateKey,
	reuseReceiptWire []byte, now time.Time,
) (seedCompletion, error) {
	_, state, err := verifySeedObservation(inputs, reservation, reservationWire, observation, now, false)
	if err != nil {
		return seedCompletion{}, err
	}
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), inputs.rootPublic) {
		return seedCompletion{}, fmt.Errorf("%w: offline root signing key mismatch", ErrSeedCLI)
	}
	expiresAt, err := seedRecordExpiry(inputs, now)
	if err != nil {
		return seedCompletion{}, err
	}
	records, err := bootstrapstart.BuildExternalSeedCompletion(bootstrapstart.ExternalSeedCompletionRequest{
		Identity: inputs.identity, Anchor: inputs.anchor, Manifest: inputs.manifest,
		Roots: inputs.roots, State: state, Observation: observation.instanceObservation(),
		ObservedAt: observation.ObservedAt, ExpectedPrivateIP: inputs.plan.Plan().SeedPrivateIP,
		RootPrivate: rootPrivate, LedgerPrivate: ledgerPrivate, ReuseReceiptWire: reuseReceiptWire,
		Now: now, ExpiresAt: expiresAt})
	if err != nil {
		return seedCompletion{}, err
	}
	return seedCompletion{SchemaVersion: seedBundleVersion,
		ReservationSHA256: seedDigest(reservationWire), Observation: observation,
		ReceiptWire: records.ReceiptWire, ResultWire: records.ResultWire,
		CompletedHeadWire: records.CompletedHeadWire}, nil
}

func (c command) signSeedCompletionAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-external-seed-completion", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputFlags := addSeedInputFlags(flags)
	reservationPath := flags.String("reservation", "", "exact signed reservation bundle")
	observationPath := flags.String("observation", "", "exact read-only OCI observation")
	rootPrivatePath := flags.String("signing-key", "", "owner-only offline root private PEM")
	ledgerPrivatePath := flags.String("ledger-signing-key", "", "owner-only raw founder-ledger.key from controller material")
	reuseReceiptPath := flags.String("reuse-receipt-from", "", "prior completion whose exact root receipt may already be stored")
	output := flags.String("out", "", "new signed seed completion bundle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *reservationPath == "" || *observationPath == "" || *rootPrivatePath == "" ||
		*ledgerPrivatePath == "" || *output == "" || flags.NArg() != 0 {
		return fmt.Errorf("%w: reservation, observation, both private keys, and new output are required", ErrSeedCLI)
	}
	inputs, err := inputFlags.load(now)
	if err != nil {
		return err
	}
	reservation, reservationWire, err := readSeedBundle[seedReservation](*reservationPath)
	if err != nil {
		return err
	}
	observation, _, err := readSeedBundle[seedObservation](*observationPath)
	if err != nil {
		return err
	}
	rootPrivate, err := readRootPrivateKey(*rootPrivatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	ledgerPrivate, err := readSeedLedgerSigner(*ledgerPrivatePath, inputs.anchor)
	if err != nil {
		return err
	}
	defer clear(ledgerPrivate)
	var reuseReceiptWire []byte
	if *reuseReceiptPath != "" {
		prior, _, readErr := readSeedBundle[seedCompletion](*reuseReceiptPath)
		if readErr != nil {
			return readErr
		}
		if prior.SchemaVersion != seedBundleVersion || prior.ReservationSHA256 != seedDigest(reservationWire) {
			return fmt.Errorf("%w: prior completion does not match reservation", ErrSeedCLI)
		}
		reuseReceiptWire = prior.ReceiptWire
	}
	completion, err := makeSeedCompletionUsingReceipt(inputs, reservation, reservationWire, observation,
		rootPrivate, ledgerPrivate, reuseReceiptWire, now)
	if err != nil {
		return err
	}
	if err := writeSeedBundle(*output, completion); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed external seed completion slot=%s instance=%s receipt=%s result=%s\n",
		seedSlot, observation.InstanceOCID, seedDigest(completion.ReceiptWire), seedDigest(completion.ResultWire))
	return nil
}

func verifySeedCompletion(inputs seedInputs, reservation seedReservation,
	reservationWire []byte, completion seedCompletion, now time.Time, allowStale bool,
) (bootstrap.InstanceFacts, bootstrap.Result, bootstrap.SlotHead, error) {
	if completion.SchemaVersion != seedBundleVersion ||
		completion.ReservationSHA256 != seedDigest(reservationWire) {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, ErrSeedCLI
	}
	facts, state, err := verifySeedObservation(inputs, reservation, reservationWire,
		completion.Observation, now, allowStale)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	receiptEnvelope, err := trust.DecodeEnvelope(completion.ReceiptWire)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	if _, err := bootstrap.VerifySeedReceipt(receiptEnvelope, inputs.manifest, inputs.roots,
		facts, now, bootstrap.ManifestTrustPolicy()); err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	grant, err := inputs.anchor.LedgerDelegation()
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	scope := trust.Scope{DeploymentID: inputs.identity.DeploymentID,
		Cell: string(inputs.identity.Cell), Environment: inputs.identity.Environment,
		Role: "controller", Slot: seedSlot}
	resultScope := scope
	resultScope.Domain = seedResultDomain
	result, err := decodeSeedSignedRecord[bootstrap.Result](completion.ResultWire, resultScope, grant, now, false)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	headScope := scope
	headScope.Domain = seedHeadDomain
	head, err := decodeSeedSignedRecord[bootstrap.SlotHead](completion.CompletedHeadWire, headScope, grant, now, false)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	profileWire, err := trust.EncodePayload(facts.Profile)
	if err != nil {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, err
	}
	if result.SchemaVersion != 1 || result.Mode != bootstrap.IntentModeExternalSeed ||
		result.DeploymentID != state.Intent.DeploymentID || result.Cell != state.Intent.Cell ||
		result.Environment != state.Intent.Environment || result.Role != "controller" || result.Slot != seedSlot ||
		result.Attempt != 1 || result.Generation != 1 ||
		result.RegionIntentGeneration != state.Intent.RegionIntentGeneration ||
		result.IntentDigest != state.IntentRecord.SHA256 ||
		result.InstanceOCID != completion.Observation.InstanceOCID ||
		result.ETag != completion.Observation.ETag || result.OCIRegion != state.Intent.OCIRegion ||
		result.CompartmentOCID != facts.CompartmentOCID || result.ImageOCID != facts.ImageOCID ||
		result.Shape != facts.Profile.Shape || result.ObservedProfileDigest != seedDigest(profileWire) ||
		result.SeedReceiptDigest != seedDigest(completion.ReceiptWire) ||
		result.CreateKey != state.Intent.CreateKey ||
		!result.ObservedAt.Equal(completion.Observation.ObservedAt) ||
		head.SchemaVersion != 1 || head.DeploymentID != state.Head.DeploymentID ||
		head.Cell != state.Head.Cell || head.Environment != state.Head.Environment ||
		head.Role != state.Head.Role || head.Slot != seedSlot || head.Attempt != 1 ||
		head.Generation != 1 || head.IntentDigest != state.Head.IntentDigest ||
		head.ResultDigest != seedDigest(completion.ResultWire) || head.PreviousAttempt != 0 {
		return bootstrap.InstanceFacts{}, bootstrap.Result{}, bootstrap.SlotHead{}, ErrSeedCLI
	}
	return facts, result, head, nil
}

func sameSeedOCIObservation(expected seedObservation, current bootstrapstart.InstanceObservation,
	checkETag bool,
) bool {
	if expected.InstanceOCID != current.InstanceOCID ||
		expected.BootstrapCreateKey != current.BootstrapCreateKey ||
		expected.CompartmentOCID != current.CompartmentOCID || expected.ImageOCID != current.ImageOCID ||
		expected.AvailabilityDomain != current.AvailabilityDomain ||
		expected.FaultDomain != current.FaultDomain || expected.Shape != current.Shape ||
		expected.SubnetOCID != current.SubnetOCID ||
		expected.PrimaryVNICOCID != current.PrimaryVNICOCID ||
		expected.PrimaryPrivateIP != current.PrimaryPrivateIP ||
		expected.LifecycleState != current.LifecycleState ||
		checkETag && expected.ETag != current.ETag {
		return false
	}
	left := slices.Clone(expected.NetworkSecurityGroupOCIDs)
	right := slices.Clone(current.NSGOCIDs)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func seedCompletionMatchesCommitted(state bootstrap.SlotState, reservation seedReservation,
	reservationWire []byte, completion seedCompletion, manifestWire []byte,
) bool {
	return matchingSeedReservationState(state, reservation) &&
		completion.SchemaVersion == seedBundleVersion &&
		completion.ReservationSHA256 == seedDigest(reservationWire) &&
		completion.Observation.ReservationSHA256 == completion.ReservationSHA256 &&
		state.Head.ResultDigest == seedDigest(completion.ResultWire) &&
		state.HeadRecord.SHA256 == seedDigest(completion.CompletedHeadWire) &&
		state.ResultRecord != nil && state.ResultRecord.SHA256 == state.Head.ResultDigest &&
		state.SeedReceiptRecord != nil &&
		state.SeedReceiptRecord.SHA256 == seedDigest(completion.ReceiptWire) &&
		state.ManifestRecord != nil && state.ManifestRecord.SHA256 == seedDigest(manifestWire) &&
		state.Result != nil && state.Result.InstanceOCID == completion.Observation.InstanceOCID &&
		state.Result.ETag == completion.Observation.ETag &&
		state.Result.ObservedAt.Equal(completion.Observation.ObservedAt)
}

func verifyCompletedSeedReplay(inputs seedInputs, plan bootstrap.VerifiedCompletedFounderPlan,
	state bootstrap.SlotState, reservation seedReservation, reservationWire []byte,
	completion seedCompletion, now time.Time,
) error {
	if _, err := verifySeedReservation(inputs, reservation, now, true); err != nil {
		return err
	}
	if !seedCompletionMatchesCommitted(state, reservation, reservationWire, completion,
		inputs.manifestWire) || completion.Observation.SchemaVersion != seedBundleVersion ||
		state.ResultRecord == nil ||
		!plan.StoredCompletionBeforeLaunchDeadline(state.IntentRecord.LastModified,
			state.HeadRecord.LastModified) ||
		!plan.StoredCompletionBeforeLaunchDeadline(state.ResultRecord.LastModified,
			state.HeadRecord.LastModified) {
		return fmt.Errorf("%w: exact seed completion was not durably stored before the founder deadline", ErrSeedCLI)
	}
	if _, err := bootstrapstart.VerifyExternalSeedObservation(inputs.anchor, inputs.manifest,
		state, completion.Observation.instanceObservation(), inputs.seedPrivateIP); err != nil {
		return err
	}
	return nil
}

func (c command) reconcileCompletedSeedAfterDeadline(flags *seedInputFlags, reservationPath,
	completionPath, configPath, profile string, now time.Time,
) error {
	inputs, plan, err := loadCompletedSeedInputs(*flags.identity, *flags.anchor,
		*flags.plan, *flags.root, flags.manifest, now)
	if err != nil {
		return err
	}
	reservation, reservationWire, err := readSeedBundle[seedReservation](reservationPath)
	if err != nil {
		return err
	}
	completion, _, err := readSeedBundle[seedCompletion](completionPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()
	ledger, _, err := openSeedOperatorLedger(ctx, inputs, configPath, profile)
	if err != nil {
		return err
	}
	state, err := ledger.ReadSlot(ctx, seedScope(inputs))
	if err != nil {
		return err
	}
	if err := verifyCompletedSeedReplay(inputs, plan, state, reservation,
		reservationWire, completion, now); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "external seed completion already committed slot=%s result=%s\n",
		seedSlot, state.Head.ResultDigest)
	return nil
}

func (c command) publishSeedCompletionAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("publish-external-seed-completion", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputFlags := addSeedInputFlags(flags)
	reservationPath := flags.String("reservation", "", "published signed reservation bundle")
	completionPath := flags.String("completion", "", "exact signed completion bundle")
	reviewedPlanPath := flags.String("reviewed-plan", "", "exact reviewed manual seed launch preflight JSON")
	reviewedPlanSHA := flags.String("reviewed-plan-sha256", "", "SHA-256 of the exact reviewed manual seed launch preflight")
	configPath := flags.String("oci-config", "", "reviewed OCI operator API-key configuration")
	profile := flags.String("oci-profile", "DEFAULT", "reviewed OCI config profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *reservationPath == "" || *completionPath == "" || flags.NArg() != 0 {
		return fmt.Errorf("%w: reservation and completion are required", ErrSeedCLI)
	}
	inputs, err := inputFlags.load(now)
	if errors.Is(err, bootstrap.ErrFounderPlanExpired) {
		return c.reconcileCompletedSeedAfterDeadline(inputFlags, *reservationPath,
			*completionPath, *configPath, *profile, now)
	}
	if err != nil {
		return err
	}
	reservation, reservationWire, err := readSeedBundle[seedReservation](*reservationPath)
	if err != nil {
		return err
	}
	completion, _, err := readSeedBundle[seedCompletion](*completionPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()
	ledger, provider, err := openSeedOperatorLedger(ctx, inputs, *configPath, *profile)
	if err != nil {
		return err
	}
	state, err := ledger.ReadSlot(ctx, seedScope(inputs))
	if err != nil || !matchingSeedReservationState(state, reservation) {
		return fmt.Errorf("%w: persisted reservation differs from signed completion: %v", ErrSeedCLI, err)
	}
	if state.Head.ResultDigest != "" {
		if !seedCompletionMatchesCommitted(state, reservation, reservationWire, completion,
			inputs.manifestWire) {
			return fmt.Errorf("%w: seed slot is complete with different proof bytes", ErrSeedCLI)
		}
		if _, _, _, err := verifySeedCompletion(inputs, reservation, reservationWire,
			completion, now, true); err != nil {
			return err
		}
		fmt.Fprintf(c.output, "external seed completion already committed slot=%s result=%s\n",
			seedSlot, state.Head.ResultDigest)
		return nil
	}
	if *reviewedPlanPath == "" || *reviewedPlanSHA != reservation.ReviewedPlanSHA256 {
		return fmt.Errorf("%w: exact reviewed seed plan is required before a new completion", ErrSeedCLI)
	}
	reviewed, err := readReviewedSeedPlan(*reviewedPlanPath, *reviewedPlanSHA,
		reservation.CreateIdentity, inputs, now, false)
	if err != nil {
		return err
	}
	_, receiptStored, resultStored, err := ledger.ExternalSeedProgress(ctx, seedScope(inputs),
		inputs.manifestWire, completion.ReceiptWire, completion.ResultWire)
	if err != nil {
		return err
	}
	if !resultStored && now.Sub(completion.Observation.ObservedAt) > bootstrap.ExternalSeedObservationMaxAge {
		if receiptStored {
			return fmt.Errorf("%w: observation is stale; obtain a fresh OCI observation and re-sign using --reuse-receipt-from", ErrSeedCLI)
		}
		return fmt.Errorf("%w: observation is stale; obtain a fresh OCI observation and re-sign completion", ErrSeedCLI)
	}
	if _, _, _, err := verifySeedCompletion(inputs, reservation, reservationWire, completion, now, resultStored); err != nil {
		return err
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(inputs.identity.Cell, provider)
	if err != nil {
		return err
	}
	current, err := observer.ObserveInstance(ctx, completion.Observation.InstanceOCID)
	if err != nil {
		return err
	}
	if !sameSeedOCIObservation(completion.Observation, current, true) {
		return fmt.Errorf("%w: fresh exact OCI seed readback differs from signed observation", ErrSeedCLI)
	}
	reader, err := newSeedSizingReader(inputs.anchor.Anchor().OCIRegion, provider)
	if err != nil {
		return err
	}
	if err := reader.verifyReadback(ctx, current, reviewed); err != nil {
		return err
	}
	facts, err := bootstrapstart.VerifyExternalSeedObservation(inputs.anchor, inputs.manifest,
		state, current, inputs.plan.Plan().SeedPrivateIP)
	if err != nil {
		return err
	}
	state, err = ledger.RecordExternalSeed(ctx, seedScope(inputs), inputs.manifestWire,
		completion.ReceiptWire, facts, completion.ResultWire, completion.CompletedHeadWire)
	if err != nil {
		return err
	}
	if state.Head.ResultDigest != seedDigest(completion.ResultWire) ||
		state.SeedReceiptRecord == nil || state.SeedReceiptRecord.SHA256 != seedDigest(completion.ReceiptWire) {
		return fmt.Errorf("%w: committed seed result differs from signed completion", ErrSeedCLI)
	}
	fmt.Fprintf(c.output, "committed external seed slot=%s instance=%s result=%s\n",
		seedSlot, completion.Observation.InstanceOCID, state.Head.ResultDigest)
	return nil
}
