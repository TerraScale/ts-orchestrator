package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ControllerHostRecipient proves an existing controller's signed slot and live
// OCI identity. The caller must separately fence adoption of its exact spec.
type ControllerHostRecipient struct {
	reader     *CurrentFounderAuthorityReader
	sources    controllerRecipientSources
	issuer     AcceptedIdentity
	spec       []byte
	node       string
	instanceID string
	privateIP  string
	slot       string
	region     string
	domain     bootstrap.ControllerFailureDomain
	started    time.Time
	validUntil time.Time
}

type controllerRecipientSources struct {
	trust    bakedStore
	ledger   *bootstrap.Ledger
	observer *OCIInstanceObserver
}

// ReadControllerHostRecipient derives the requested slot only from the root's
// signed host grant. It issues neither launch permission nor worker projection.
func ReadControllerHostRecipient(ctx context.Context, reader *CurrentFounderAuthorityReader, issuer AcceptedIdentity,
	signedSpec []byte, node, instanceID, privateIP string,
) (*ControllerHostRecipient, error) {
	return readControllerHostRecipient(ctx, reader, issuer, signedSpec, node, instanceID, privateIP,
		controllerRecipientSources{trust: bakedStore{directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0}})
}

func readControllerHostRecipient(ctx context.Context, reader *CurrentFounderAuthorityReader, issuer AcceptedIdentity,
	signedSpec []byte, node, instanceID, privateIP string, sources controllerRecipientSources,
) (*ControllerHostRecipient, error) {
	started := time.Now()
	proof := &ControllerHostRecipient{reader: reader, sources: sources, issuer: issuer.Clone(), spec: bytes.Clone(signedSpec),
		node: node, instanceID: instanceID, privateIP: privateIP, started: started,
		validUntil: started.Add(bootstrap.ManagedPeerObservationMaxAge)}
	grant, authority, err := proof.current(ctx)
	if err != nil {
		return nil, err
	}
	proof.slot, proof.region = grant.Controller, authority.identity.OCIRegion
	proof.domain, _ = authority.ControllerFailureDomain(grant.Controller)
	if authority.expires.Before(proof.validUntil) {
		proof.validUntil = authority.expires
	}
	if !proof.Valid(time.Now()) {
		return nil, bootstrap.ErrManagedPeerObservationStale
	}
	return proof, nil
}

func (proof *ControllerHostRecipient) ControllerSlot() string { return proof.slot }
func (proof *ControllerHostRecipient) Node() string           { return proof.node }
func (proof *ControllerHostRecipient) InstanceID() string     { return proof.instanceID }
func (proof *ControllerHostRecipient) PrivateIP() string      { return proof.privateIP }
func (proof *ControllerHostRecipient) OCIRegion() string      { return proof.region }
func (proof *ControllerHostRecipient) FailureDomain() bootstrap.ControllerFailureDomain {
	return proof.domain
}
func (proof *ControllerHostRecipient) Environment() string { return proof.issuer.Environment }
func (proof *ControllerHostRecipient) SpecSHA256() string  { return digestWire(proof.spec) }

// Valid is a cheap final check after task reads. Verification never extends the
// constructor's fixed observation interval or any signed authority deadline.
func (proof *ControllerHostRecipient) Valid(now time.Time) bool {
	return proof != nil && proof.slot != "" && proof.region != "" && proof.domain.Region == proof.region &&
		proof.domain.AvailabilityDomain != "" && proof.domain.FaultDomain != "" && !now.IsZero() &&
		!proof.started.IsZero() && !now.Before(proof.started) && now.Before(proof.validUntil) &&
		time.Now().Before(proof.validUntil) && time.Now().Before(proof.started.Add(bootstrap.ManagedPeerObservationMaxAge))
}

// Verify repeats all signed-source, current-root, ledger and OCI reads.
func (proof *ControllerHostRecipient) Verify(ctx context.Context) error {
	if !proof.Valid(time.Now()) {
		return ErrAdmission
	}
	_, _, err := proof.current(ctx)
	if err == nil && !proof.Valid(time.Now()) {
		return bootstrap.ErrManagedPeerObservationStale
	}
	return err
}

// VerifyRegistration adds the independent ownhost registration comparison;
// completed enrollment, revocation and the actual Agent remain separate gates.
func (proof *ControllerHostRecipient) VerifyRegistration(ctx context.Context, registration host.Registration) error {
	if !proof.Valid(time.Now()) {
		return ErrAdmission
	}
	grant, authority, err := proof.current(ctx)
	if err != nil {
		return err
	}
	if registration.ID != entityid.Derive("host", strings.ToLower(authority.identity.Cell), proof.node) ||
		registration.Node != proof.node || registration.Cell != strings.ToLower(authority.identity.Cell) ||
		registration.Environment != proof.issuer.Environment || registration.Generation == 0 ||
		registration.FailureDomain != strings.ToLower(proof.domain.FaultDomain) ||
		!slices.Equal(registration.Roles, grant.Roles) || registration.ManagedOCI != nil ||
		registration.ManagedMember != nil || registration.ManagedPlacement != nil {
		return errors.New("controller registration differs from its signed slot and host grant")
	}
	if !proof.Valid(time.Now()) {
		return bootstrap.ErrManagedPeerObservationStale
	}
	return nil
}

func (proof *ControllerHostRecipient) current(ctx context.Context) (cellspec.HostGrant, RuntimeAuthority, error) {
	fail := func(err error) (cellspec.HostGrant, RuntimeAuthority, error) {
		return cellspec.HostGrant{}, RuntimeAuthority{}, err
	}
	if proof == nil || proof.reader == nil || proof.issuer.Validate() != nil || proof.node == "" ||
		!instanceIDRE.MatchString(proof.instanceID) || !validPrivateIPv4(proof.privateIP) ||
		len(proof.spec) == 0 || len(proof.spec) > cellspec.MaxSignedBytes || proof.started.IsZero() ||
		!time.Now().Before(proof.validUntil) || !time.Now().Before(proof.started.Add(bootstrap.ManagedPeerObservationMaxAge)) {
		return fail(ErrAdmission)
	}
	ctx, stop := context.WithDeadline(ctx, proof.started.Add(bootstrap.ManagedPeerObservationMaxAge))
	defer stop()
	inputs, err := proof.sources.trust.loadTrustInputs(proof.issuer)
	if err != nil {
		return fail(err)
	}
	// The fixed adopted chain supplies both current grants and historical
	// launch verification; a caller-provided keyring cannot select authority.
	reader := *proof.reader
	reader.baked = proof.reader.baked
	reader.baked.Roots = inputs.Roots.Historical
	authority, err := reader.ReadRuntimeAuthority(ctx, proof.issuer, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	identity := authority.identity
	signed, err := cellspec.VerifyHistorical(proof.spec, inputs.Roots.Current, cellspec.Identity{
		DeploymentID: identity.DeploymentID, Cell: strings.ToLower(identity.Cell), Environment: identity.Environment})
	if err != nil || !signed.RootSigned {
		return fail(errors.New("controller recipient requires a root-signed host grant under current roots"))
	}
	grant, ok := signed.Grant(proof.node)
	if !ok || grant.Controller == "" || grant.Node != proof.node || grant.Environment != identity.Environment ||
		grant.PrivateIP != proof.privateIP || len(grant.Roles) == 0 || slices.Contains(grant.Roles, "function-worker") ||
		slices.Contains(grant.Roles, "terrabase") || !slices.Contains(authority.plan.ControllerSlots, grant.Controller) ||
		proof.slot != "" && proof.slot != grant.Controller || proof.region != "" && proof.region != identity.OCIRegion {
		return fail(errors.New("controller recipient differs from its signed host grant"))
	}
	domain, ok := authority.ControllerFailureDomain(grant.Controller)
	if !ok || proof.domain != (bootstrap.ControllerFailureDomain{}) && proof.domain != domain {
		return fail(errors.New("controller recipient failure domain changed from its verified topology"))
	}
	if authority.anchor.ExpiresAt().Before(authority.expires) {
		authority.expires = authority.anchor.ExpiresAt()
	}
	ctx, cancel := context.WithDeadline(ctx, authority.expires)
	defer cancel()
	var ledger SlotReader
	if proof.sources.ledger != nil {
		ledger = proof.sources.ledger
	} else if reader.derived != nil {
		ledger, err = reader.derived.OpenLedger(ctx, reader.baked.Roots)
	} else {
		config, configErr := currentLedgerConfig(authority.anchor, reader.baked.Roots)
		if configErr != nil {
			return fail(configErr)
		}
		ledger, err = openInstancePrincipalLedger(ctx, config, nil)
	}
	if err != nil {
		return fail(err)
	}
	scope := bootstrap.BootstrapScope{DeploymentID: identity.DeploymentID, Cell: identity.Cell, Slot: grant.Controller}
	state, err := readSlot(ctx, ledger, scope)
	if err != nil {
		return fail(err)
	}
	if err := proof.checkCompletedSlot(authority, grant, state); err != nil {
		return fail(err)
	}
	observer := proof.sources.observer
	if observer == nil {
		observer, err = reader.RuntimeInstanceObserver(ctx, proof.issuer)
		if err != nil {
			return fail(err)
		}
	}
	observed, err := (Gate{Instances: observer}).observe(ctx, proof.instanceID, state, authority.anchor.Anchor())
	if err != nil {
		return fail(err)
	}
	if observed.AvailabilityDomain != domain.AvailabilityDomain || observed.FaultDomain != domain.FaultDomain ||
		observed.PrimaryPrivateIP != grant.PrivateIP || grant.Controller == proof.issuer.Slot &&
		(observed.InstanceOCID != proof.issuer.InstanceOCID || observed.ImageOCID != proof.issuer.ImageOCID ||
			observed.PrimaryVNICOCID != proof.issuer.PrimaryVNICOCID || observed.PrimaryPrivateIP != proof.issuer.PrimaryPrivateIP) {
		return fail(errors.New("controller recipient differs from its live primary address or accepted local identity"))
	}
	startup, err := controllerRecipientStartup(ctx, authority, reader.baked.Roots, grant.Controller, state.Intent.ImageOCID)
	if err != nil {
		return fail(err)
	}
	if startup.ExpiresAt().Before(authority.expires) {
		authority.expires = startup.ExpiresAt()
	}
	expectedReceipt, err := bootstrap.NewReceipt(startup, observed.Facts)
	if err != nil {
		return fail(err)
	}
	receipt := state.PeerReceipt
	if grant.Controller == authority.plan.SeedSlot {
		receipt = state.SeedReceipt
	}
	if receipt == nil || *receipt != expectedReceipt {
		return fail(errors.New("controller recipient differs from its protected historical receipt and live OCI facts"))
	}
	confirmed, err := readSlot(ctx, ledger, scope)
	if err != nil {
		return fail(err)
	}
	if !sameControllerRecipientSlot(state, confirmed) {
		return fail(errors.New("controller slot changed during live recipient verification"))
	}
	current, err := reader.ReadRuntimeAuthority(ctx, proof.issuer, time.Now().UTC())
	if err != nil || current.identity != identity || current.selectionDigest != authority.selectionDigest ||
		current.planDigest != authority.planDigest || !time.Now().Before(authority.expires) {
		return fail(errors.New("controller issuer authority changed during live recipient verification"))
	}
	if confirmedDomain, ok := current.ControllerFailureDomain(grant.Controller); !ok || confirmedDomain != domain {
		return fail(errors.New("controller failure domain changed during live recipient verification"))
	}
	freshRoots, err := proof.sources.trust.loadTrustInputs(proof.issuer)
	if err != nil || freshRoots.Roots.Head != inputs.Roots.Head || freshRoots.Roots.Sequence != inputs.Roots.Sequence {
		return fail(errors.New("adopted roots changed during controller recipient verification"))
	}
	if !time.Now().Before(authority.expires) || !time.Now().Before(proof.validUntil) ||
		!time.Now().Before(proof.started.Add(bootstrap.ManagedPeerObservationMaxAge)) {
		return fail(bootstrap.ErrManagedPeerObservationStale)
	}
	if proof.slot != "" && authority.expires.Before(proof.validUntil) {
		return fail(errors.New("controller recipient authority shortened; reconstruct its proof"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return grant, authority, nil
}

func (proof *ControllerHostRecipient) checkCompletedSlot(authority RuntimeAuthority, grant cellspec.HostGrant, state bootstrap.SlotState) error {
	identity := authority.identity
	if state.ManifestRecord == nil || state.Result == nil || state.ResultRecord == nil ||
		state.Head.ResultDigest != state.ResultRecord.SHA256 || state.Result.InstanceOCID != proof.instanceID ||
		state.Intent.DeploymentID != identity.DeploymentID || state.Intent.Cell != identity.Cell ||
		state.Intent.Environment != identity.Environment || state.Intent.Slot != grant.Controller ||
		state.Head.Attempt != state.Intent.Attempt || state.Head.Generation != state.Intent.Generation ||
		state.Result.Attempt != state.Head.Attempt || state.Intent.ManifestDigest != state.ManifestRecord.SHA256 ||
		state.ManifestRecord.SHA256 != digestWire(authority.manifests[grant.Controller]) {
		return errors.New("controller recipient has no exact currently selected completed slot")
	}
	if grant.Controller == authority.plan.SeedSlot {
		if state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Result.Mode != bootstrap.IntentModeExternalSeed ||
			state.SeedReceipt == nil || state.SeedReceiptRecord == nil || state.Result.SeedReceiptDigest != state.SeedReceiptRecord.SHA256 ||
			grant.PrivateIP != authority.plan.SeedPrivateIP {
			return ErrAdmission
		}
		return nil
	}
	if state.Intent.Mode != bootstrap.IntentModeManaged || state.Result.Mode != bootstrap.IntentModeManaged ||
		state.Candidate == nil || state.CandidateRecord == nil || state.PeerReceipt == nil || state.PeerReceiptRecord == nil ||
		state.Head.CandidateDigest != state.CandidateRecord.SHA256 || state.Candidate.InstanceOCID != proof.instanceID ||
		state.Candidate.IntentDigest != state.IntentRecord.SHA256 || state.Result.PeerReceiptDigest != state.PeerReceiptRecord.SHA256 ||
		state.Intent.FounderPlanSHA256 != authority.planDigest ||
		state.ResultRecord.LastModified.IsZero() || state.HeadRecord.LastModified.IsZero() ||
		state.ResultRecord.LastModified.Add(time.Second).After(authority.plan.LaunchDeadline) ||
		state.HeadRecord.LastModified.Add(time.Second).After(authority.plan.LaunchDeadline) {
		return errors.New("controller peer lacks its exact protected candidate, result and receipt")
	}
	for _, row := range authority.plan.Peers {
		if row.Slot != grant.Controller {
			continue
		}
		rowDigest, err := bootstrap.FounderPeerRowDigest(row)
		if err == nil && rowDigest == state.Intent.PeerRowDigest && state.Candidate.FounderPlanSHA256 == authority.planDigest &&
			state.Candidate.PeerRowDigest == rowDigest && row.PrivateIP == grant.PrivateIP && row.ImageOCID == state.Intent.ImageOCID &&
			row.ManifestSHA256 == state.ManifestRecord.SHA256 && row.CompartmentOCID == state.Intent.CompartmentOCID {
			return nil
		}
	}
	return ErrAdmission
}

func sameControllerRecipientSlot(before, after bootstrap.SlotState) bool {
	// OCI's per-read ServerDate changes even when the signed object does not.
	for _, pair := range [][2]*bootstrap.StoredRecord{
		{&before.HeadRecord, &after.HeadRecord}, {&before.IntentRecord, &after.IntentRecord},
		{before.ManifestRecord, after.ManifestRecord}, {before.ResultRecord, after.ResultRecord},
		{before.PeerReceiptRecord, after.PeerReceiptRecord}, {before.SeedReceiptRecord, after.SeedReceiptRecord},
		{before.CandidateRecord, after.CandidateRecord}, {before.ProgressRecord, after.ProgressRecord},
	} {
		left, right := pair[0], pair[1]
		if left == nil || right == nil {
			if left != right {
				return false
			}
			continue
		}
		if left.SHA256 != right.SHA256 || left.ETag != right.ETag ||
			!left.LastModified.Equal(right.LastModified) || !bytes.Equal(left.Bytes, right.Bytes) {
			return false
		}
	}
	return true
}

func controllerRecipientStartup(ctx context.Context, authority RuntimeAuthority, roots trust.Keyring, slot, image string) (bootstrap.StartupAuthority, error) {
	if authority.derived != nil {
		startup, ok := authority.derived.Authority(slot)
		if !ok || startup.VerifyCurrent(ctx, time.Now().UTC()) != nil {
			return nil, ErrAdmission
		}
		return startup, nil
	}
	envelope, err := trust.DecodeEnvelope(authority.manifests[slot])
	if err != nil {
		return nil, err
	}
	expected, err := authority.anchor.ManifestExpectation(slot, image)
	if err != nil {
		return nil, err
	}
	return bootstrap.VerifyManifest(envelope, roots, expected, time.Now().UTC(), bootstrap.ManifestTrustPolicy())
}
