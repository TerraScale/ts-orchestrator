package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// ManagerRetirement is sealed to the genuine current signed authority, protected
// slot ledger and provider reads. It is not a workload or worker grant.
type ManagerRetirement struct {
	reader         *CurrentFounderAuthorityReader
	sources        controllerRecipientSources
	issuer         AcceptedIdentity
	original       context.Context
	wire           []byte
	slot           string
	started, until time.Time
	captured       managerRetirementCapture
}

// ManagerRetirementSurvivor identifies one currently completed, running slot.
// Native callers must independently match its actual Swarm node and certificate.
type ManagerRetirementSurvivor struct {
	Slot, InstanceID, AvailabilityDomain, FaultDomain string
}

type managerRetirementCapture struct {
	Cell, Region, Environment, PriorInstanceID, RetirementSHA256 string
	PreviousAttempt                                              uint64
	Pins                                                         string
	Survivors                                                    []ManagerRetirementSurvivor
}

// ReadControllerManagerRetirement verifies exact old-instance retirement. An
// empty wire reads only the retirement already selected by protected HEAD.
func ReadControllerManagerRetirement(ctx context.Context, reader *CurrentFounderAuthorityReader, issuer AcceptedIdentity, slot string, retirement []byte) (*ManagerRetirement, error) {
	return readControllerManagerRetirement(ctx, reader, issuer, slot, retirement,
		controllerRecipientSources{trust: bakedStore{directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0}})
}

func readControllerManagerRetirement(ctx context.Context, reader *CurrentFounderAuthorityReader, issuer AcceptedIdentity, slot string, retirement []byte, sources controllerRecipientSources) (*ManagerRetirement, error) {
	if ctx == nil || reader == nil || issuer.Validate() != nil || slot == "" || len(retirement) > 64<<10 {
		return nil, ErrAdmission
	}
	started := time.Now()
	proof := &ManagerRetirement{reader: reader, sources: sources, issuer: issuer.Clone(), original: ctx, wire: bytes.Clone(retirement), slot: slot, started: started, until: started.Add(bootstrap.ManagedPeerObservationMaxAge)}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(proof.until) {
		proof.until = deadline
	}
	captured, until, err := proof.current(ctx)
	if err != nil {
		return nil, err
	}
	proof.captured = captured
	if until.Before(proof.until) {
		proof.until = until
	}
	if !proof.Valid(time.Now()) {
		return nil, bootstrap.ErrManagedPeerObservationStale
	}
	return proof, nil
}

func (p *ManagerRetirement) Slot() string             { return p.slot }
func (p *ManagerRetirement) Cell() string             { return p.captured.Cell }
func (p *ManagerRetirement) OCIRegion() string        { return p.captured.Region }
func (p *ManagerRetirement) Environment() string      { return p.captured.Environment }
func (p *ManagerRetirement) PriorInstanceID() string  { return p.captured.PriorInstanceID }
func (p *ManagerRetirement) PreviousAttempt() uint64  { return p.captured.PreviousAttempt }
func (p *ManagerRetirement) RetirementSHA256() string { return p.captured.RetirementSHA256 }
func (p *ManagerRetirement) ExpiresAt() time.Time     { return p.until }
func (p *ManagerRetirement) SourceSHA256() string     { return p.captured.Pins }

// ObservationSHA256 identifies this original finite observation, not a renewed
// read of the same signed records. It grants no independent authority.
func (p *ManagerRetirement) ObservationSHA256() string {
	if p == nil || p.captured.Pins == "" {
		return ""
	}
	wire, err := protocol.EncodeJSON(struct {
		Source              string
		ObservedAt, Expires time.Time
	}{p.captured.Pins, p.started.UTC().Round(0), p.until.UTC().Round(0)})
	if err != nil {
		return ""
	}
	return digestWire(wire)
}
func (p *ManagerRetirement) Survivors() []ManagerRetirementSurvivor {
	return slices.Clone(p.captured.Survivors)
}

// Valid never performs I/O and never extends the original call's lifetime.
func (p *ManagerRetirement) Valid(now time.Time) bool {
	return p != nil && p.original != nil && p.original.Err() == nil && p.captured.PriorInstanceID != "" &&
		!now.IsZero() && !now.Before(p.started) && now.Before(p.until) && time.Now().Before(p.until)
}

// OperationContext retains the original authenticated call values and clips
// native proposal/wait lifetime to this proof, even if a caller passes Background.
func (p *ManagerRetirement) OperationContext(caller context.Context) (context.Context, context.CancelFunc, error) {
	if caller == nil || caller.Err() != nil || !p.Valid(time.Now()) {
		return nil, nil, ErrAdmission
	}
	until := p.until
	if deadline, ok := caller.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	ctx, cancel := context.WithDeadline(p.original, until)
	stop := context.AfterFunc(caller, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

// Verify repeats actual root/selection/ledger/provider reads and rejects any
// changed source pin. It cannot renew an expired or canceled original call.
func (p *ManagerRetirement) Verify(ctx context.Context) error {
	bounded, cancel, err := p.OperationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	current, until, err := p.current(bounded)
	if err != nil {
		return err
	}
	if current.Pins != p.captured.Pins || !slices.Equal(current.Survivors, p.captured.Survivors) || until.Before(p.until) || !p.Valid(time.Now()) {
		return errors.New("manager retirement source changed from its original capture")
	}
	return nil
}

func (p *ManagerRetirement) current(ctx context.Context) (managerRetirementCapture, time.Time, error) {
	fail := func(err error) (managerRetirementCapture, time.Time, error) {
		return managerRetirementCapture{}, time.Time{}, err
	}
	if p == nil || ctx == nil || p.original == nil || p.original.Err() != nil || p.reader == nil ||
		p.issuer.Validate() != nil || p.slot == "" || len(p.wire) > 64<<10 || !time.Now().Before(p.until) {
		return fail(ErrAdmission)
	}
	ctx, cancel := context.WithDeadline(ctx, p.until)
	defer cancel()
	stop := context.AfterFunc(p.original, cancel)
	defer stop()
	if err := ociclient.CheckRequestGuard(ctx); err != nil {
		return fail(err)
	}
	inputs, err := p.sources.trust.loadTrustInputs(p.issuer)
	if err != nil {
		return fail(err)
	}
	reader := *p.reader
	reader.baked = p.reader.baked
	reader.baked.Roots = inputs.Roots.Historical
	authority, err := reader.ReadRuntimeAuthority(ctx, p.issuer, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	if !slices.Contains(authority.plan.ControllerSlots, p.slot) || p.slot == authority.plan.SeedSlot {
		return fail(ErrAdmission)
	}
	until := authority.expires
	if authority.anchor.ExpiresAt().Before(until) {
		until = authority.anchor.ExpiresAt()
	}
	ctx, stopAuthority := context.WithDeadline(ctx, until)
	defer stopAuthority()
	ledger := p.sources.ledger
	if ledger == nil {
		if reader.derived != nil {
			ledger, err = reader.derived.OpenLedger(ctx, reader.baked.Roots)
		} else {
			config, configErr := currentLedgerConfig(authority.anchor, reader.baked.Roots)
			if configErr != nil {
				return fail(configErr)
			}
			opened, openErr := openInstancePrincipalLedger(ctx, config, nil)
			if openErr != nil {
				return fail(openErr)
			}
			concrete, ok := opened.(admissionLedger)
			if !ok || concrete.ledger == nil {
				return fail(ErrLedgerGrant)
			}
			ledger = concrete.ledger
		}
	}
	if err != nil || ledger == nil {
		return fail(errors.Join(ErrLedgerGrant, err))
	}
	scope := bootstrap.BootstrapScope{DeploymentID: authority.identity.DeploymentID, Cell: authority.identity.Cell, Slot: p.slot}
	retired, err := ledger.ReadControllerRetirement(ctx, scope, p.wire)
	if err != nil {
		return fail(err)
	}
	prior := retired.PriorIntent
	anchor := authority.anchor.Anchor()
	if prior.OCIRegion != authority.identity.OCIRegion || prior.RegionIntentGeneration != anchor.InitialRegionIntentGeneration ||
		prior.RegionIntentDigest != anchor.InitialRegionIntentSHA256 || prior.FaultDomain != "FAULT-DOMAIN-1" && prior.FaultDomain != "FAULT-DOMAIN-2" && prior.FaultDomain != "FAULT-DOMAIN-3" {
		return fail(errors.New("retired controller differs from current signed region generation"))
	}
	observer := p.sources.observer
	if observer == nil {
		observer, err = reader.RuntimeInstanceObserver(ctx, p.issuer)
		if err != nil {
			return fail(err)
		}
	}
	if observer == nil || observer.compute == nil {
		return fail(ErrInstanceObservation)
	}
	captures := make([]bootstrap.SlotState, 0, len(authority.plan.ControllerSlots))
	survivors := make([]ManagerRetirementSurvivor, 0, len(authority.plan.ControllerSlots))
	domains := map[string]bool{}
	for _, slot := range authority.plan.ControllerSlots {
		selectedScope := scope
		selectedScope.Slot = slot
		state, err := ledger.ReadSlot(ctx, selectedScope)
		if err != nil {
			return fail(err)
		}
		captures = append(captures, state)
		if slot == p.slot && (state.Result == nil || state.Result.InstanceOCID == retired.Evidence.PriorInstanceOCID) {
			continue
		}
		if state.Result == nil {
			return fail(errors.New("surviving controller has no completed current slot"))
		}
		privateIP := authority.plan.SeedPrivateIP
		if slot != authority.plan.SeedSlot {
			privateIP = ""
			for _, row := range authority.plan.Peers {
				if row.Slot == slot {
					privateIP = row.PrivateIP
				}
			}
		}
		recipient := &ControllerHostRecipient{instanceID: state.Result.InstanceOCID}
		if err := recipient.checkCompletedSlot(authority, cellspec.HostGrant{Controller: slot, PrivateIP: privateIP}, state); err != nil {
			return fail(err)
		}
		observed, err := (Gate{Instances: observer}).observe(ctx, state.Result.InstanceOCID, state, anchor)
		if err != nil {
			return fail(err)
		}
		startup, err := controllerRecipientStartup(ctx, authority, reader.baked.Roots, slot, state.Intent.ImageOCID)
		if err != nil {
			return fail(err)
		}
		if startup.ExpiresAt().Before(until) {
			until = startup.ExpiresAt()
		}
		profile, ok := startup.Profile(slot)
		expected, receiptErr := bootstrap.NewReceipt(startup, observed.Facts)
		receipt := state.PeerReceipt
		if slot == authority.plan.SeedSlot {
			receipt = state.SeedReceipt
		}
		if !ok || receiptErr != nil || receipt == nil || *receipt != expected || observed.PrimaryPrivateIP != privateIP ||
			profile.AvailabilityDomain != observed.AvailabilityDomain || profile.FaultDomain != observed.FaultDomain ||
			domains[profile.AvailabilityDomain+"/"+profile.FaultDomain] {
			return fail(ErrInstanceObservation)
		}
		domains[profile.AvailabilityDomain+"/"+profile.FaultDomain] = true
		survivors = append(survivors, ManagerRetirementSurvivor{Slot: slot, InstanceID: state.Result.InstanceOCID, AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain})
	}
	if len(survivors) < 2 {
		return fail(errors.New("retirement requires two distinct canonical surviving controllers"))
	}
	for _, before := range captures {
		selectedScope := scope
		selectedScope.Slot = before.Intent.Slot
		after, err := ledger.ReadSlot(ctx, selectedScope)
		if err != nil || !sameControllerRecipientSlot(before, after) {
			return fail(errors.New("surviving controller slot changed during retirement verification"))
		}
	}
	confirmed, err := ledger.ReadControllerRetirement(ctx, scope, p.wire)
	if err != nil || !sameControllerRecipientSlot(retired.Current, confirmed.Current) || confirmed.RetirementSHA256 != retired.RetirementSHA256 {
		return fail(errors.New("retired attempt changed during provider verification"))
	}
	current, err := reader.ReadRuntimeAuthority(ctx, p.issuer, time.Now().UTC())
	if err != nil || current.identity != authority.identity || current.selectionDigest != authority.selectionDigest || current.planDigest != authority.planDigest {
		return fail(errors.New("retirement issuer authority changed"))
	}
	freshRoots, err := p.sources.trust.loadTrustInputs(p.issuer)
	if err != nil || freshRoots.Roots.Head != inputs.Roots.Head || freshRoots.Roots.Sequence != inputs.Roots.Sequence {
		return fail(errors.New("retirement adopted roots changed"))
	}
	// The final provider read is positive TERMINATED evidence for the exact old
	// instance, including signed compartment and canonical placement, without VNIC
	// lookup (a terminated instance no longer has an attached primary VNIC).
	response, err := observer.compute.GetInstance(observationContext(ctx, observer.compute), core.GetInstanceRequest{InstanceId: new(retired.Evidence.PriorInstanceOCID)})
	if err != nil {
		return fail(err)
	}
	instance := response.Instance
	if value(instance.Id) != retired.Evidence.PriorInstanceOCID || instance.LifecycleState != core.InstanceLifecycleStateTerminated ||
		value(instance.CompartmentId) != prior.CompartmentOCID || value(instance.AvailabilityDomain) != prior.AvailabilityDomain || value(instance.FaultDomain) != prior.FaultDomain {
		return fail(errors.New("retired controller lacks current exact OCI TERMINATED evidence"))
	}
	// Immutable object pins omit ServerDate, which changes on every OCI read.
	recordPins := make([][3]string, 0, len(captures)*9)
	for _, state := range captures {
		for _, record := range []*bootstrap.StoredRecord{&state.HeadRecord, &state.IntentRecord, state.ManifestRecord, state.ResultRecord, state.PeerReceiptRecord, state.SeedReceiptRecord, state.CandidateRecord, state.ProgressRecord} {
			if record == nil {
				recordPins = append(recordPins, [3]string{})
				continue
			}
			recordPins = append(recordPins, [3]string{record.SHA256, record.ETag, record.LastModified.UTC().Format(time.RFC3339Nano)})
		}
	}
	pinBytes, err := protocol.EncodeJSON(struct {
		Selection, Plan, Retirement, RootsHead string
		RootsSequence                          uint64
		Records                                [][3]string
	}{authority.selectionDigest, authority.planDigest, retired.RetirementSHA256, inputs.Roots.Head, inputs.Roots.Sequence, recordPins})
	if err != nil {
		return fail(err)
	}
	pins := digestWire(pinBytes)
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if !time.Now().Before(until) || p.original.Err() != nil {
		return fail(bootstrap.ErrManagedPeerObservationStale)
	}
	if err := ociclient.CheckRequestGuard(ctx); err != nil {
		return fail(err)
	}
	return managerRetirementCapture{Cell: authority.identity.Cell, Region: authority.identity.OCIRegion, Environment: authority.identity.Environment,
		PriorInstanceID: retired.Evidence.PriorInstanceOCID, RetirementSHA256: retired.RetirementSHA256, PreviousAttempt: retired.Evidence.PreviousAttempt,
		Pins: pins, Survivors: survivors}, until, nil
}
