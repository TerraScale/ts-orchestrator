package placement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

const (
	defaultTickInterval = 5 * time.Second
	minTickInterval     = 100 * time.Millisecond
	maxTickInterval     = 5 * time.Minute
	maxMemberStates     = 64
	bytesPerGiB         = int64(1 << 30)
)

// HostView is the controller's read-only view of durable host registration and
// current-session reports. The current TerraBase runtime contract is absent,
// so this controller deliberately has no desired-state writer capability.
type HostView interface {
	ListHosts(context.Context) ([]host.HostStatus, error)
}

type Config struct {
	Cell            string
	Region          oci.Region
	FaultDomains    []string
	ManagedOwner    string
	FleetGeneration uint64
	Environment     string
	MemberRole      string
	Resources       Resources
	TickInterval    time.Duration
	OnError         func(error)
	OnHold          func(string)
}

type Controller struct {
	config Config
	store  Store
	fencer authority.Fencer
	fleet  oci.Fleet
	hosts  HostView
}

// StartController validates one region-bound reconciler. Run owns the periodic
// lifecycle; Tick is exposed for deterministic callers and tests.
func StartController(ctx context.Context, config Config, store Store, fencer authority.Fencer, fleet oci.Fleet, hosts HostView) (*Controller, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("placement controller requires a live context")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if store == nil || fencer == nil || fleet == nil || hosts == nil {
		return nil, errors.New("placement controller requires durable state, authority, OCI fleet, and host view")
	}
	if fleet.Region() != config.Region {
		return nil, errors.New("placement controller region differs from its pinned OCI fleet")
	}
	if config.TickInterval == 0 {
		config.TickInterval = defaultTickInterval
	}
	return &Controller{config: config, store: store, fencer: fencer, fleet: fleet, hosts: hosts}, nil
}

func (config Config) validate() error {
	if !validToken(config.Cell) || !knownRegion(config.Region) || !validToken(config.ManagedOwner) ||
		!validToken(config.Environment) || !validToken(config.MemberRole) || config.FleetGeneration == 0 ||
		!positive(config.Resources) ||
		config.Resources.CPU > 4096 || config.Resources.MemoryBytes > 1<<50 || config.Resources.DiskBytes > 1<<50 {
		return errors.New("placement controller config has an invalid cell, region, owner, role, or resource profile")
	}
	if config.TickInterval < 0 || config.TickInterval != 0 && (config.TickInterval < minTickInterval || config.TickInterval > maxTickInterval) {
		return errors.New("placement tick interval must be zero or between 100ms and 5m")
	}
	if len(config.FaultDomains) < 2 || len(config.FaultDomains) > 3 || config.FaultDomains[0] == config.FaultDomains[1] {
		return errors.New("placement region requires at least two distinct OCI fault domains")
	}
	for _, domain := range config.FaultDomains {
		if len(domain) != len("FAULT-DOMAIN-1") || !strings.HasPrefix(domain, "FAULT-DOMAIN-") || domain[len(domain)-1] < '1' || domain[len(domain)-1] > '3' {
			return fmt.Errorf("invalid configured OCI fault domain %q", domain)
		}
	}
	return nil
}

// Run reconciles at a bounded cadence. Errors leave durable state at its last
// confirmed stage and are reported through OnError before a later retry.
func (controller *Controller) Run(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return errors.New("placement controller and context are required")
	}
	ticker := time.NewTicker(controller.config.TickInterval)
	defer ticker.Stop()
	for {
		if err := controller.Tick(ctx); err != nil && ctx.Err() == nil && controller.config.OnError != nil {
			controller.config.OnError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Tick observes each authoritative input once and advances no more than one
// durable transition or external lifecycle action. An admitted intent observed
// at the start of this tick may finish that bounded action if a newer intent
// commits concurrently; the next tick holds the old member pin. Unadmitted
// hosts and missing database evidence remain holds.
func (controller *Controller) Tick(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return errors.New("placement controller and context are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot := controller.fencer.Current()
	if !snapshot.CanMutate() {
		return nil
	}
	epoch := snapshot.Epoch
	intents, err := controller.store.ListIntents(ctx)
	if err != nil {
		return err
	}
	if len(intents) > maxIntentCount {
		return errors.New("placement intent list exceeds its safety bound")
	}
	instances, err := controller.fleet.Observe(ctx)
	if err != nil {
		return fmt.Errorf("observe region-bound OCI fleet: %w", err)
	}
	instanceByID := make(map[string]oci.Instance, len(instances))
	for _, instance := range instances {
		if instance.ID == "" || instance.Node == "" || instance.Region != controller.config.Region || instance.ETag == "" {
			return errors.New("OCI fleet returned an incomplete or cross-region instance")
		}
		if _, exists := instanceByID[instance.ID]; exists {
			return fmt.Errorf("OCI fleet returned duplicate instance %q", instance.ID)
		}
		instanceByID[instance.ID] = instance
	}
	statuses, err := controller.hosts.ListHosts(ctx)
	if err != nil {
		return fmt.Errorf("read current host registrations and reports: %w", err)
	}
	statusByNode := make(map[string]host.HostStatus, len(statuses))
	for _, status := range statuses {
		node := status.Registration.Node
		if node == "" {
			return errors.New("host view returned a registration without a node")
		}
		if _, exists := statusByNode[node]; exists {
			return fmt.Errorf("host view returned duplicate node %q", node)
		}
		statusByNode[node] = status
	}
	seenIntents := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		if err := intent.Validate(); err != nil {
			return err
		}
		identity := intent.DatabaseID + "\x00" + intent.PartitionID
		if _, exists := seenIntents[identity]; exists {
			return fmt.Errorf("%w: duplicate database/partition intent", ErrInvalidIntent)
		}
		seenIntents[identity] = struct{}{}
		if intent.SchemaVersion != IntentSchemaVersion || intent.PayloadDigest() == "" {
			controller.hold(fmt.Sprintf("database %s/%s has no admitted managed placement profile; host reconciliation is held", intent.DatabaseID, intent.PartitionID))
			continue
		}
		members, err := controller.store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			return err
		}
		if len(members) > maxMemberStates {
			return fmt.Errorf("placement member state for %s/%s exceeds its bound", intent.DatabaseID, intent.PartitionID)
		}
		if !slices.Contains(intent.ActiveRegions, controller.config.Region) {
			if len(members) > 0 && controller.config.OnHold != nil {
				controller.config.OnHold(fmt.Sprintf("database %s/%s regional retirement is held; trusted replication, quorum, drain, writer-stop, and retained-volume evidence is required", intent.DatabaseID, intent.PartitionID))
			}
			continue
		}
		seats, err := controller.localSeats(intent)
		if err != nil {
			return err
		}
		rosterDigest, err := intent.CanonicalRosterDigest()
		if err != nil {
			return err
		}
		rowsBySeat := make(map[string]CanonicalRosterRow, len(seats))
		rosterHeld := false
		for _, seat := range seats {
			row, err := intent.RosterRowForSeat(seat)
			if err != nil {
				controller.hold(fmt.Sprintf("member %s has no signed roster row matching its configured seat; host reconciliation is held: %v", seat.MemberID, err))
				rosterHeld = true
				break
			}
			rowsBySeat[seat.MemberID] = row
		}
		if rosterHeld {
			continue
		}
		profile, err := intent.ManagedHostProfile(controller.config.Region)
		if err != nil {
			return err
		}
		profileDigest, err := profile.ProfileDigest()
		if err != nil {
			return err
		}
		memberByID := make(map[string]VersionedMemberState, len(members))
		for _, member := range members {
			if member.State.DatabaseID != intent.DatabaseID || member.State.PartitionID != intent.PartitionID {
				return fmt.Errorf("%w: member state escaped database/partition scope", ErrStoreCorrupt)
			}
			if _, exists := memberByID[member.State.MemberID]; exists {
				return fmt.Errorf("%w: duplicate member state %q", ErrStoreCorrupt, member.State.MemberID)
			}
			memberByID[member.State.MemberID] = member
		}
		held := false
		for _, seat := range seats {
			versioned, exists := memberByID[seat.MemberID]
			if !exists {
				continue
			}
			state := versioned.State
			if state.Region != seat.Region || state.Kind != seat.Kind || state.FailureDomain != seat.FailureDomain {
				return fmt.Errorf("%w: admitted placement seat conflicts with durable member identity", ErrStoreCorrupt)
			}
			if state.SchemaVersion != placementSchemaVersion ||
				state.CanonicalRosterRow != rowsBySeat[seat.MemberID] ||
				state.CanonicalRosterDigest != rosterDigest ||
				state.AuthorityReference != intent.CanonicalRoster.Authority ||
				state.IntentPayloadDigest == "" || state.ManagedHostProfileDigest == "" ||
				state.IntentPayloadDigest != intent.PayloadDigest() || state.ManagedHostProfile != profile ||
				state.ManagedHostProfileDigest != profileDigest || state.IntentGeneration != intent.Generation {
				controller.hold(fmt.Sprintf("member %s has no matching immutable roster, authority reference, or placement profile; an explicit new attempt is required", seat.MemberID))
				held = true
				break
			}
			if state.Stage == StageRemoved {
				controller.hold(fmt.Sprintf("removed member %s requires an explicit reconciled new attempt", seat.MemberID))
				held = true
				break
			}
		}
		if held {
			continue
		}
		for _, seat := range seats {
			versioned, exists := memberByID[seat.MemberID]
			if !exists {
				state := controller.initialState(intent, seat, rowsBySeat[seat.MemberID], rosterDigest, profile, profileDigest, 1)
				if _, err := controller.persist(ctx, epoch, 0, state); err != nil {
					return err
				}
				return nil
			}
			acted, err := controller.advanceMember(ctx, epoch, intent, seat, versioned, instanceByID, statusByNode)
			if err != nil {
				return err
			}
			if acted {
				return nil
			}
		}
	}
	return nil
}

func (controller *Controller) advanceMember(
	ctx context.Context,
	epoch uint64,
	intent Intent,
	seat Seat,
	versioned VersionedMemberState,
	instances map[string]oci.Instance,
	statuses map[string]host.HostStatus,
) (bool, error) {
	state := versioned.State
	switch state.Stage {
	case StagePreparedHost:
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		instance, err := controller.fleet.EnsureHost(ctx, pinnedEnsureRequest(state))
		if err != nil {
			return false, fmt.Errorf("ensure TerraBase member host %s/%s: %w", intent.DatabaseID, seat.MemberID, err)
		}
		if err := controller.validateEnsuredInstance(instance, state, seat); err != nil {
			return false, err
		}
		state.Stage = StageAwaitingHost
		state.HostNode = instance.Node
		state.InstanceID = instance.ID
		state.InstanceETag = instance.ETag
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "host")
		_, err = controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	case StageAwaitingHost:
		instance, exists := instances[state.InstanceID]
		if !exists {
			// Retrying EnsureHost with the same durable create key recovers an
			// unknown launch outcome without adopting a tag-matched resource.
			if err := controller.guard(ctx, epoch); err != nil {
				return false, err
			}
			instance, err := controller.fleet.EnsureHost(ctx, pinnedEnsureRequest(state))
			if err != nil {
				return false, fmt.Errorf("recover TerraBase member host %s/%s: %w", intent.DatabaseID, seat.MemberID, err)
			}
			if err := controller.validateEnsuredInstance(instance, state, seat); err != nil {
				return false, err
			}
			state.HostNode, state.InstanceID, state.InstanceETag = instance.Node, instance.ID, instance.ETag
			_, err = controller.persist(ctx, epoch, versioned.Revision, state)
			return true, err
		}
		if err := controller.validateObservedInstance(instance, state, seat); err != nil {
			return false, err
		}
		status, admitted := controller.admittedHost(intent, state, instance, statuses)
		if !admitted {
			return false, nil
		}
		if state.VolumeID == "" {
			state.Stage = StagePreparedVolume
		} else {
			state.Stage = StagePreparedAttach
		}
		state.HostGeneration = status.Registration.Generation
		state.InstanceETag = instance.ETag
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "admitted")
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	case StagePreparedVolume:
		instance, exists := instances[state.InstanceID]
		if !exists {
			controller.hold(fmt.Sprintf("member %s OCI host is not currently observed; retained volume creation is withheld", seat.MemberID))
			return false, nil
		}
		if err := controller.validateObservedInstance(instance, state, seat); err != nil {
			return false, err
		}
		status, admitted := controller.admittedHost(intent, state, instance, statuses)
		if !admitted || status.Registration.Generation != state.HostGeneration {
			controller.hold(fmt.Sprintf("member %s has no current exact host registration; retained volume creation is withheld", seat.MemberID))
			return false, nil
		}
		if state.VolumeID != "" {
			state.Stage = StagePreparedAttach
			state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "attach")
			_, err := controller.persist(ctx, epoch, versioned.Revision, state)
			return true, err
		}
		sizeGB, err := volumeSizeGB(controller.config.Resources.DiskBytes)
		if err != nil {
			return false, err
		}
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		volume, err := controller.fleet.CreateRetainedVolume(ctx, oci.VolumeCreateRequest{
			CreateKey: volumeCreateKey(intent, seat), SizeGB: sizeGB,
		})
		if err != nil {
			return false, fmt.Errorf("create or recover retained member volume %s/%s: %w", intent.DatabaseID, seat.MemberID, err)
		}
		if volume.ID == "" || volume.CreateKey != volumeCreateKey(intent, seat) || volume.Region != controller.config.Region ||
			volume.Owner != controller.config.ManagedOwner || volume.Generation != controller.config.FleetGeneration || volume.SizeGB < sizeGB {
			return false, errors.New("OCI fleet returned a retained volume with mismatched durable identity")
		}
		state.VolumeID = volume.ID
		state.Stage = StagePreparedAttach
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "attach")
		_, err = controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	case StagePreparedAttach:
		instance, exists := instances[state.InstanceID]
		if !exists {
			return false, nil
		}
		if err := controller.validateObservedInstance(instance, state, seat); err != nil {
			return false, err
		}
		status, admitted := controller.admittedHost(intent, state, instance, statuses)
		if !admitted || status.Registration.Generation != state.HostGeneration {
			return false, nil
		}
		var attachment *oci.Attachment
		for index := range instance.Attachments {
			if instance.Attachments[index].VolumeID == state.VolumeID {
				if instance.Attachments[index].InstanceID != state.InstanceID {
					return false, oci.ErrRetainedVolumeInUse
				}
				attachment = &instance.Attachments[index]
				break
			}
		}
		if attachment == nil {
			if err := controller.guard(ctx, epoch); err != nil {
				return false, err
			}
			attached, err := controller.fleet.AttachRetainedVolume(ctx, oci.VolumeAttachRequest{
				VolumeID: state.VolumeID, InstanceID: state.InstanceID,
				IdempotencyKey: memberOperationID(intent, seat.MemberID, state.HostAttempt, "attach-volume"),
			})
			if err != nil {
				return false, fmt.Errorf("attach retained member volume %s/%s: %w", intent.DatabaseID, seat.MemberID, err)
			}
			attachment = &attached
		}
		state.AttachmentID = attachment.ID
		if attachment.State == "ATTACHED" {
			state.Stage = StageAwaitingRuntimeContract
			state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
		} else if attachment.State == "ATTACHING" {
			state.Stage = StageAwaitingAttach
			state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "attach-wait")
		} else {
			controller.hold(fmt.Sprintf("member %s retained volume attachment is %s; desired state remains withheld", seat.MemberID, attachment.State))
			return false, nil
		}
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	case StageAwaitingAttach:
		instance, exists := instances[state.InstanceID]
		if !exists {
			return false, nil
		}
		if err := controller.validateObservedInstance(instance, state, seat); err != nil {
			return false, err
		}
		status, admitted := controller.admittedHost(intent, state, instance, statuses)
		if !admitted || status.Registration.Generation != state.HostGeneration {
			return false, nil
		}
		for _, attachment := range instance.Attachments {
			if attachment.ID != state.AttachmentID || attachment.VolumeID != state.VolumeID || attachment.InstanceID != state.InstanceID {
				continue
			}
			switch attachment.State {
			case "ATTACHED":
				state.Stage = StageAwaitingRuntimeContract
				state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
				_, err := controller.persist(ctx, epoch, versioned.Revision, state)
				return true, err
			case "ATTACHING":
				return false, nil
			default:
				controller.hold(fmt.Sprintf("member %s retained volume attachment is %s; desired state remains withheld", seat.MemberID, attachment.State))
				return false, nil
			}
		}
		controller.hold(fmt.Sprintf("member %s retained volume attachment is not positively observed; desired state remains withheld", seat.MemberID))
		return false, nil
	case StagePreparedDesired:
		// Recover old prepared records conservatively; the current host agent
		// has no TerraBase volume-mount or per-member launch contract.
		state.Stage = StageAwaitingRuntimeContract
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	case StageAwaitingRuntimeContract:
		instance, exists := instances[state.InstanceID]
		if !exists {
			controller.hold(fmt.Sprintf("member %s OCI host is not currently observed; retained volume is kept", seat.MemberID))
			return false, nil
		}
		if err := controller.validateObservedInstance(instance, state, seat); err != nil {
			return false, err
		}
		status, admitted := controller.admittedHost(intent, state, instance, statuses)
		if !admitted || status.Registration.Generation != state.HostGeneration {
			controller.hold(fmt.Sprintf("member %s is awaiting an exact managed OCI registration and current host session", seat.MemberID))
			return false, nil
		}
		if !hasAttachedVolume(instance, state) {
			controller.hold(fmt.Sprintf("member %s retained volume is not observed ATTACHED; desired state remains withheld", seat.MemberID))
			return false, nil
		}
		controller.hold(fmt.Sprintf("member %s retained volume is attached, but no verified TerraBase runtime and mount contract is available; desired state remains withheld", seat.MemberID))
		return false, nil
	case StageAwaitingHealthy:
		state.Stage = StageAwaitingRuntimeContract
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		controller.hold(fmt.Sprintf("member %s is held because a production TerraBase launch and volume-mount contract is not available", seat.MemberID))
		return true, err
	case StageServing:
		observedHealthy := false
		if instance, exists := instances[state.InstanceID]; exists {
			if err := controller.validateObservedInstance(instance, state, seat); err != nil {
				return false, err
			}
			if status, admitted := controller.admittedHost(intent, state, instance, statuses); admitted &&
				status.Registration.Generation == state.HostGeneration && hasAttachedVolume(instance, state) {
				observedHealthy = hasCurrentProcessReport(status, state, controller.config)
			}
		}
		state.Stage = StageAwaitingRuntimeContract
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		if observedHealthy {
			controller.hold(fmt.Sprintf("member %s host is live, but it cannot remain serving without a verified TerraBase runtime and mounted-volume contract", seat.MemberID))
		} else {
			controller.hold(fmt.Sprintf("member %s lost current host, session, attachment, or process evidence; it is held without replacement", seat.MemberID))
		}
		return true, err
	case StageRemoveCandidate, StageCordoned, StageDraining, StageDrained, StageStorageHandled, StageTerminated:
		controller.hold(fmt.Sprintf("member %s is in retirement stage %s; retirement actions require the integrated evidence-driven scale-in path", seat.MemberID, state.Stage))
		return false, nil
	case StageRemoved:
		return false, nil
	default:
		return false, fmt.Errorf("%w: unknown member stage %q", ErrStoreCorrupt, state.Stage)
	}
}

func (controller *Controller) localSeats(intent Intent) ([]Seat, error) {
	if !slices.Contains(intent.ActiveRegions, controller.config.Region) {
		return nil, nil
	}
	domains := controller.config.FaultDomains
	if len(domains) < 2 || domains[0] == domains[1] {
		return nil, fmt.Errorf("%w: region %s has fewer than two anti-affine fault domains", ErrInvalidIntent, controller.config.Region)
	}
	return []Seat{
		{MemberID: permanentMember(controller.config.Region), Region: controller.config.Region, FailureDomain: domains[0], Kind: MemberPermanent},
		{MemberID: elasticMember(controller.config.Region), Region: controller.config.Region, FailureDomain: domains[1], Kind: MemberElastic},
	}, nil
}

func (controller *Controller) initialState(intent Intent, seat Seat, row CanonicalRosterRow, rosterDigest string, profile ManagedHostProfile, profileDigest string, attempt uint64) MemberState {
	return MemberState{
		SchemaVersion: placementSchemaVersion, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		MemberID: seat.MemberID, Region: seat.Region, FailureDomain: seat.FailureDomain, Kind: seat.Kind,
		Stage: StagePreparedHost, CreateKey: hostCreateKey(intent, seat, attempt), HostAttempt: attempt,
		CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest, AuthorityReference: intent.CanonicalRoster.Authority,
		IntentPayloadDigest: intent.PayloadDigest(), ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
		IntentGeneration: intent.Generation, OperationID: memberOperationID(intent, seat.MemberID, attempt, "prepare"),
		UpdatedAt: time.Now().UTC(),
	}
}

func pinnedEnsureRequest(state MemberState) oci.EnsureRequest {
	return oci.EnsureRequest{
		CreateKey: state.CreateKey, FaultDomain: state.FailureDomain,
		Shape: state.ManagedHostProfile.Compute.Shape, WholeOCPUs: state.ManagedHostProfile.Compute.WholeOCPUs,
		MemoryInGBs:            state.ManagedHostProfile.Compute.MemoryInGBs,
		PlacementProfileDigest: state.ManagedHostProfileDigest, PlacementGeneration: state.IntentGeneration,
	}
}

func (controller *Controller) validateEnsuredInstance(instance oci.Instance, state MemberState, seat Seat) error {
	if instance.ID == "" || instance.Node == "" || instance.ETag == "" || instance.CreateKey != state.CreateKey ||
		state.InstanceID != "" && instance.ID != state.InstanceID || state.HostNode != "" && instance.Node != state.HostNode ||
		instance.Region != controller.config.Region || instance.FaultDomain != seat.FailureDomain ||
		!controller.instanceMatchesPinnedProfile(instance, state) {
		return errors.New("OCI EnsureHost returned an instance with mismatched durable placement identity")
	}
	return nil
}

func (controller *Controller) validateObservedInstance(instance oci.Instance, state MemberState, seat Seat) error {
	if instance.ID != state.InstanceID || instance.Node != state.HostNode || instance.CreateKey != state.CreateKey ||
		instance.Region != controller.config.Region || instance.FaultDomain != seat.FailureDomain || instance.ETag == "" ||
		state.InstanceETag == "" || !controller.instanceMatchesPinnedProfile(instance, state) {
		return errors.New("observed OCI instance differs from the durable TerraBase member binding")
	}
	return nil
}

func (controller *Controller) instanceMatchesPinnedProfile(instance oci.Instance, state MemberState) bool {
	compute := state.ManagedHostProfile.Compute
	return instance.Owner == controller.config.ManagedOwner && instance.Generation == controller.config.FleetGeneration &&
		instance.Shape == compute.Shape && instance.WholeOCPUs == compute.WholeOCPUs &&
		instance.MemoryInGBs == compute.MemoryInGBs && instance.PlacementProfileDigest == state.ManagedHostProfileDigest &&
		instance.PlacementGeneration == state.IntentGeneration
}

func (controller *Controller) admittedHost(intent Intent, state MemberState, instance oci.Instance, statuses map[string]host.HostStatus) (host.HostStatus, bool) {
	status, exists := statuses[instance.Node]
	if !exists {
		return host.HostStatus{}, false
	}
	registration := status.Registration
	binding := registration.ManagedOCI
	if !status.Verified || !time.Now().Before(status.SessionExpiresAt) || binding == nil ||
		registration.Cell != controller.config.Cell || registration.Node != instance.Node ||
		registration.Environment != controller.config.Environment || registration.FailureDomain != instance.FaultDomain ||
		!slices.Contains(registration.Roles, controller.config.MemberRole) ||
		registration.Capacity.CPU < controller.config.Resources.CPU ||
		registration.Capacity.MemoryBytes < controller.config.Resources.MemoryBytes ||
		registration.Capacity.DiskBytes < controller.config.Resources.DiskBytes ||
		binding.Region != string(controller.config.Region) || binding.InstanceID != instance.ID ||
		binding.Owner != controller.config.ManagedOwner || binding.FleetGeneration != controller.config.FleetGeneration ||
		binding.CreateKey != instance.CreateKey {
		return host.HostStatus{}, false
	}
	row := state.CanonicalRosterRow
	roster := intent.CanonicalRoster
	pins := host.ManagedRegistrationPins{
		Placement: host.ManagedPlacementBinding{
			DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
			IntentGeneration: state.IntentGeneration, IntentPayloadDigest: state.IntentPayloadDigest,
			CanonicalRosterDigest: state.CanonicalRosterDigest, ManagedHostProfileDigest: state.ManagedHostProfileDigest,
		},
		Member: host.ManagedMemberBinding{
			Scope: host.MemberScope{
				ClusterID: roster.ClusterID, TenantID: roster.TenantID, DatabaseID: roster.DatabaseID,
				ShardID: roster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation,
			},
			HostAttempt: state.HostAttempt,
		},
		OCI: host.ManagedOCIBinding{
			Region: string(instance.Region), InstanceID: instance.ID, Owner: instance.Owner,
			FleetGeneration: instance.Generation, CreateKey: instance.CreateKey,
		},
		FailureDomain:          row.FailureDomain,
		AllocatableMemoryBytes: state.ManagedHostProfile.AllocatableMemoryBytes,
		SystemReserveBytes:     state.ManagedHostProfile.SystemReserveBytes,
	}
	if err := host.ValidateManagedRegistrationPins(registration, pins); err != nil {
		return host.HostStatus{}, false
	}
	return status, true
}

func hasCurrentProcessReport(status host.HostStatus, state MemberState, config Config) bool {
	now := time.Now()
	for _, report := range status.Reports {
		if report.Cell == config.Cell && report.Node == status.Registration.Node &&
			report.Environment == config.Environment && report.Role == config.MemberRole &&
			report.Generation == state.DesiredGeneration && report.State == "running" &&
			!report.ObservedAt.IsZero() && !report.ObservedAt.After(now.Add(2*time.Second)) && now.Sub(report.ObservedAt) < 30*time.Second {
			return true
		}
	}
	return false
}

func (controller *Controller) persist(ctx context.Context, epoch, revision uint64, state MemberState) (uint64, error) {
	if err := controller.guard(ctx, epoch); err != nil {
		return 0, err
	}
	state.WriterEpoch = epoch
	state.UpdatedAt = time.Now().UTC()
	return controller.store.CompareAndSwap(ctx, revision, state)
}

func (controller *Controller) guard(ctx context.Context, epoch uint64) error {
	if epoch == 0 || !controller.fencer.Current().CanMutate() || controller.fencer.Current().Epoch != epoch {
		return authority.ErrFenced
	}
	return controller.fencer.Guard(ctx, epoch)
}

func (controller *Controller) hold(reason string) {
	if controller.config.OnHold != nil {
		controller.config.OnHold(reason)
	}
}

func hostCreateKey(intent Intent, seat Seat, attempt uint64) string {
	return digestToken("th", intent.DatabaseID, intent.PartitionID, string(seat.Region), seat.MemberID, fmt.Sprint(attempt))
}

func volumeCreateKey(intent Intent, seat Seat) string {
	return digestToken("tv", intent.DatabaseID, intent.PartitionID, string(seat.Region), seat.MemberID)
}

func memberOperationID(intent Intent, memberID string, attempt uint64, action string) string {
	return digestToken("p", intent.DatabaseID, intent.PartitionID, memberID, fmt.Sprint(intent.Generation), fmt.Sprint(attempt), action)
}

func digestToken(prefix string, values ...string) string {
	joined := strings.Join(values, "\x00")
	sum := sha256.Sum256([]byte(joined))
	return prefix + "-" + hex.EncodeToString(sum[:24])
}

func volumeSizeGB(bytes int64) (int64, error) {
	if bytes <= 0 || bytes > 32768*bytesPerGiB {
		return 0, errors.New("TerraBase member volume request is outside OCI size limits")
	}
	gigabytes := bytes / bytesPerGiB
	if bytes%bytesPerGiB != 0 {
		gigabytes++
	}
	gigabytes = max(gigabytes, 50)
	if gigabytes > 32768 {
		return 0, errors.New("TerraBase member volume request exceeds OCI's maximum size")
	}
	return gigabytes, nil
}

func hasAttachedVolume(instance oci.Instance, state MemberState) bool {
	if state.VolumeID == "" || state.AttachmentID == "" {
		return false
	}
	for _, attachment := range instance.Attachments {
		if attachment.ID == state.AttachmentID && attachment.VolumeID == state.VolumeID &&
			attachment.InstanceID == state.InstanceID && attachment.State == "ATTACHED" {
			return true
		}
	}
	return false
}
