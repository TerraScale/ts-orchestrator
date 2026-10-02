package placement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

const (
	defaultTickInterval = 5 * time.Second
	minTickInterval     = 100 * time.Millisecond
	maxTickInterval     = 5 * time.Minute
	maxMemberStates     = 64
	bytesPerGiB         = int64(1 << 30)
)

// HostView reads durable host registrations, current-session reports and
// committed desired state before a prepared placement effect is replayed.
type HostView interface {
	ListHosts(context.Context) ([]host.HostStatus, error)
	ListDesired(context.Context, string) ([]host.Desired, error)
}

type DesiredWriter interface {
	ApplyDesired(context.Context, host.Desired) (host.Receipt, error)
}

// AdmittedArtifact is the current content and asserted source identity of an
// artifact that passed durable delivery admission and byte verification.
type AdmittedArtifact struct {
	Digest         string
	ManifestDigest string
	SourceDigest   string
}

type ArtifactResolver func(context.Context, string, string, string) (AdmittedArtifact, error)

type Config struct {
	Cell            string
	Region          oci.Region
	FaultDomains    []string
	ManagedOwner    string
	FleetGeneration uint64
	ImageID         string
	Environment     string
	MemberRole      string
	Resources       Resources
	TickInterval    time.Duration
	OnError         func(error)
	OnHold          func(string)
	// LostMemberEvidence enables replacing a member whose OCI host is gone.
	// Nil keeps such members held without replacement.
	LostMemberEvidence LostMemberEvidence
	// LostMemberGrace defaults to DefaultLostMemberGrace.
	LostMemberGrace time.Duration
}

type Controller struct {
	config          Config
	store           Store
	fencer          authority.Fencer
	fleet           oci.Fleet
	hosts           HostView
	desired         DesiredWriter
	resolveArtifact ArtifactResolver
	now             func() time.Time
}

func (controller *Controller) currentTime() time.Time {
	if controller.now != nil {
		return controller.now()
	}
	return time.Now()
}

// StartController validates one region-bound reconciler. Run owns the periodic
// lifecycle; Tick is exposed for deterministic callers and tests.
func StartController(ctx context.Context, config Config, store Store, fencer authority.Fencer, fleet oci.Fleet, hosts HostView, desired DesiredWriter, resolveArtifact ArtifactResolver) (*Controller, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("placement controller requires a live context")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if store == nil || fencer == nil || fleet == nil || hosts == nil || desired == nil || resolveArtifact == nil {
		return nil, errors.New("placement controller requires durable state, authority, OCI fleet, host view, desired writer and artifact admission")
	}
	if fleet.Region() != config.Region {
		return nil, errors.New("placement controller region differs from its pinned OCI fleet")
	}
	if config.TickInterval == 0 {
		config.TickInterval = defaultTickInterval
	}
	return &Controller{config: config, store: store, fencer: fencer, fleet: fleet, hosts: hosts, desired: desired, resolveArtifact: resolveArtifact}, nil
}

func (config Config) validate() error {
	if !validToken(config.Cell) || !knownRegion(config.Region) || !validToken(config.ManagedOwner) ||
		!validToken(config.Environment) || !validToken(config.MemberRole) || config.FleetGeneration == 0 ||
		!strings.HasPrefix(config.ImageID, "ocid1.image.") || len(config.ImageID) > 255 || strings.ContainsAny(config.ImageID, " \t\r\n") ||
		!positive(config.Resources) ||
		config.Resources.CPU > 4096 || config.Resources.MemoryBytes > 1<<50 || config.Resources.DiskBytes > 1<<50 {
		return errors.New("placement controller config has an invalid cell, region, owner, role, or resource profile")
	}
	if config.LostMemberGrace < 0 || config.LostMemberGrace > 7*24*time.Hour {
		return errors.New("placement lost member grace must be between zero and seven days")
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
	// A failing placement must not starve independent ones: its error is
	// reported with the pass while later placements still advance.
	var placementErrs []error
intents:
	for _, intent := range intents {
		if err := intent.Validate(); err != nil {
			return err
		}
		identity := intent.DatabaseID + "\x00" + intent.PartitionID
		if _, exists := seenIntents[identity]; exists {
			return fmt.Errorf("%w: duplicate database/partition intent", ErrInvalidIntent)
		}
		seenIntents[identity] = struct{}{}
		if _, err := controller.store.ReadTerminalIntent(ctx, intent.DatabaseID, intent.PartitionID); err == nil {
			controller.hold(fmt.Sprintf("database %s/%s has a committed terminal teardown fence", intent.DatabaseID, intent.PartitionID))
			continue
		} else if !errors.Is(err, authority.ErrNotFound) {
			return fmt.Errorf("read terminal workload fence for %s/%s: %w", intent.DatabaseID, intent.PartitionID, err)
		}
		if intent.SchemaVersion != IntentSchemaVersion || intent.PayloadDigest() == "" {
			controller.hold(fmt.Sprintf("database %s/%s has no admitted managed placement profile; host reconciliation is held", intent.DatabaseID, intent.PartitionID))
			continue
		}
		if len(intent.ActiveRegions) != 1 {
			controller.hold(fmt.Sprintf("database %s/%s has %d regions; current TerraBase outbound sender supports exactly two members in one region", intent.DatabaseID, intent.PartitionID, len(intent.ActiveRegions)))
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
		manifestsBySeat := make(map[string]RuntimeManifest, len(seats))
		manifestDigestsBySeat := make(map[string]string, len(seats))
		rosterHeld := false
		for _, seat := range seats {
			row, err := intent.RosterRowForSeat(seat)
			if err != nil {
				controller.hold(fmt.Sprintf("member %s has no signed roster row matching its configured seat; host reconciliation is held: %v", seat.MemberID, err))
				rosterHeld = true
				break
			}
			rowsBySeat[seat.MemberID] = row
			manifest, err := intent.RuntimeManifestForSeat(seat)
			if err != nil {
				controller.hold(fmt.Sprintf("member %s has no signed runtime manifest: %v", seat.MemberID, err))
				rosterHeld = true
				break
			}
			manifestDigest, err := manifest.Digest()
			if err != nil {
				return err
			}
			manifestsBySeat[seat.MemberID] = manifest
			manifestDigestsBySeat[seat.MemberID] = manifestDigest
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
			if state.SchemaVersion != placementSchemaVersion &&
				state.SchemaVersion != managedUpdateMemberStateSchemaVersion ||
				state.CanonicalRosterRow != rowsBySeat[seat.MemberID] ||
				state.RuntimeManifest != manifestsBySeat[seat.MemberID] ||
				state.RuntimeManifestDigest != manifestDigestsBySeat[seat.MemberID] ||
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
		managedUpdateActed, err := controller.reconcileManagedUpdate(ctx, epoch, intent, seats, memberByID)
		if err != nil {
			placementErrs = append(placementErrs, fmt.Errorf("%s/%s: %w", intent.DatabaseID, intent.PartitionID, err))
			continue
		}
		if managedUpdateActed {
			return errors.Join(placementErrs...)
		}
		for _, seat := range seats {
			versioned, exists := memberByID[seat.MemberID]
			if !exists {
				state := controller.initialState(intent, seat, rowsBySeat[seat.MemberID], rosterDigest,
					profile, profileDigest, manifestsBySeat[seat.MemberID], manifestDigestsBySeat[seat.MemberID], 1)
				if _, err := controller.persist(ctx, epoch, 0, state); err != nil {
					return errors.Join(append(placementErrs, err)...)
				}
				return errors.Join(placementErrs...)
			}
			acted, err := controller.replaceLostMember(ctx, epoch, intent, seat, versioned, seats, memberByID,
				instanceByID, statusByNode)
			if err != nil {
				placementErrs = append(placementErrs, fmt.Errorf("%s/%s: %w", intent.DatabaseID, intent.PartitionID, err))
				continue intents
			}
			if acted {
				return errors.Join(placementErrs...)
			}
			acted, err = controller.advanceMember(ctx, epoch, intent, seat, versioned, instanceByID, statusByNode)
			if err != nil {
				placementErrs = append(placementErrs, fmt.Errorf("%s/%s: %w", intent.DatabaseID, intent.PartitionID, err))
				continue intents
			}
			if acted {
				return errors.Join(placementErrs...)
			}
		}
	}
	return errors.Join(placementErrs...)
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
	if state.ManagedRuntimeTarget.Phase == ManagedUpdateSeatHeld {
		controller.hold(fmt.Sprintf("managed update %s is durably held: %s",
			state.ManagedRuntimeTarget.OperationID, state.ManagedRuntimeTarget.Outcome))
		return false, nil
	}
	switch state.Stage {
	case StagePreparedHost:
		if !controller.runtimeArtifactReady(ctx, state, seat) {
			return false, nil
		}
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
			if !controller.runtimeArtifactReady(ctx, state, seat) {
				return false, nil
			}
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
			if err := controller.verifyPinnedImage(ctx); err != nil {
				return false, err
			}
			state.Stage = StagePreparedAttach
			state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "attach")
			_, err := controller.persist(ctx, epoch, versioned.Revision, state)
			return true, err
		}
		sizeGB, err := volumeSizeGB(controller.config.Resources.DiskBytes)
		if err != nil {
			return false, err
		}
		if !controller.runtimeArtifactReady(ctx, state, seat) {
			return false, nil
		}
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		volume, err := controller.fleet.CreateRetainedVolume(ctx, oci.VolumeCreateRequest{
			DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			MemberID:  seat.MemberID,
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
		if !controller.runtimeArtifactReady(ctx, state, seat) {
			return false, nil
		}
		if err := controller.verifyPinnedImage(ctx); err != nil {
			return false, err
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
				DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
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
				if !controller.runtimeArtifactReady(ctx, state, seat) {
					return false, nil
				}
				if err := controller.verifyPinnedImage(ctx); err != nil {
					return false, err
				}
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
		if acted, err := controller.holdTimedOutManagedCanary(ctx, epoch, intent, versioned); acted || err != nil {
			return acted, err
		}
		if !controller.preparedPinsMatch(intent, state, seat) {
			controller.hold(fmt.Sprintf("member %s prepared desired pins changed; launch is held", seat.MemberID))
			return false, nil
		}
		fresh, err := controller.freshPreparedInputs(ctx, epoch, intent, seat, state)
		if err != nil {
			return false, err
		}
		if !fresh {
			return false, nil
		}
		if err := controller.verifyPinnedImage(ctx); err != nil {
			return false, err
		}
		desired, err := controller.memberDesired(epoch, intent, state, seat)
		if err != nil {
			return false, err
		}
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		receipt, err := controller.desired.ApplyDesired(ctx, desired)
		if err != nil {
			return false, fmt.Errorf("apply prepared TerraBase desired for %s: %w", seat.MemberID, err)
		}
		if receipt.Generation != state.DesiredGeneration || receipt.Revision == 0 {
			return false, errors.New("host desired writer returned a mismatched receipt")
		}
		state.Stage = StageAwaitingHealthy
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "await-healthy")
		_, err = controller.persist(ctx, epoch, versioned.Revision, state)
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
		attachment, attached := observedAttachment(instance, state)
		if !attached || !validObservedAttachment(attachment) {
			controller.hold(fmt.Sprintf("member %s retained volume is not observed ATTACHED; desired state remains withheld", seat.MemberID))
			return false, nil
		}
		if !controller.runtimeArtifactReady(ctx, state, seat) {
			return false, nil
		}
		if err := controller.verifyPinnedImage(ctx); err != nil {
			return false, err
		}
		if _, err := host.ManagedMountPath(state.RuntimeManifest.ManagedRuntimeRoot, controller.memberBinding(intent, state)); err != nil {
			controller.hold(fmt.Sprintf("member %s has no safe managed mount path: %v", seat.MemberID, err))
			return false, nil
		}
		state.AttachmentDevice, state.AttachmentETag = attachment.Device, attachment.ETag
		state.DesiredGeneration = state.IntentGeneration
		state.Stage = StagePreparedDesired
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "prepare-desired")
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	case StageAwaitingHealthy:
		if acted, err := controller.holdTimedOutManagedCanary(ctx, epoch, intent, versioned); acted || err != nil {
			return acted, err
		}
		if instance, exists := instances[state.InstanceID]; exists {
			if err := controller.validateObservedInstance(instance, state, seat); err != nil {
				return false, err
			}
			if status, admitted := controller.admittedHost(intent, state, instance, statuses); admitted &&
				status.Registration.Generation == state.HostGeneration {
				if state.ManagedRuntimeTarget.OperationID != "" {
					current, err := controller.managedUpdatePrepareIsCurrent(ctx, state)
					if err != nil {
						return false, err
					}
					if !current {
						controller.hold(fmt.Sprintf("member %s managed canary authority is no longer current", seat.MemberID))
						return false, nil
					}
				}
				if controller.hasServingReport(intent, state, instance, status) {
					if state.ManagedRuntimeTarget.OperationID != "" {
						target := state.ManagedRuntimeTarget
						target.Phase = ManagedUpdateSeatCanaryServing
						target.Outcome = string(authority.ManagedUpdateCanaryServing)
						_, err := controller.commitManagedUpdateOutcome(ctx, epoch, state,
							authority.ManagedUpdateCanaryServing, target.Outcome,
							func(verifyCtx context.Context, update ManagedUpdateIntent,
								prepared authority.ManagedUpdateRecord,
							) error {
								return controller.verifyManagedCanaryServingAtAuthorityCommit(verifyCtx, epoch, update, prepared, versioned)
							})
						if err != nil {
							return false, err
						}
						state.ManagedRuntimeTarget = target
					}
					state.Stage = StageServing
					state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "serving")
					_, err := controller.persist(ctx, epoch, versioned.Revision, state)
					return true, err
				}
				if state.ManagedRuntimeTarget.OperationID != "" && hasCurrentFailedCanaryReport(status, state,
					controller.config.Environment, controller.config.MemberRole) {
					outcome := "candidate-reported-failure"
					target := state.ManagedRuntimeTarget
					target.Phase, target.Outcome = ManagedUpdateSeatHeld, outcome
					_, err := controller.commitManagedUpdateOutcome(ctx, epoch, state,
						authority.ManagedUpdateHeld, outcome,
						func(verifyCtx context.Context, update ManagedUpdateIntent,
							prepared authority.ManagedUpdateRecord,
						) error {
							return controller.verifyManagedCanaryFailureAtAuthorityCommit(verifyCtx, epoch, update, versioned,
								controller.config.Environment, controller.config.MemberRole)
						})
					if err != nil {
						return false, err
					}
					state.ManagedRuntimeTarget = target
					state.OperationID = digestToken("u", state.DatabaseID, state.PartitionID,
						state.ManagedRuntimeTarget.OperationID, state.MemberID, "held")
					_, err = controller.persist(ctx, epoch, versioned.Revision, state)
					return true, err
				}
			}
		}
		controller.hold(fmt.Sprintf("member %s awaits a current mounted process and independent TerraBase serving proof", seat.MemberID))
		return false, nil
	case StageServing:
		if instance, exists := instances[state.InstanceID]; exists {
			if err := controller.validateObservedInstance(instance, state, seat); err != nil {
				return false, err
			}
			if status, admitted := controller.admittedHost(intent, state, instance, statuses); admitted &&
				status.Registration.Generation == state.HostGeneration &&
				controller.hasServingReport(intent, state, instance, status) {
				return false, nil
			}
		}
		if state.ManagedRuntimeTarget.OperationID != "" {
			controller.hold(fmt.Sprintf("managed canary member %s lost its current candidate serving proof; it remains held without peer promotion", seat.MemberID))
			return false, nil
		}
		state.Stage = StageAwaitingRuntimeContract
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
		_, err := controller.persist(ctx, epoch, versioned.Revision, state)
		controller.hold(fmt.Sprintf("member %s lost current host, attachment, mounted process, or TerraBase serving proof; it is held without replacement", seat.MemberID))
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

func (controller *Controller) verifyPinnedImage(ctx context.Context) error {
	if err := controller.fleet.VerifyPinnedImage(ctx); err != nil {
		return fmt.Errorf("current managed OCI image qualification: %w", err)
	}
	return nil
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

func (controller *Controller) initialState(intent Intent, seat Seat, row CanonicalRosterRow, rosterDigest string, profile ManagedHostProfile, profileDigest string, manifest RuntimeManifest, manifestDigest string, attempt uint64) MemberState {
	return MemberState{
		SchemaVersion: managedUpdateMemberStateSchemaVersion, DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		MemberID: seat.MemberID, Region: seat.Region, FailureDomain: seat.FailureDomain, Kind: seat.Kind,
		Stage: StagePreparedHost, CreateKey: hostCreateKey(intent, seat, attempt), HostAttempt: attempt,
		CanonicalRosterRow: row, CanonicalRosterDigest: rosterDigest, AuthorityReference: intent.CanonicalRoster.Authority,
		RuntimeManifest: manifest, RuntimeManifestDigest: manifestDigest,
		IntentPayloadDigest: intent.PayloadDigest(), ManagedHostProfile: profile, ManagedHostProfileDigest: profileDigest,
		IntentGeneration: intent.Generation, OperationID: memberOperationID(intent, seat.MemberID, attempt, "prepare"),
		UpdatedAt: time.Now().UTC(),
	}
}

func pinnedEnsureRequest(state MemberState) oci.EnsureRequest {
	privateIP, _, _ := net.SplitHostPort(state.RuntimeManifest.ReplicationListenAddress)
	return oci.EnsureRequest{
		CreateKey: state.CreateKey, PrivateIP: privateIP, FaultDomain: state.FailureDomain,
		Shape: state.ManagedHostProfile.Compute.Shape, WholeOCPUs: state.ManagedHostProfile.Compute.WholeOCPUs,
		MemoryInGBs:            state.ManagedHostProfile.Compute.MemoryInGBs,
		PlacementProfileDigest: state.ManagedHostProfileDigest, PlacementGeneration: state.IntentGeneration,
		BootPins: oci.HostBootPins{
			DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
			HostAttempt: state.HostAttempt, IntentPayloadDigest: state.IntentPayloadDigest,
			CanonicalRosterDigest: state.CanonicalRosterDigest, RuntimeManifestDigest: state.RuntimeManifestDigest,
		},
	}
}

func (controller *Controller) validateEnsuredInstance(instance oci.Instance, state MemberState, seat Seat) error {
	privateIP, _, err := net.SplitHostPort(state.RuntimeManifest.ReplicationListenAddress)
	if err != nil || privateIP == "" || instance.PrivateIP != privateIP {
		return errors.New("OCI EnsureHost returned a different prepared private IP")
	}
	if instance.ID == "" || instance.Node == "" || instance.ETag == "" || instance.CreateKey != state.CreateKey ||
		state.InstanceID != "" && instance.ID != state.InstanceID || state.HostNode != "" && instance.Node != state.HostNode ||
		instance.Region != controller.config.Region || instance.FaultDomain != seat.FailureDomain ||
		!controller.instanceMatchesPinnedProfile(instance, state) {
		return errors.New("OCI EnsureHost returned an instance with mismatched durable placement identity")
	}
	return nil
}

func (controller *Controller) validateObservedInstance(instance oci.Instance, state MemberState, seat Seat) error {
	privateIP, _, err := net.SplitHostPort(state.RuntimeManifest.ReplicationListenAddress)
	if err != nil || privateIP == "" || instance.PrivateIP != privateIP {
		return errors.New("observed OCI instance differs from the prepared private IP")
	}
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
		instance.ImageID == controller.config.ImageID && controller.instanceMatchesPinnedBootDescriptor(instance, state) &&
		instance.Shape == compute.Shape && instance.WholeOCPUs == compute.WholeOCPUs &&
		instance.MemoryInGBs == compute.MemoryInGBs && instance.PlacementProfileDigest == state.ManagedHostProfileDigest &&
		instance.PlacementGeneration == state.IntentGeneration
}

func (controller *Controller) instanceMatchesPinnedBootDescriptor(instance oci.Instance, state MemberState) bool {
	descriptor := hostboot.Descriptor{
		SchemaVersion: hostboot.SchemaVersion, Cell: controller.config.Cell, Region: string(controller.config.Region),
		Node: instance.Node, Owner: controller.config.ManagedOwner, CreateKey: state.CreateKey,
		ImageID: controller.config.ImageID, FleetGeneration: controller.config.FleetGeneration,
		DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, SeatID: state.MemberID,
		HostAttempt: state.HostAttempt, IntentGeneration: state.IntentGeneration,
		IntentPayloadDigest: state.IntentPayloadDigest, CanonicalRosterDigest: state.CanonicalRosterDigest,
		ManagedHostProfileDigest: state.ManagedHostProfileDigest, RuntimeManifestDigest: state.RuntimeManifestDigest,
	}
	digest, err := descriptor.Digest()
	return err == nil && digest == instance.BootDescriptorSHA256
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

func (controller *Controller) hasServingReport(intent Intent, state MemberState, instance oci.Instance, status host.HostStatus) bool {
	manifest := state.EffectiveRuntimeManifest()
	attachment, attached := observedAttachment(instance, state)
	if !attached || !validObservedAttachment(attachment) ||
		attachment.Device != state.AttachmentDevice || attachment.ETag != state.AttachmentETag {
		return false
	}
	var survivor memberstatus.Survivor
	for _, row := range intent.CanonicalRoster.Rows {
		if row.MemberID == manifest.ReplicationPeerMemberID && row.MemberID != state.CanonicalRosterRow.MemberID {
			survivor = memberstatus.Survivor{MemberID: row.MemberID, Incarnation: row.Incarnation}
			break
		}
	}
	if survivor.MemberID == "" {
		return false
	}
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, controller.memberBinding(intent, state))
	if err != nil {
		return false
	}
	now := time.Now()
	for _, report := range status.Reports {
		managed := report.Managed
		if report.Cell != controller.config.Cell || report.Node != status.Registration.Node ||
			report.Environment != controller.config.Environment || report.Role != controller.config.MemberRole ||
			report.Generation != state.DesiredGeneration || report.Digest != manifest.ArtifactDigest ||
			report.State != "running" || report.ObservedAt.IsZero() || report.ObservedAt.After(now.Add(2*time.Second)) ||
			now.Sub(report.ObservedAt) >= host.ReportMaxAge || managed == nil || managed.ServingProof == nil ||
			managed.Member != controller.memberBinding(intent, state) ||
			managed.Authority != (host.MemberAuthority{
				Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
				CertificateSHA256: state.AuthorityReference.CertificateSHA256,
				TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
			}) || managed.OCI != (host.ManagedOCIBinding{
			Region: string(state.Region), InstanceID: state.InstanceID, Owner: controller.config.ManagedOwner,
			FleetGeneration: controller.config.FleetGeneration, CreateKey: state.CreateKey,
		}) || managed.VolumeID != state.VolumeID || managed.AttachmentID != state.AttachmentID ||
			managed.AttachmentETag != attachment.ETag || managed.FileSystemUUID != manifest.FileSystemUUID ||
			managed.FileSystemType != manifest.FileSystemType || managed.MountDevice != attachment.Device ||
			managed.MountPath != mountPath || managed.MountID == 0 || managed.ProcessPID < 2 ||
			managed.ProcessStart == "" || !strings.HasPrefix(managed.ProcessCgroup, "/") ||
			!managed.StorageRecovered || !managed.ListenerReady {
			continue
		}
		proof := managed.ServingProof
		if memberstatus.VerifyReportedServing(*proof, memberstatus.Identity{
			Process: memberstatus.Process{PID: managed.ProcessPID, StartNonce: managed.ProcessBootID},
			Scope: memberstatus.Scope{
				ClusterID: intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
				DatabaseID: intent.CanonicalRoster.DatabaseID, ShardID: intent.CanonicalRoster.ShardID,
				MemberID: state.CanonicalRosterRow.MemberID, Incarnation: state.CanonicalRosterRow.Incarnation,
			},
			Authority: memberstatus.Authority{
				Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
				CertificateSHA256: state.AuthorityReference.CertificateSHA256,
				TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
			},
		}, survivor) == nil {
			return true
		}
	}
	return false
}

func (controller *Controller) persist(ctx context.Context, epoch, revision uint64, state MemberState) (uint64, error) {
	barrier, ok := controller.fencer.(interface {
		BeginActiveWorkloadEffect(context.Context, uint64, authority.WorkloadScope) (func(), error)
	})
	if !ok {
		return 0, errors.New("placement authority lacks terminal workload fence")
	}
	release, err := barrier.BeginActiveWorkloadEffect(ctx, epoch, authority.WorkloadScope{
		DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
	})
	if err != nil {
		return 0, err
	}
	defer release()
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

// TerminalTargetsForRegion derives the only workload create keys that a
// terminal plan may name. A durable member pins any later host attempt; if a
// member has not been prepared, only the first attempt can exist.
func TerminalTargetsForRegion(intent Intent, region oci.Region, faultDomains []string,
	members []VersionedMemberState,
) ([]authority.TerminalTarget, error) {
	if len(intent.ActiveRegions) != 1 || intent.ActiveRegions[0] != region {
		return nil, fmt.Errorf("%w: terminal plan is limited to one admitted managed region", ErrInvalidIntent)
	}
	seats, err := DesiredSeats(intent, map[oci.Region][]string{region: faultDomains})
	if err != nil {
		return nil, err
	}
	if len(seats) != 2 || len(members) > len(seats) {
		return nil, fmt.Errorf("%w: terminal plan requires two exact local seats", ErrInvalidIntent)
	}
	bySeat := make(map[string]MemberState, len(members))
	for _, member := range members {
		state := member.State
		if member.Revision == 0 || state.Validate() != nil || state.DatabaseID != intent.DatabaseID ||
			state.PartitionID != intent.PartitionID || state.Region != region ||
			state.IntentGeneration != intent.Generation || state.IntentPayloadDigest != intent.PayloadDigest() {
			return nil, fmt.Errorf("%w: terminal member state differs from admitted placement", ErrStoreCorrupt)
		}
		if _, exists := bySeat[state.MemberID]; exists {
			return nil, fmt.Errorf("%w: duplicate terminal member state", ErrStoreCorrupt)
		}
		bySeat[state.MemberID] = state
	}
	targets := make([]authority.TerminalTarget, 0, len(seats))
	for _, seat := range seats {
		row, err := intent.RosterRowForSeat(seat)
		if err != nil {
			return nil, err
		}
		attempt := uint64(1)
		if state, exists := bySeat[seat.MemberID]; exists {
			attempt = state.HostAttempt
			if state.Kind != seat.Kind || state.FailureDomain != seat.FailureDomain ||
				state.CreateKey != hostCreateKey(intent, seat, attempt) {
				return nil, fmt.Errorf("%w: terminal host key differs from durable member", ErrStoreCorrupt)
			}
			delete(bySeat, seat.MemberID)
		}
		targets = append(targets, authority.TerminalTarget{
			SeatID: seat.MemberID, MemberID: row.MemberID,
			HostCreateKey: hostCreateKey(intent, seat, attempt), DataCreateKey: volumeCreateKey(intent, seat),
		})
	}
	if len(bySeat) != 0 {
		return nil, fmt.Errorf("%w: terminal member lies outside admitted seats", ErrStoreCorrupt)
	}
	return targets, nil
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
	_, attached := observedAttachment(instance, state)
	return attached
}

func observedAttachment(instance oci.Instance, state MemberState) (oci.Attachment, bool) {
	if state.VolumeID == "" || state.AttachmentID == "" {
		return oci.Attachment{}, false
	}
	for _, attachment := range instance.Attachments {
		if attachment.ID == state.AttachmentID && attachment.VolumeID == state.VolumeID &&
			attachment.InstanceID == state.InstanceID && attachment.State == "ATTACHED" {
			return attachment, true
		}
	}
	return oci.Attachment{}, false
}

func validObservedAttachment(attachment oci.Attachment) bool {
	return attachment.ETag != "" && strings.HasPrefix(attachment.Device, "/dev/") &&
		filepath.Clean(attachment.Device) == attachment.Device && len(attachment.Device) <= 255 &&
		!strings.ContainsAny(attachment.Device, " \t\r\n\x00") &&
		!attachment.IsReadOnly && !attachment.IsShareable && attachment.IsPvEncryptionInTransitEnabled
}

func (controller *Controller) memberBinding(intent Intent, state MemberState) host.ManagedMemberBinding {
	roster, row := intent.CanonicalRoster, state.CanonicalRosterRow
	return host.ManagedMemberBinding{
		Scope: host.MemberScope{
			ClusterID: roster.ClusterID, TenantID: roster.TenantID, DatabaseID: roster.DatabaseID,
			ShardID: roster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation,
		},
		HostAttempt: state.HostAttempt,
	}
}

func (controller *Controller) admittedRuntimeArtifact(ctx context.Context, state MemberState) (AdmittedArtifact, error) {
	manifest := state.EffectiveRuntimeManifest()
	artifact, err := controller.resolveArtifact(ctx, manifest.ArtifactDigest, controller.config.MemberRole, controller.config.Environment)
	if err != nil {
		return AdmittedArtifact{}, err
	}
	if artifact.Digest != manifest.ArtifactDigest || artifact.SourceDigest != manifest.SourceDigest {
		return AdmittedArtifact{}, errors.New("admitted runtime artifact differs from signed source and byte pins")
	}
	if target := state.ManagedRuntimeTarget; target.OperationID != "" &&
		artifact.ManifestDigest != target.ManifestDigest {
		return AdmittedArtifact{}, errors.New("admitted managed update manifest differs from its durable target")
	}
	return artifact, nil
}

func (controller *Controller) runtimeArtifactReady(ctx context.Context, state MemberState, seat Seat) bool {
	if _, err := controller.admittedRuntimeArtifact(ctx, state); err != nil {
		controller.hold(fmt.Sprintf("member %s runtime artifact is not currently admitted: %v", seat.MemberID, err))
		return false
	}
	return true
}

func (controller *Controller) memberDesired(epoch uint64, intent Intent, state MemberState, seat Seat) (host.Desired, error) {
	manifest := state.EffectiveRuntimeManifest()
	binding := controller.memberBinding(intent, state)
	mountPath, err := host.ManagedMountPath(manifest.ManagedRuntimeRoot, binding)
	if err != nil {
		return host.Desired{}, err
	}
	return host.Desired{
		Cell: controller.config.Cell, Node: state.HostNode, Environment: controller.config.Environment,
		Role: controller.config.MemberRole, Digest: manifest.ArtifactDigest,
		Generation: state.DesiredGeneration, AuthorityEpoch: epoch,
		ManagedMember: &host.ManagedMemberLaunch{
			OCI: host.ManagedOCIBinding{
				Region: string(seat.Region), InstanceID: state.InstanceID, Owner: controller.config.ManagedOwner,
				FleetGeneration: controller.config.FleetGeneration, CreateKey: state.CreateKey,
			},
			Member: binding,
			Authority: host.MemberAuthority{
				Epoch: state.AuthorityReference.Epoch, ConfigurationID: state.AuthorityReference.ConfigurationID,
				CertificateSHA256: state.AuthorityReference.CertificateSHA256,
				TLSLeafSHA256:     state.CanonicalRosterRow.TLSLeafSHA256,
			},
			SourceDigest: manifest.SourceDigest, VolumeID: state.VolumeID,
			AttachmentID: state.AttachmentID, AttachmentETag: state.AttachmentETag,
			ProcessMemoryBytes:   state.ManagedHostProfile.ProcessMemoryBytes,
			MemoryHeadroomBytes:  state.ManagedHostProfile.MemoryHeadroomBytes,
			CgroupMemoryMaxBytes: state.ManagedHostProfile.CgroupMemoryMaxBytes,
			SystemReserveBytes:   state.ManagedHostProfile.SystemReserveBytes,
			Runtime: &host.ManagedRuntimePins{
				DevicePath: state.AttachmentDevice, MountPath: mountPath,
				FileSystemUUID: manifest.FileSystemUUID, FileSystemType: manifest.FileSystemType,
				TrustedKeySHA256:                    manifest.TrustedKeySHA256,
				ServerCertificateSHA256:             manifest.ServerCertificateSHA256,
				ServerPrivateKeySHA256:              manifest.ServerPrivateKeySHA256,
				ClientCARootsSHA256:                 manifest.ClientCARootsSHA256,
				ClientManagedMaterialManifestSHA256: manifest.ClientManagedMaterialManifestSHA256,
				SQLSchemaBundleSHA256:               manifest.SQLSchemaBundleSHA256,
				LiveS3ConfigSHA256:                  manifest.LiveS3ConfigSHA256,
				LiveS3TargetSHA256:                  manifest.LiveS3TargetSHA256,
				LiveS3Credential:                    manifest.LiveS3Credential,
				BackupManifestSHA256:                manifest.BackupManifestSHA256,
				BackupS3ConfigSHA256:                manifest.BackupS3ConfigSHA256,
				BackupS3TargetSHA256:                manifest.BackupS3TargetSHA256,
				BackupS3CredentialSHA256:            manifest.BackupS3CredentialSHA256,
				BackupDataKeySHA256:                 manifest.BackupDataKeySHA256,
				BackupOwner:                         manifest.BackupOwner,
				BackupS3Credential:                  manifest.BackupS3Credential,
				BackupDataKey:                       manifest.BackupDataKey,
				ReplicationListenAddress:            manifest.ReplicationListenAddress,
				ReplicationPeerMemberID:             manifest.ReplicationPeerMemberID,
				ReplicationPeerAddress:              manifest.ReplicationPeerAddress,
				ReplicationServerCASHA256:           manifest.ReplicationServerCASHA256,
			},
		},
	}, nil
}

func (controller *Controller) preparedPinsMatch(intent Intent, state MemberState, seat Seat) bool {
	manifest, err := intent.RuntimeManifestForSeat(seat)
	if err != nil || manifest != state.RuntimeManifest || state.Validate() != nil {
		return false
	}
	digest, err := manifest.Digest()
	return err == nil && digest == state.RuntimeManifestDigest
}

func (controller *Controller) freshPreparedInputs(ctx context.Context, epoch uint64, intent Intent, seat Seat, state MemberState) (bool, error) {
	if state.ManagedRuntimeTarget.OperationID != "" {
		current, err := controller.managedUpdatePrepareIsCurrent(ctx, state)
		if err != nil {
			return false, err
		}
		if !current {
			controller.hold(fmt.Sprintf("member %s managed update authorization is no longer prepared", seat.MemberID))
			return false, nil
		}
	}
	if _, err := controller.admittedRuntimeArtifact(ctx, state); err != nil {
		controller.hold(fmt.Sprintf("member %s runtime artifact admission changed: %v", seat.MemberID, err))
		return false, nil
	}
	if err := controller.guard(ctx, epoch); err != nil {
		return false, err
	}
	currentIntents, err := controller.store.ListIntents(ctx)
	if err != nil {
		return false, err
	}
	foundIntent := false
	for _, current := range currentIntents {
		if current.DatabaseID == state.DatabaseID && current.PartitionID == state.PartitionID {
			if foundIntent || current.PayloadDigest() != intent.PayloadDigest() || current.Generation != intent.Generation {
				controller.hold(fmt.Sprintf("member %s placement intent changed before desired effect", seat.MemberID))
				return false, nil
			}
			foundIntent = true
		}
	}
	if !foundIntent {
		controller.hold(fmt.Sprintf("member %s placement intent disappeared before desired effect", seat.MemberID))
		return false, nil
	}
	instances, err := controller.fleet.Observe(ctx)
	if err != nil {
		return false, err
	}
	var currentInstance oci.Instance
	instanceCount := 0
	for _, instance := range instances {
		if instance.ID == state.InstanceID {
			currentInstance = instance
			instanceCount++
		}
	}
	if instanceCount != 1 || controller.validateObservedInstance(currentInstance, state, seat) != nil {
		controller.hold(fmt.Sprintf("member %s owned OCI host changed before desired effect", seat.MemberID))
		return false, nil
	}
	attachment, attached := observedAttachment(currentInstance, state)
	if !attached || !validObservedAttachment(attachment) ||
		attachment.Device != state.AttachmentDevice || attachment.ETag != state.AttachmentETag {
		controller.hold(fmt.Sprintf("member %s OCI attachment device or ETag changed before desired effect", seat.MemberID))
		return false, nil
	}
	statuses, err := controller.hosts.ListHosts(ctx)
	if err != nil {
		return false, err
	}
	var currentStatus host.HostStatus
	statusCount := 0
	for _, status := range statuses {
		if status.Registration.Node == state.HostNode {
			currentStatus = status
			statusCount++
		}
	}
	if statusCount != 1 {
		controller.hold(fmt.Sprintf("member %s exact host registration disappeared before desired effect", seat.MemberID))
		return false, nil
	}
	status, admitted := controller.admittedHost(intent, state, currentInstance, map[string]host.HostStatus{state.HostNode: currentStatus})
	if !admitted || status.Registration.Generation != state.HostGeneration {
		controller.hold(fmt.Sprintf("member %s host session or registration changed before desired effect", seat.MemberID))
		return false, nil
	}
	currentDesired, err := controller.hosts.ListDesired(ctx, controller.config.MemberRole)
	if err != nil {
		return false, err
	}
	want, err := controller.memberDesired(epoch, intent, state, seat)
	if err != nil {
		return false, err
	}
	seenDesired := false
	previousDesired := false
	for _, existing := range currentDesired {
		if existing.Node != state.HostNode || existing.Role != controller.config.MemberRole {
			continue
		}
		if seenDesired {
			controller.hold(fmt.Sprintf("member %s host view returned duplicate desired targets", seat.MemberID))
			return false, nil
		}
		seenDesired = true
		want.AuthorityEpoch, existing.AuthorityEpoch = 0, 0
		if reflect.DeepEqual(existing, want) {
			continue
		}
		target := state.ManagedRuntimeTarget
		if target.OperationID != "" {
			previous, err := controller.memberDesired(epoch, intent, state.PredecessorState(), seat)
			if err != nil {
				return false, err
			}
			previous.AuthorityEpoch = 0
			if reflect.DeepEqual(existing, previous) {
				previousDesired = true
				continue
			}
		}
		if !previousDesired {
			controller.hold(fmt.Sprintf("member %s host desired target differs from prepared pins", seat.MemberID))
			return false, nil
		}
	}
	if state.ManagedRuntimeTarget.OperationID != "" && !seenDesired {
		controller.hold(fmt.Sprintf("member %s managed canary lost its recorded predecessor desired", seat.MemberID))
		return false, nil
	}
	return true, nil
}
