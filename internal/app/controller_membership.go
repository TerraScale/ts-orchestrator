package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/membership"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// natsMembershipPeers adapts the embedded broker's JetStream metadata view.
type natsMembershipPeers struct{ runtime *natscell.Runtime }

func (peers natsMembershipPeers) Meta(context.Context) (membership.Meta, error) {
	view, err := peers.runtime.Meta()
	if err != nil {
		return membership.Meta{}, err
	}
	return membershipMeta(view), nil
}

func membershipMeta(view natscell.MetaView) membership.Meta {
	meta := membership.Meta{Leader: view.Leader, Size: view.Size}
	for _, replica := range view.Replicas {
		if replica.Name == view.Self {
			continue
		}
		meta.Peers = append(meta.Peers, membership.Peer{Name: replica.Name,
			Online: !replica.Offline && !replica.Pending, Current: replica.Current,
			Lag: replica.Lag, Active: replica.Active})
	}
	return meta
}

// ledgerMembershipSlots reads historically verified controller slot HEADs.
type ledgerMembershipSlots struct {
	ledger       bootstrapstart.SlotReader
	deploymentID string
	cell         string
}

func (source ledgerMembershipSlots) Slots(ctx context.Context, slots []string) (map[string]membership.LedgerSlot, error) {
	summaries, err := bootstrapstart.SummarizeControllerSlots(ctx, source.ledger, source.deploymentID, source.cell, slots)
	if err != nil {
		return nil, err
	}
	out := make(map[string]membership.LedgerSlot, len(summaries))
	for slot, summary := range summaries {
		out[slot] = membership.LedgerSlot{Attempt: summary.Attempt, InstanceOCID: summary.InstanceOCID,
			Complete: summary.Complete, Retirement: summary.Retirement}
	}
	return out, nil
}

type lifecycleObserver interface {
	ObserveLifecycle(context.Context, string) (string, error)
}

type lifecycleInstances struct{ observer lifecycleObserver }

func (instances lifecycleInstances) Lifecycle(ctx context.Context, instanceID string) (string, error) {
	return instances.observer.ObserveLifecycle(ctx, instanceID)
}

// founderMembershipReplacer relaunches a slot through the seed's founder. It
// is opened lazily per action so a long-lived controller always uses the
// currently selected founder authority, and fails closed off the seed.
type founderMembershipReplacer struct {
	open func(context.Context) (*bootstrapstart.FounderReplacer, error)
}

func (replacer founderMembershipReplacer) Replace(ctx context.Context, action membership.Action) error {
	if replacer.open == nil {
		return membership.ErrReplacerUnavailable
	}
	founder, err := replacer.open(ctx)
	if err != nil {
		return fmt.Errorf("open seed founder replacer: %w", err)
	}
	return founder.ReplaceFenced(ctx, action.Slot, action.Retirement.Wire, action.Fence)
}

// RetirementRequestSuffix names the unsigned candidate a controller writes
// for the operator to review and sign with `bootstrap sign-slot-retirement`.
const RetirementRequestSuffix = ".retirement-request.json"

// ledgerRetirementRequests renders unsigned retirement candidates from the
// exact ledger HEAD. It binds a digest of the observation that justified the
// request; it never signs.
type ledgerRetirementRequests struct {
	ledger       bootstrapstart.SlotReader
	deploymentID string
	cell         string
	dir          string
	// fencingAuthority overrides the authority-epoch binding for requests
	// rendered outside a controller term (break-glass recovery).
	fencingAuthority string
}

func (requests ledgerRetirementRequests) RequestRetirement(ctx context.Context, request membership.RetirementRequest) error {
	observed, err := protocol.EncodeJSON(struct {
		Slot         string    `json:"slot"`
		Attempt      uint64    `json:"attempt"`
		InstanceOCID string    `json:"instanceOcid"`
		Lifecycle    string    `json:"lifecycle"`
		MetaLeader   string    `json:"metaLeader"`
		OfflineSince time.Time `json:"offlineSince"`
		ObservedAt   time.Time `json:"observedAt"`
		Epoch        uint64    `json:"epoch"`
	}{request.Slot, request.Attempt, request.InstanceOCID, request.Lifecycle, request.MetaLeader,
		request.OfflineSince, request.ObservedAt, request.Epoch})
	if err != nil {
		return err
	}
	fencing := requests.fencingAuthority
	if fencing == "" {
		fencing = fmt.Sprintf("authority-epoch-%d", request.Epoch)
	}
	candidate, err := bootstrapstart.RenderSlotRetirementCandidate(ctx, requests.ledger, requests.deploymentID,
		requests.cell, request.Slot, controllerSHA256(observed), fencing, request.ObservedAt)
	if err != nil {
		return err
	}
	if candidate.PreviousAttempt != request.Attempt || candidate.PriorInstanceOCID != request.InstanceOCID {
		return errors.New("controller slot ledger changed while rendering its retirement request")
	}
	wire, err := protocol.EncodeJSON(candidate)
	if err != nil {
		return err
	}
	return writeOwnerOnlyFile(requests.dir, request.Slot+RetirementRequestSuffix, wire)
}

// writeOwnerOnlyFile atomically and durably replaces dir/name with data at
// mode 0600: the directory is synced after the rename.
func writeOwnerOnlyFile(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".request-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

// acceptedMembershipSlots observes current physical controllers without
// inventing former launch attempts or authority to launch replacements.
type acceptedMembershipSlots struct {
	accepted bootstrapstart.AcceptedIdentity
}

func (source acceptedMembershipSlots) Slots(ctx context.Context, slots []string) (map[string]membership.LedgerSlot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := source.accepted.Validate(); err != nil {
		return nil, err
	}
	result := make(map[string]membership.LedgerSlot, len(slots))
	for _, binding := range source.accepted.ControllerBindings {
		if slices.Contains(slots, binding.Slot) {
			result[binding.Slot] = membership.LedgerSlot{InstanceOCID: binding.InstanceOCID, Complete: true}
		}
	}
	return result, nil
}

type membershipLedger struct {
	baked    bootstrapstart.BakedInputs
	accepted bootstrapstart.AcceptedIdentity
	initial  *bootstrapstart.AcceptedInstall
	observer lifecycleObserver
	ledger   bootstrapstart.SlotReader
	slots    membership.LedgerSource
}

func openMembershipLedger(ctx context.Context) (membershipLedger, error) {
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return membershipLedger{}, err
	}
	if _, err := bootstrapstart.ReadIdentityRekeyJournal(accepted); err == nil {
		region := oci.Region(accepted.Cell)
		provider, err := bootstrap.NewRegionalInstancePrincipalConfigurationProvider(region)
		if err != nil {
			return membershipLedger{}, err
		}
		instances, err := bootstrapstart.NewOCIInstanceObserver(region, provider)
		if err != nil {
			return membershipLedger{}, err
		}
		observer := instances
		return membershipLedger{accepted: accepted, observer: observer, slots: acceptedMembershipSlots{accepted: accepted}}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return membershipLedger{}, err
	}
	initial, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return membershipLedger{}, err
	}
	if initial.DeploymentID != accepted.DeploymentID || initial.Cell != accepted.Cell || initial.Slot != accepted.Slot ||
		initial.InstanceOCID != accepted.InstanceOCID || initial.PrimaryVNICOCID != accepted.PrimaryVNICOCID {
		return membershipLedger{}, errors.New("current formation differs from accepted controller identity")
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return membershipLedger{}, err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return membershipLedger{}, err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, baked.Roots,
		baked.Identity.AnchorExpectation(), initial.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != initial.AnchorSHA256 {
		return membershipLedger{}, errors.New("current formation anchor differs from root-owned history")
	}
	if _, derived, present, err := installedAutomaticStartup(ctx); err != nil {
		return membershipLedger{}, err
	} else if present {
		instances, _, _, err := bootstrapstart.NewDerivedOCIAdmissionClients(ctx, derived, baked.Roots)
		if err != nil {
			return membershipLedger{}, err
		}
		observer, ok := instances.(lifecycleObserver)
		if !ok {
			return membershipLedger{}, errors.New("derived OCI observer cannot read lifecycle state")
		}
		ledger, err := derived.OpenLedger(ctx, baked.Roots)
		if err != nil {
			return membershipLedger{}, err
		}
		return membershipLedger{baked: baked, accepted: accepted, initial: &initial, observer: observer, ledger: ledger,
			slots: ledgerMembershipSlots{ledger: ledger, deploymentID: accepted.DeploymentID, cell: accepted.Cell}}, nil
	}
	instances, _, err := bootstrapstart.NewHistoricalOCIAdmissionClients(anchor, baked.Roots)
	if err != nil {
		return membershipLedger{}, err
	}
	observer, ok := instances.(lifecycleObserver)
	if !ok {
		return membershipLedger{}, errors.New("OCI instance observer cannot read lifecycle state")
	}
	ledger, err := (bootstrapstart.InstancePrincipalLedgerOpener{}).OpenHistoricalLedger(ctx, anchor, baked.Roots)
	if err != nil {
		return membershipLedger{}, err
	}
	return membershipLedger{baked: baked, accepted: accepted, initial: &initial, observer: observer, ledger: ledger,
		slots: ledgerMembershipSlots{ledger: ledger, deploymentID: accepted.DeploymentID, cell: accepted.Cell}}, nil
}

func ControllerSlotLedger(ctx context.Context) (map[string]membership.LedgerSlot, error) {
	opened, err := openMembershipLedger(ctx)
	if err != nil {
		return nil, err
	}
	return opened.slots.Slots(ctx, opened.accepted.ControllerSlots)
}

// RenderBreakGlassRetirementRequest writes <slot>.retirement-request.json for
// a lost peer slot while metadata quorum, and with it controller authority, is
// lost, so no reconciler can render one. It re-checks the exact ledger-pinned
// instance is TERMINATED in OCI and never signs anything.
func RenderBreakGlassRetirementRequest(ctx context.Context, slot, dir string, now time.Time) (string, error) {
	opened, err := openMembershipLedger(ctx)
	if err != nil {
		return "", err
	}
	accepted := opened.accepted
	if opened.initial == nil {
		return "", errors.New("current controller replacement launch authority is absent for accepted deployment")
	}
	if !slices.Contains(opened.accepted.ControllerSlots, slot) || slot == accepted.Slot ||
		slot == accepted.SeedSlot {
		return "", errors.New("only a lost anchored non-seed peer slot other than this controller can be retired")
	}
	summaries, err := bootstrapstart.SummarizeControllerSlots(ctx, opened.ledger, accepted.DeploymentID,
		accepted.Cell, []string{slot})
	if err != nil {
		return "", err
	}
	summary := summaries[slot]
	if !summary.Complete || summary.InstanceOCID == "" {
		return "", errors.New("slot has no completed ledger attempt to retire")
	}
	lifecycle, err := opened.observer.ObserveLifecycle(ctx, summary.InstanceOCID)
	if err != nil {
		return "", fmt.Errorf("observe pinned instance %s: %w", summary.InstanceOCID, err)
	}
	if lifecycle != membership.LifecycleTerminated {
		return "", fmt.Errorf("pinned instance %s is %s; terminate it before retiring the slot", summary.InstanceOCID, lifecycle)
	}
	requests := ledgerRetirementRequests{ledger: opened.ledger, deploymentID: accepted.DeploymentID,
		cell: accepted.Cell, dir: dir, fencingAuthority: "break-glass-quorum-loss"}
	at := now.UTC().Truncate(time.Second)
	if err := requests.RequestRetirement(ctx, membership.RetirementRequest{Slot: slot, Attempt: summary.Attempt,
		InstanceOCID: summary.InstanceOCID, Lifecycle: lifecycle, ObservedAt: at}); err != nil {
		return "", err
	}
	return filepath.Join(dir, slot+RetirementRequestSuffix), nil
}

// controllerMembership is the membership supervision of one production
// controller: the reconciler every controller runs, and on the seed,
// the server that executes replacements a non-seed
// authority leader decided.
type controllerMembership struct {
	reconciler *membership.Reconciler
	seed       *seedReplacementService
	// Provider availability cannot gate local serving or bypass verified membership.
	open func(context.Context) (*controllerMembership, error)
}

// Run runs the reconciler and the seed server until ctx ends. Either one
// returning early (the seed failing to subscribe, say) stops the other, and
// both are joined before Run returns, so the controller's worker supervision
// sees the failure at once instead of only at shutdown.
func (m *controllerMembership) Run(ctx context.Context) error {
	if m.open != nil {
		for {
			attemptCtx, cancel := context.WithCancel(ctx)
			timer := time.AfterFunc(20*time.Second, cancel)
			opened, err := m.open(attemptCtx)
			stopped := timer.Stop()
			if err == nil && stopped && attemptCtx.Err() == nil {
				defer cancel()
				return opened.Run(attemptCtx)
			}
			if opened != nil && opened.seed != nil {
				opened.seed.server.Close()
			}
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				err = context.DeadlineExceeded
			}
			slog.WarnContext(ctx, "controller membership held while verified ledger is unavailable",
				"component", "membership", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(membership.DefaultInterval):
			}
		}
	}
	if m.seed == nil {
		return m.reconciler.Run(ctx)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- m.seed.Run(runCtx) }()
	go func() { errs <- m.reconciler.Run(runCtx) }()
	first := <-errs
	cancel()
	return errors.Join(first, <-errs)
}

// startControllerMembership builds the reconciler for every production controller.
func startControllerMembership(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	control *authority.Runtime,
) (*controllerMembership, error) {
	return &controllerMembership{open: func(openCtx context.Context) (*controllerMembership, error) {
		return openControllerMembership(openCtx, cfg, runtime, control)
	}}, nil
}

func openControllerMembership(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	control *authority.Runtime,
) (*controllerMembership, error) {
	opened, err := openMembershipLedger(ctx)
	if err != nil {
		return nil, err
	}
	baked, accepted, observer, ledger := opened.baked, opened.accepted, opened.observer, opened.ledger
	topology := membership.Topology{Cell: cfg.NATS.Cell, Slots: accepted.ControllerSlots,
		SeedSlot: accepted.SeedSlot, SelfSlot: accepted.Slot}
	logger := slog.Default().With("component", "membership")
	instances := lifecycleInstances{observer: observer}
	var replacer membership.Replacer
	var seed *seedReplacementService
	switch {
	case opened.initial != nil && accepted.Slot == accepted.SeedSlot:
		// The seed's own reconciler and its seed-routing server share one
		// founder replacer, which runs one replacement at a time.
		founder := &serializedReplacer{inner: founderMembershipReplacer{
			open: func(openCtx context.Context) (*bootstrapstart.FounderReplacer, error) {
				serviceUID, serviceGID, err := controllerServiceIdentity()
				if err != nil {
					return nil, err
				}
				local, derived, present, err := installedAutomaticStartup(openCtx)
				if err != nil {
					return nil, err
				}
				if present {
					if !bytes.Equal(local.baked.AnchorWire, baked.AnchorWire) {
						return nil, errors.New("replacement startup authority differs from the installed anchor")
					}
					return bootstrapstart.NewAdmittedDerivedFounderReplacer(openCtx, baked, *opened.initial, derived, serviceUID, serviceGID)
				}
				return bootstrapstart.NewAdmittedFounderReplacer(openCtx, baked, *opened.initial, serviceUID, serviceGID)
			}}}
		replacer = founder
		server, err := membership.NewSeedServer(ctx, topology, membership.SeedServerDependencies{
			Leases: control, Instances: instances, Replacer: founder, Logger: logger})
		if err != nil {
			return nil, err
		}
		seed = &seedReplacementService{conn: runtime.Conn(), subject: protocol.MembershipReplaceSubject(cfg.NATS.Cell),
			server: server}
	case opened.initial != nil:
		replacer = membership.SeedRoutedReplacer{Cell: cfg.NATS.Cell, Leadership: control,
			Request: natsSeedRequester(runtime.Conn(), protocol.MembershipReplaceSubject(cfg.NATS.Cell))}
	}
	var requests membership.RetirementRequester
	if opened.initial != nil {
		requests = ledgerRetirementRequests{ledger: ledger, deploymentID: accepted.DeploymentID, cell: accepted.Cell,
			dir: membership.DefaultRetirementEvidenceDir}
	}
	reconciler, err := membership.New(topology, membership.Dependencies{
		Leadership: control, Peers: natsMembershipPeers{runtime: runtime},
		Ledger:    opened.slots,
		Instances: instances,
		Evidence:  membership.NewFileEvidence(membership.DefaultRetirementEvidenceDir, topology.Slots, logger),
		Requests:  requests,
		Replacer:  replacer, Logger: logger,
	})
	if err != nil {
		if seed != nil {
			seed.server.Close()
		}
		return nil, err
	}
	return &controllerMembership{reconciler: reconciler, seed: seed}, nil
}

// stepDownMetaLeaderOnShutdown hands JetStream metadata leadership to a peer
// before this broker stops, using only the scoped membership user. It is a
// best-effort courtesy; a failure never blocks shutdown.
func stepDownMetaLeaderOnShutdown(runtime *natscell.Runtime, credentials string) {
	if runtime == nil || credentials == "" {
		return
	}
	view, err := runtime.Meta()
	if err != nil || view.Leader == "" || view.Leader != view.Self {
		return
	}
	admin, err := runtime.OpenMembershipAdmin(credentials)
	if err != nil {
		slog.Warn("membership step-down credentials unavailable", "error", err)
		return
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := admin.StepDownMetaLeader(ctx); err != nil {
		slog.WarnContext(ctx, "JetStream metadata leader step-down before shutdown failed", "error", err)
	}
}
