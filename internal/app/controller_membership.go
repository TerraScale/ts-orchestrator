package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
	return founder.Replace(ctx, action.Slot, action.Retirement.Wire)
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
	candidate, err := bootstrapstart.RenderSlotRetirementCandidate(ctx, requests.ledger, requests.deploymentID,
		requests.cell, request.Slot, controllerSHA256(observed), fmt.Sprintf("authority-epoch-%d", request.Epoch),
		request.ObservedAt)
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

// writeOwnerOnlyFile atomically replaces dir/name with data at mode 0600.
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
	return os.Rename(temporary.Name(), filepath.Join(dir, name))
}

// startControllerMembership builds the reconciler for a production controller
// whose signed config enables supervision. It returns nil when disabled.
func startControllerMembership(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	control *authority.Runtime,
) (*membership.Reconciler, error) {
	settings := cfg.Controller.Membership
	if settings == nil || !settings.Enabled {
		return nil, nil
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if cfg.NATS.Lab {
		return nil, errors.New("controller membership supervision requires a production controller")
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return nil, fmt.Errorf("load baked controller inputs for membership: %w", err)
	}
	accepted, err := bootstrapstart.NewMarkerStore().Read()
	if err != nil {
		return nil, fmt.Errorf("read accepted controller install for membership: %w", err)
	}
	anchorEnvelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return nil, err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, baked.Roots,
		baked.Identity.AnchorExpectation(), accepted.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != accepted.AnchorSHA256 {
		return nil, fmt.Errorf("verify accepted anchor for membership: %v", err)
	}
	instances, ledgers, err := bootstrapstart.NewHistoricalOCIAdmissionClients(anchor, baked.Roots)
	if err != nil {
		return nil, err
	}
	observer, ok := instances.(lifecycleObserver)
	if !ok {
		return nil, errors.New("OCI instance observer cannot read lifecycle state")
	}
	ledger, err := ledgers.OpenHistoricalLedger(ctx, anchor, baked.Roots)
	if err != nil {
		return nil, err
	}
	topology := membership.Topology{Cell: cfg.NATS.Cell, Slots: anchor.Anchor().ControllerSlots,
		SeedSlot: accepted.SeedSlot, SelfSlot: accepted.Slot}
	var replacer membership.Replacer
	if settings.Replace && accepted.Slot == accepted.SeedSlot {
		replacer = founderMembershipReplacer{open: func(openCtx context.Context) (*bootstrapstart.FounderReplacer, error) {
			serviceUID, serviceGID, err := controllerServiceIdentity()
			if err != nil {
				return nil, err
			}
			return bootstrapstart.NewAdmittedFounderReplacer(openCtx, baked, accepted, serviceUID, serviceGID)
		}}
	}
	return membership.New(*settings, topology, membership.Dependencies{
		Leadership: control, Peers: natsMembershipPeers{runtime: runtime},
		Ledger:    ledgerMembershipSlots{ledger: ledger, deploymentID: accepted.DeploymentID, cell: accepted.Cell},
		Instances: lifecycleInstances{observer: observer},
		Evidence:  membership.FileEvidence{Dir: settings.EvidenceDir(), Slots: topology.Slots},
		Requests: ledgerRetirementRequests{ledger: ledger, deploymentID: accepted.DeploymentID,
			cell: accepted.Cell, dir: settings.EvidenceDir()},
		Replacer: replacer, Logger: slog.Default().With("component", "membership"),
	})
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
		slog.Warn("JetStream metadata leader step-down before shutdown failed", "error", err)
	}
}
