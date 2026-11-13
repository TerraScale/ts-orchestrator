package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/membership"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

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
	local, derived, present, err := installedAutomaticStartup(ctx)
	if err != nil {
		return membershipLedger{}, err
	}
	original := false
	if present {
		if _, err := derived.OriginalLaunch(); err == nil {
			original = true
			anchor := derived.Template().OriginAnchor()
			manifest := derived.Manifest()
			if anchor.Digest() != initial.AnchorSHA256 || derived.Digest() != initial.ManifestSHA256 ||
				!bytes.Equal(local.baked.AnchorWire, baked.AnchorWire) ||
				manifest.DeploymentID != accepted.DeploymentID || manifest.ClusterID != accepted.ClusterID ||
				manifest.Environment != accepted.Environment || string(manifest.Cell) != accepted.Cell ||
				manifest.Slot != initial.Slot || manifest.SeedSlot != initial.SeedSlot || manifest.ImageOCID != initial.ImageOCID {
				return membershipLedger{}, errors.New("original membership authority differs from accepted regional formation and HOME origin")
			}
		}
	}
	var anchor bootstrap.HistoricalBootstrapAnchor
	if !original {
		anchorEnvelope, err := trust.DecodeEnvelope(baked.AnchorWire)
		if err != nil {
			return membershipLedger{}, err
		}
		anchor, err = bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, baked.Roots,
			baked.Identity.AnchorExpectation(), initial.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
		if err != nil || anchor.Digest() != initial.AnchorSHA256 {
			return membershipLedger{}, errors.New("current formation anchor differs from root-owned history")
		}
	}
	if present {
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
