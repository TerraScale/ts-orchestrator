package fixturegen

import (
	"context"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// SeedHistory and ManagedHistory contain public signed wire produced by the
// source signing APIs. The builder never writes raw Object Storage keys: it
// uses Ledger methods, allowing the capture client to learn their exact names.
type SeedHistory struct {
	Scope             bootstrap.BootstrapScope
	IntentWire        []byte
	ReservedHeadWire  []byte
	ManifestWire      []byte
	ReceiptWire       []byte
	Facts             bootstrap.InstanceFacts
	ResultWire        []byte
	CompletedHeadWire []byte
}

type ManagedHistory struct {
	Scope             bootstrap.BootstrapScope
	IntentWire        []byte
	ReservedHeadWire  []byte
	CandidateWire     []byte
	SignProgress      bootstrap.ManagedPeerProgressSigner
	Refresh           bootstrap.ManagedPeerRecoveryRefresh
	ManifestWire      []byte
	ReceiptWire       []byte
	Facts             bootstrap.InstanceFacts
	ResultWire        []byte
	CompletedHeadWire []byte
}

type CompletedHistories struct {
	Seed  bootstrap.SlotState
	Peers map[string]bootstrap.SlotState
}

// BuildCompletedHistories records all three slots through the real public
// Ledger lifecycle, then reopens each slot through the production verifier.
// A seed-only history or an uncommitted managed result is rejected.
func BuildCompletedHistories(ctx context.Context, ledger *bootstrap.Ledger,
	seed SeedHistory, peers []ManagedHistory,
) (CompletedHistories, error) {
	if ledger == nil || seed.Scope.Slot == "" || len(peers) != 2 ||
		peers[0].Scope.Slot == "" || peers[1].Scope.Slot == "" ||
		peers[0].Scope.Slot == peers[1].Scope.Slot ||
		peers[0].Scope.Slot == seed.Scope.Slot || peers[1].Scope.Slot == seed.Scope.Slot {
		return CompletedHistories{}, errors.New("restart fixture needs one seed and two distinct managed slots")
	}
	if _, err := ledger.ReserveSlot(ctx, seed.Scope, seed.IntentWire, seed.ReservedHeadWire); err != nil {
		return CompletedHistories{}, fmt.Errorf("reserve seed slot: %w", err)
	}
	for _, peer := range peers {
		if _, err := ledger.ReserveSlot(ctx, peer.Scope, peer.IntentWire, peer.ReservedHeadWire); err != nil {
			return CompletedHistories{}, fmt.Errorf("reserve managed slot %s: %w", peer.Scope.Slot, err)
		}
	}
	if _, err := ledger.RecordExternalSeed(ctx, seed.Scope, seed.ManifestWire, seed.ReceiptWire,
		seed.Facts, seed.ResultWire, seed.CompletedHeadWire); err != nil {
		return CompletedHistories{}, fmt.Errorf("complete seed slot: %w", err)
	}
	for _, peer := range peers {
		if err := ledger.RecordManagedPeerCandidate(ctx, peer.Scope, peer.CandidateWire,
			peer.SignProgress, peer.Refresh); err != nil {
			return CompletedHistories{}, fmt.Errorf("pin managed candidate %s: %w", peer.Scope.Slot, err)
		}
		if _, err := ledger.RecordManagedPeer(ctx, peer.Scope, peer.ManifestWire, peer.ReceiptWire,
			peer.Facts, peer.ResultWire, peer.CompletedHeadWire, peer.SignProgress, peer.Refresh); err != nil {
			return CompletedHistories{}, fmt.Errorf("complete managed slot %s: %w", peer.Scope.Slot, err)
		}
	}
	seedState, err := ledger.ReadSlot(ctx, seed.Scope)
	if err != nil || seedState.Result == nil || seedState.Intent.Mode != bootstrap.IntentModeExternalSeed ||
		seedState.Head.ResultDigest == "" || seedState.SeedReceiptRecord == nil {
		return CompletedHistories{}, fmt.Errorf("seed history failed verified replay: %w", err)
	}
	completed := CompletedHistories{Seed: seedState, Peers: make(map[string]bootstrap.SlotState, 2)}
	for _, peer := range peers {
		state, err := ledger.ReadSlot(ctx, peer.Scope)
		if err != nil || state.Result == nil || state.Intent.Mode != bootstrap.IntentModeManaged ||
			state.Head.ResultDigest == "" || state.CandidateRecord == nil || state.PeerReceiptRecord == nil {
			return CompletedHistories{}, fmt.Errorf("managed slot %s failed verified replay: %w", peer.Scope.Slot, err)
		}
		completed.Peers[peer.Scope.Slot] = state
	}
	return completed, nil
}
