package fixturegen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// HistoryPreparer signs source-defined public ledger inputs after the real
// Ledger has been constructed over the capturing ObjectStorageClient. Its
// managed refresh callbacks can then use that same Ledger for fresh reads.
type HistoryPreparer func(*bootstrap.Ledger) (SeedHistory, []ManagedHistory, error)

// MaterialPreparer derives guest files and the executable from the completed,
// verified ledger states. In particular, accepted-install markers must pin
// the records that were actually captured, not a separately predicted wire.
type MaterialPreparer func(context.Context, CompletedHistories) (map[string][]byte, error)

// EmitCompletedRestartPacket is the production-restart fixture path. It
// performs every durable transition through public Ledger methods, captures
// their exact OCI keys and wire bytes, binds controller instances to positive
// results, derives storage routes, and verifies the root-signed image receipt
// against the executable before publishing the packet.
func EmitCompletedRestartPacket(ctx context.Context, destination, sourceRoot string,
	manifest Manifest, prepareMaterial MaterialPreparer, anchor bootstrap.VerifiedBootstrapAnchor,
	capture *CapturingObjectStorage, prepare HistoryPreparer, packetRootKey ed25519.PrivateKey,
	roots trust.Keyring, expiresAt time.Time,
) (VerifiedPacket, CompletedHistories, error) {
	if !anchor.IsVerified() || capture == nil || prepare == nil || prepareMaterial == nil {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("complete packet requires verified anchor, history, and material preparers")
	}
	anchored := anchor.Anchor()
	if manifest.DeploymentID != anchored.DeploymentID || manifest.Cell != string(anchored.Cell) ||
		manifest.Environment != anchored.Environment || len(manifest.Controllers) != len(anchored.ControllerSlots) {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("packet identity differs from verified anchor")
	}
	for index, controller := range manifest.Controllers {
		if controller.Slot != anchored.ControllerSlots[index] {
			return VerifiedPacket{}, CompletedHistories{}, errors.New("packet controller slot differs from verified anchor")
		}
	}
	if err := VerifyCompletedSourcePins(sourceRoot, manifest.SourcePins); err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("completed recipe source binding: %w", err)
	}
	for _, route := range manifest.Routes {
		if route.Host != "iaas.sa-saopaulo-1.oraclecloud.com" {
			return VerifiedPacket{}, CompletedHistories{}, errors.New("prepared route inventory may contain only Compute reads")
		}
	}
	capture.mu.Lock()
	captureNow := capture.now
	captureStarted := capture.puts != 0 || len(capture.objects) != 0 || len(capture.misses) != 0
	capture.mu.Unlock()
	if captureStarted || !captureNow.Equal(manifest.FixtureNow.Truncate(time.Second)) {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("completed recipe requires an empty capture at the fixture clock")
	}
	grant, err := anchor.LedgerDelegation()
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	domain := anchor.StorageDomain()
	config := bootstrap.LedgerConfig{
		DeploymentID: anchored.DeploymentID, Cell: anchored.Cell, ClusterID: anchored.ClusterID,
		InitialRegionIntentGeneration: anchored.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchored.InitialRegionIntentSHA256,
		Namespace:                     domain.Namespace, Bucket: domain.LedgerBucket, KMSKeyID: domain.LedgerKMSKeyOCID,
		Prefix: domain.Prefix, HeadBucket: domain.HeadBucket, HeadKMSKeyID: domain.HeadKMSKeyOCID,
		Environment: anchored.Environment, ControllerSlots: slices.Clone(anchored.ControllerSlots),
		AnchorExpiresAt: anchor.ExpiresAt(), TrustRoots: roots, Delegations: []trust.VerifiedDelegation{grant},
		TrustPolicy: bootstrap.BootstrapAnchorTrustPolicy(), VerificationNow: func() time.Time { return captureNow },
	}
	ledger, err := bootstrap.NewLedger(capture, config)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("open capture-backed public ledger: %w", err)
	}
	seed, peers, err := prepare(ledger)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("prepare signed histories: %w", err)
	}
	if seed.Scope.Slot != "seed-a" || len(peers) != 2 ||
		!slices.ContainsFunc(peers, func(peer ManagedHistory) bool { return peer.Scope.Slot == "controller-a" }) ||
		!slices.ContainsFunc(peers, func(peer ManagedHistory) bool { return peer.Scope.Slot == "controller-b" }) {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("completed packet requires seed-a external seed and both controller slots as managed peers")
	}
	completed, err := BuildCompletedHistories(ctx, ledger, seed, peers)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	historical, err := bootstrap.NewHistoricalLedger(capture, config)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("open production-style historical reader: %w", err)
	}
	for _, peer := range peers {
		state, err := historical.ReadSlot(ctx, peer.Scope)
		if err != nil || state.Result == nil || state.ResultRecord == nil || state.PeerReceiptRecord == nil ||
			state.Head.ResultDigest == "" || state.Head.ResultDigest != state.ResultRecord.SHA256 ||
			state.Intent.Mode != bootstrap.IntentModeManaged || state.Result.Mode != bootstrap.IntentModeManaged ||
			state.Head.Attempt != state.Intent.Attempt || state.Head.Attempt != state.Result.Attempt ||
			state.Intent.Slot != peer.Scope.Slot || state.Result.Slot != peer.Scope.Slot ||
			state.Intent.DeploymentID != peer.Scope.DeploymentID || state.Result.DeploymentID != peer.Scope.DeploymentID ||
			state.Intent.Cell != peer.Scope.Cell || state.Result.Cell != peer.Scope.Cell {
			return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("historical founder peer %q is not completed: %w", peer.Scope.Slot, err)
		}
	}
	if completed.Seed.Manifest == nil || completed.Seed.Result == nil {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("verified seed history lacks image or instance identity")
	}
	imageOCID := completed.Seed.Manifest.ImageOCID
	for _, controller := range manifest.Controllers {
		state := completed.Seed
		if controller.Slot != seed.Scope.Slot {
			var exists bool
			state, exists = completed.Peers[controller.Slot]
			if !exists {
				return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("controller %q has no completed history", controller.Slot)
			}
		}
		if state.Result == nil || state.Result.InstanceOCID != controller.InstanceOCID ||
			state.Manifest == nil || state.Manifest.ImageOCID != imageOCID ||
			!bytes.Equal(state.Manifest.ReleaseImageReceiptWire, completed.Seed.Manifest.ReleaseImageReceiptWire) ||
			!bytes.Equal(state.Manifest.ReleaseDelegationWire, completed.Seed.Manifest.ReleaseDelegationWire) {
			return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("controller %q has different positive OCI or image identity", controller.Slot)
		}
	}
	putsBeforeMaterial := capture.PutCount()
	prepared, err := prepareMaterial(ctx, completed)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("prepare verified guest material: %w", err)
	}
	if capture.PutCount() != putsBeforeMaterial {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("guest material preparation wrote to the ledger capture")
	}
	if _, err := parseGuestDirectories(prepared[guestDirectoryPlanPath], manifest.Controllers,
		func(path string) bool { _, ok := prepared[path]; return ok }); err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("completed packet guest directory contract: %w", err)
	}
	inventory, err := BuildCapturedInventory(anchor, manifest.Controllers, capture)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	material := make(map[string][]byte, len(prepared)+len(inventory.Bodies)+2)
	for name, body := range prepared {
		material[name] = bytes.Clone(body)
	}
	for name, body := range inventory.Bodies {
		if old, exists := material[name]; exists && !bytes.Equal(old, body) {
			return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("captured Object Storage body conflicts with prepared material %q", name)
		}
		material[name] = bytes.Clone(body)
	}
	for name, body := range map[string][]byte{
		"simulator/release-image-receipt.json": completed.Seed.Manifest.ReleaseImageReceiptWire,
		"simulator/release-delegation.json":    completed.Seed.Manifest.ReleaseDelegationWire,
	} {
		if old, exists := material[name]; exists && !bytes.Equal(old, body) {
			return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("signed release proof conflicts with prepared material %q", name)
		}
		material[name] = bytes.Clone(body)
	}
	manifest.Routes = append(slices.Clone(manifest.Routes), inventory.Routes...)
	slices.SortFunc(manifest.Routes, func(a, b Route) int {
		return strings.Compare(a.ControllerSlot+"\n"+a.InstanceOCID+"\n"+a.Host+"\n"+a.RequestURI,
			b.ControllerSlot+"\n"+b.InstanceOCID+"\n"+b.Host+"\n"+b.RequestURI)
	})
	for name := range material {
		if !strings.HasPrefix(name, "simulator/responses/") {
			continue
		}
		if !slices.ContainsFunc(manifest.Routes, func(route Route) bool { return route.BodyPath == name }) {
			return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("unreferenced simulator response %q", name)
		}
	}
	if _, err := os.Lstat(destination); err == nil || !errors.Is(err, os.ErrNotExist) {
		return VerifiedPacket{}, CompletedHistories{}, errors.New("completed packet destination must not exist")
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	stagingRoot, err := os.MkdirTemp(parent, ".completed-packet-")
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	defer os.RemoveAll(stagingRoot)
	staging := filepath.Join(stagingRoot, "packet")
	packet, err := EmitPacket(staging, sourceRoot, manifest, material, packetRootKey, roots, expiresAt)
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	if _, err := VerifyPacketEmbeddedImage(packet, roots, imageOCID, time.Now().UTC()); err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("completed packet image binding: %w", err)
	}
	if err := packet.ValidateProductionGuests(time.Now().UTC()); err != nil {
		return VerifiedPacket{}, CompletedHistories{}, fmt.Errorf("completed packet production guest boundary: %w", err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	packet, err = ValidatePacket(destination, roots, time.Now().UTC())
	if err != nil {
		return VerifiedPacket{}, CompletedHistories{}, err
	}
	return packet, completed, nil
}
