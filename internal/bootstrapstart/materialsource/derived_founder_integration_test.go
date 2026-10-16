//go:build fixturetest

package materialsource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"maps"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Called by the real HTTP/Vault/filesystem source-publication scenario after
// all three source-key-signed startup proofs have been committed atomically.
func assertDerivedFounderAuthority(t *testing.T, source *ColdStartMaterial, seed bootstrap.DerivedStartupAuthority, roots trust.Keyring, now time.Time) {
	t.Helper()
	plan, err := bootstrap.NewDerivedFounderPlan(t.Context(), seed, now)
	if err != nil || !plan.IsVerified() {
		t.Fatalf("derive genuine founder plan: %v", err)
	}
	if plan.SelectionGeneration() != source.grant.Generation() || plan.SelectionDigest() != plan.Digest() || plan.SeedAuthority().Digest() != seed.Digest() {
		t.Fatal("founder selection lost original grant or seed identity")
	}
	value := plan.Plan()
	startup, err := source.grant.Startup()
	if err != nil {
		t.Fatal(err)
	}
	resources := startup.FounderResources
	if resources == nil || !value.LaunchDeadline.Equal(resources.LaunchDeadline) || len(value.Peers) != 2 || value.SeedManifestSHA256 != seed.Digest() {
		t.Fatal("founder plan lost finite signed resource or seed pins")
	}
	for _, slot := range value.ControllerSlots {
		authority, ok := plan.Authority(slot)
		if !ok || !bytes.Equal(authority.Wire(), source.state.Startup[slot]) || authority.VerifyCurrent(t.Context(), now) != nil {
			t.Fatalf("founder slot %s lost exact source proof", slot)
		}
		if slot == value.SeedSlot {
			if _, err := plan.InitialManagedPeerIntent(slot, now); err == nil {
				t.Fatal("founder seed became a managed peer")
			}
			continue
		}
		intent, err := plan.InitialManagedPeerIntent(slot, now)
		if err != nil || intent.ManifestDigest != authority.Digest() || intent.FounderPlanSHA256 != plan.Digest() || intent.Attempt != 1 || intent.Generation != 1 {
			t.Fatalf("founder intent source binding for %s: %v", slot, err)
		}
		rowIndex := 0
		if value.Peers[0].Slot != slot {
			rowIndex = 1
		}
		row := value.Peers[rowIndex]
		var resource bootstrap.StartupSlotResources
		for _, candidate := range resources.Slots {
			if candidate.Slot == slot {
				resource = candidate
			}
		}
		if row.WholeOCPUs != resource.WholeOCPUs || row.MemoryInGB != resource.MemoryInGB || row.BootVolumeGB != resource.BootVolumeGB || row.BootVolumeTier != resource.BootVolumeTier || row.ImageCompartmentOCID != resource.ImageCompartmentOCID {
			t.Fatalf("founder row %s changed signed resources", slot)
		}
	}
	value.Peers[0].PrivateIP = "10.255.255.254"
	if plan.Plan().Peers[0].PrivateIP == value.Peers[0].PrivateIP {
		t.Fatal("rendered founder plan exposed mutable authority")
	}
	if err := plan.VerifyFounderPlanCurrent(t.Context(), roots, now, bootstrap.ManifestTrustPolicy()); err != nil {
		t.Fatalf("recheck original anchor/grant/source: %v", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	if plan.VerifyFounderPlanCurrent(t.Context(), wrongRoots, now, bootstrap.ManifestTrustPolicy()) == nil {
		t.Fatal("founder current check ignored caller's trusted roots")
	}
	deadline := plan.Plan().LaunchDeadline
	if plan.VerifyFounderPlanCurrent(t.Context(), roots, deadline, bootstrap.ManifestTrustPolicy()) == nil {
		t.Fatal("founder launch authority survived its deadline")
	}
	continued, err := plan.ForCompletedPeerContinuation(t.Context(), deadline.Add(time.Second))
	if err != nil || !continued.IsVerified() || continued.Digest() != plan.Digest() {
		t.Fatalf("current completed-peer continuation after launch deadline: %v", err)
	}
	if !continued.StoredCompletionBeforeLaunchDeadline(deadline.Add(-time.Second), deadline.Add(-time.Second)) || continued.StoredCompletionBeforeLaunchDeadline(deadline, deadline.Add(-time.Second)) {
		t.Fatal("completed continuation ignored whole-second completion boundary")
	}
	if _, err := bootstrap.NewDerivedFounderPlan(t.Context(), bootstrap.DerivedStartupAuthority{}, now); err == nil {
		t.Fatal("empty derived seal minted a founder plan")
	}

	original, etag, err := source.read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.Startup = maps.Clone(original.Startup)
	delete(changed.Startup, plan.Plan().Peers[0].Slot)
	changedETag, err := source.write(t.Context(), changed, etag)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the actual durable fixture before any fatal assertion can stop
	// its remaining home/spoke/recovery scenarios.
	denied := plan.VerifyFounderPlanCurrent(t.Context(), roots, now, bootstrap.ManifestTrustPolicy()) != nil
	_, constructorErr := bootstrap.NewDerivedFounderPlan(t.Context(), seed, now)
	_, continuationErr := plan.ForCompletedPeerContinuation(t.Context(), now)
	restoredETag, restoreErr := source.write(t.Context(), original, changedETag)
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	source.state, source.etag = original, restoredETag
	if !denied || constructorErr == nil || continuationErr == nil {
		t.Fatal("missing sibling source proof retained founder or continuation authority")
	}
	restored, err := bootstrap.NewDerivedFounderPlan(t.Context(), seed, now)
	if err != nil || restored.Digest() != plan.Digest() {
		t.Fatalf("restored source changed immutable founder identity: %v", err)
	}
}
