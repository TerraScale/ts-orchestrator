package region

import (
	"strings"
	"testing"
	"time"
)

func TestBootCleanupRetainsFirstWireAuthorityAndNeverRebindsPendingDeletion(t *testing.T) {
	child, _, updated := protectedChildFixture()
	child.InstanceTerminal = &PoolTerminalObservation{TerminalObservedAt: updated.Add(-time.Minute)}
	child.DrainAuthoritySHA256 = strings.Repeat("d", 64)
	child.DrainSource = &PoolDrainSourcePin{ReceiptSHA256: child.DrainAuthoritySHA256}
	pin := PoolBootCleanupAuthority{Lifecycle: PoolLifecycleBinding{
		InstallationID: "original-installation", Cell: "GRU", Role: "container", Architecture: "arm64", Shape: "original-shape",
		CompartmentID: "original-workload", BirthOperationID: child.OperationID, InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID,
		BootAttachmentID: child.BootAttachmentID, PoolID: child.PoolID, ConfigurationID: child.ConfigurationID, RecipeSHA256: child.RecipeSHA256,
		ProfileSHA256: strings.Repeat("a", 64), CurrentProfileSHA256: strings.Repeat("b", 64), PoolBirthSHA256: strings.Repeat("c", 64),
		ConfigurationSHA256: strings.Repeat("e", 64), BirthSHA256: strings.Repeat("f", 64), GrantSHA256: strings.Repeat("1", 64), Generation: 2},
		DrainSHA256: child.DrainAuthoritySHA256, AuthorizedAt: updated, ExpiresAt: updated.Add(time.Minute)}
	child.BootCleanupAuthority = &pin
	child.DeleteBoot = &PoolWireRecord{FirstAttemptAt: updated, ExpiresAt: pin.ExpiresAt}
	if err := pin.validate(child, updated); err != nil {
		t.Fatal(err)
	}
	previous := FoundationRecord{GrantSHA256: pin.Lifecycle.GrantSHA256, Generation: pin.Lifecycle.Generation,
		PoolChildren: map[string]PoolChildRecord{child.OperationID: child}}
	next := previous
	next.cloneCapacity()
	next.PoolChildren[child.OperationID].BootCleanupAuthority.ExpiresAt = updated.Add(2 * time.Minute)
	if !previous.PoolChildren[child.OperationID].BootCleanupAuthority.ExpiresAt.Equal(pin.ExpiresAt) {
		t.Fatal("snapshot shared original boot authority")
	}
	if next.retainCapacity(previous) == nil {
		t.Fatal("already reserved boot deletion acquired a new deadline")
	}
	next = previous
	next.cloneCapacity()
	next.PoolChildren[child.OperationID].BootCleanupAuthority.Lifecycle.GrantSHA256 = strings.Repeat("2", 64)
	if next.retainCapacity(previous) == nil {
		t.Fatal("already reserved boot deletion rebound to a successor grant")
	}
	old := child
	old.BootCleanupAuthority = nil
	previous.PoolChildren[child.OperationID] = old
	candidate := previous
	candidate.PoolChildren = map[string]PoolChildRecord{child.OperationID: child}
	if candidate.retainCapacity(previous) == nil {
		t.Fatal("legacy pending boot deletion acquired a new cleanup authority")
	}
	old.DeleteBoot = nil
	previous.PoolChildren[child.OperationID] = old
	if err := candidate.retainCapacity(previous); err != nil {
		t.Fatalf("never-reserved boot deletion could not retain its first current authority: %v", err)
	}
	candidate.GrantSHA256 = strings.Repeat("3", 64)
	if candidate.retainCapacity(previous) == nil {
		t.Fatal("new boot deletion pinned a grant other than the actual current protected grant")
	}
	candidate.GrantSHA256 = pin.Lifecycle.GrantSHA256
	old.InstanceTerminal = nil
	previous.PoolChildren[child.OperationID] = old
	if candidate.retainCapacity(previous) == nil {
		t.Fatal("new boot authority lacked already-retained positive original instance termination")
	}
}
