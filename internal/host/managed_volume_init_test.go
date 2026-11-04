//go:build linux

package host

import (
	"context"

	"slices"

	"testing"
	"time"
)

func TestManagedVolumeInitRejectsForeignFilesystem(t *testing.T) {
	pins := ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}
	foreign := volumeFilesystemProbe{FSUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", FSType: "ext4", Signatures: true}
	if action, err := volumeInitActionFor(foreign, pins, true, false); err == nil || action != volumeInitHold {
		t.Fatalf("foreign filesystem: action %v, error %v", action, err)
	}
}

func TestManagedVolumeInitEffectsFormatOnceAndAdoptWithoutFormatting(t *testing.T) {
	pins := ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}
	blank := volumeFilesystemProbe{BlankSample: true}
	formatted := volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, Signatures: true}
	var calls []string
	completedLayout := false
	effects := volumeInitEffects{
		Consume: func() error {
			calls = append(calls, "consume")
			return nil
		},
		Format: func(context.Context) error {
			calls = append(calls, "format")
			return nil
		},
		Probe: func(context.Context) (volumeFilesystemProbe, error) {
			calls = append(calls, "verify-format")
			return formatted, nil
		},
		Mount: func(_ context.Context, complete bool) error {
			calls = append(calls, "mount")
			completedLayout = complete
			return nil
		},
	}
	if err := executeVolumeInitAction(t.Context(), pins, blank, true, false, time.Now().Add(time.Minute), effects); err != nil {
		t.Fatalf("authorized blank volume did not initialize: %v", err)
	}
	if want := []string{"consume", "format", "verify-format", "mount"}; !slices.Equal(calls, want) {
		t.Fatalf("fresh initialization effects = %v, want %v", calls, want)
	}
	if !completedLayout {
		t.Fatal("fresh filesystem mount did not request exact initial layout completion")
	}

	// A retry after formatting must recognize the exact filesystem and mount it
	// without consuming another permit or invoking mkfs.
	calls = nil
	completedLayout = false
	if err := executeVolumeInitAction(t.Context(), pins, formatted, false, true, time.Now().Add(time.Minute), effects); err != nil {
		t.Fatalf("exact formatted volume was not adopted on retry: %v", err)
	}
	if want := []string{"mount"}; !slices.Equal(calls, want) {
		t.Fatalf("restart adoption effects = %v, want %v", calls, want)
	}
	if !completedLayout {
		t.Fatal("restart adoption did not request completion of a crash-interrupted initial layout")
	}
}
