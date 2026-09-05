package vmqual

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCreatingVMRecoversValidatedRuntimeProcessBeforeStackObservation(t *testing.T) {
	for _, invalid := range []string{"", "missing-runtime", "missing-marker", "wrong-run", "wrong-ticks", "wrong-executable", "wrong-version", "stale-record", "stopped-record"} {
		t.Run(invalid, func(t *testing.T) {
			root := t.TempDir()
			created := time.Now().UTC().Add(-time.Second)
			journal := Journal{RunID: "11111111-1111-4111-8111-111111111111", CreatedAt: created}
			resource := JournalVM{ID: "gru-member-1", Region: "gru", RunID: journal.RunID, Phase: vmPhaseCreating, StateDir: root, JailRoot: root, RuntimePath: filepath.Join(root, "runtime.json"), SandboxOwnershipPath: filepath.Join(root, "ownership.json"), RunMarkerPath: filepath.Join(root, "vmqual-run.json"), SocketPath: filepath.Join(root, "api.sock"), LogPath: filepath.Join(root, "firecracker.log"), MetricsPath: filepath.Join(root, "firecracker.metrics")}
			executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "exe"))
			if err != nil {
				t.Fatal(err)
			}
			resource.FirecrackerPath = executable
			ticks, err := ProcStartTime(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", resource.SocketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			marker := vmRunOwnership{Version: runMarkerVersion, Marker: runOwnershipMarker, RunID: journal.RunID, ID: resource.ID, Region: resource.Region, StateDir: root, CreatedAt: created}
			if invalid == "wrong-run" {
				marker.RunID = "22222222-2222-4222-8222-222222222222"
			}
			if invalid != "missing-marker" {
				if err := writeExclusiveJSON(resource.RunMarkerPath, marker); err != nil {
					t.Fatal(err)
				}
			}
			ownership := sandboxOwnership{Marker: "terrascale-sandboxvm-v1", ID: resource.ID, Region: resource.Region, JailRoot: resource.JailRoot, SocketPath: resource.SocketPath, LogPath: resource.LogPath, MetricsPath: resource.MetricsPath, RuntimeState: resource.RuntimePath, CreatedAt: created}
			if err := writeExclusiveJSON(resource.SandboxOwnershipPath, ownership); err != nil {
				t.Fatal(err)
			}
			record := runtimeRecord{Version: 1, Marker: "terrascale-sandboxvm-v1", ID: resource.ID, State: "running", PID: os.Getpid(), ProcessStartTime: ticks, SocketPath: resource.SocketPath, LogPath: resource.LogPath, MetricsPath: resource.MetricsPath, ObservedAt: time.Now().UTC()}
			switch invalid {
			case "wrong-ticks":
				record.ProcessStartTime++
			case "wrong-executable":
				resource.FirecrackerPath = filepath.Join(root, "foreign")
			case "wrong-version":
				record.Version++
			case "stale-record":
				record.ObservedAt = created.Add(-time.Second)
			case "stopped-record":
				record.State = "stopped"
			}
			if invalid != "missing-runtime" {
				if err := writeExclusiveJSON(resource.RuntimePath, record); err != nil {
					t.Fatal(err)
				}
			}
			// Validation only: this test must never signal its own fixture process.
			err = validateExistingResource(journal, resource)
			if invalid == "" && err != nil {
				t.Fatalf("durable runtime identity rejected before Create returned: %v", err)
			}
			if invalid != "" && err == nil {
				t.Fatalf("invalid %s accepted", invalid)
			}
			if resource.Process != nil {
				t.Fatal("validation manufactured a stack process observation")
			}
		})
	}
}

func TestProcessIdentityMatchesExactInodeAcrossExecutablePaths(t *testing.T) {
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	// Place the alias on the executable filesystem so this exercises a hardlink
	// rather than assuming that the test temp directory uses the same device.
	root, err := os.MkdirTemp(filepath.Dir(executable), "process-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	alias := filepath.Join(root, "firecracker")
	if err := os.Link(executable, alias); err != nil {
		t.Fatal(err)
	}
	ticks, err := ProcStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	identity := VMProcessIdentity{PID: os.Getpid(), StartTimeTicks: ticks, Executable: alias}
	if matched, err := ProcessIdentityMatches(identity); err != nil || !matched {
		t.Fatalf("same executable inode rejected: %v", err)
	}
	identity.StartTimeTicks++
	if matched, err := ProcessIdentityMatches(identity); err != nil || matched {
		t.Fatalf("wrong process incarnation accepted: %v", err)
	}
	identity.StartTimeTicks = ticks
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("different executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, alias); err != nil {
		t.Fatal(err)
	}
	if matched, err := ProcessIdentityMatches(identity); err != nil || matched {
		t.Fatalf("replacement inode accepted: %v", err)
	}
}
