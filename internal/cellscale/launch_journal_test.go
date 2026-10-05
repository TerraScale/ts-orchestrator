package cellscale

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func provisionTestJournal(t *testing.T) (FileConfig, string, string) {
	t.Helper()
	config := FileConfig{Cell: "gru-1", Template: testTemplate()}
	parent := t.TempDir()
	directory := filepath.Join(parent, cellStateName(config))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(initialLaunchJournal(config))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, launchJournalName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return config, parent, path
}

func testLaunchJournal(t *testing.T, config FileConfig, parent string) (*launchJournal, []OCILaunchState) {
	t.Helper()
	uid := uint32(os.Geteuid())
	j, states, err := openLaunchJournalAt(config, parent, uid, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.directory.Close() })
	return j, states
}

func TestRunLaunchStateReconciliationPersistence(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		name := "live"
		if dryRun {
			name = "dry run"
		}
		t.Run(name, func(t *testing.T) {
			config, parent, path := provisionTestJournal(t)
			config.Policy = testPolicy()
			config.Policy.DryRun = dryRun
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{}}
			cloud := newTestCloud(t, fake)
			cloud.requireLaunchPersistence = true
			intent := OCILaunchState{Name: "gru-1-db-1", Template: config.Template, Shape: small,
				RetryToken: "accepted-token", StartedAt: time.Now().UTC().Add(-time.Minute)}
			intent.Request = cloud.launchDetails(intent.Name, intent.Shape, intent.Template, intent.RetryToken)
			terminatedIntent := intent
			terminatedIntent.Name, terminatedIntent.RetryToken = "gru-1-db-2", "terminated-token"
			terminatedIntent.Request = cloud.launchDetails(terminatedIntent.Name, terminatedIntent.Shape, terminatedIntent.Template, terminatedIntent.RetryToken)
			manifest := initialLaunchJournal(config)
			manifest.Launches = []OCILaunchState{intent, terminatedIntent, {Name: "gru-1-db-3", InstanceID: "terminated-id"}}
			beforeBytes, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, beforeBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			journal, states := testLaunchJournal(t, config, parent)
			saves := 0
			if err := restoreRunLaunchState(cloud, states, func(snapshot []OCILaunchState) error {
				saves++
				return journal.save(snapshot)
			}, config.Policy.DryRun); err != nil {
				t.Fatal(err)
			}
			if cloud.saveLaunches == nil || len(cloud.launches) != len(states) {
				t.Fatal("run did not configure persistence and restore every intent")
			}
			accepted := instanceItem("accepted-id", intent.Name, config.Cell, roleDB, core.InstanceLifecycleStateProvisioning, 2, 12)
			accepted.FreeformTags[tagLaunchToken] = "different-generation"
			byToken := instanceItem("lost-response-id", terminatedIntent.Name, config.Cell, roleDB, core.InstanceLifecycleStateTerminated, 2, 12)
			byToken.FreeformTags[tagLaunchToken] = terminatedIntent.RetryToken
			byID := instanceItem("terminated-id", "gru-1-db-3", config.Cell, roleDB, core.InstanceLifecycleStateTerminated, 2, 12)
			fake.pages[""] = core.ListInstancesResponse{Items: []core.Instance{accepted, byToken, byID}}
			members := newFakeCell(0, small, 0, 0)
			controller, err := New(Config{Cell: config.Cell, Policy: config.Policy, Cloud: cloud, Members: members, Source: members})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.observe(t.Context()); err == nil || !strings.Contains(err.Error(), "different generation") || saves != 0 || len(cloud.launches) != len(states) {
				t.Fatalf("restored intent did not fence another generation: err=%v saves=%d states=%+v", err, saves, cloud.launches)
			}
			accepted.FreeformTags[tagLaunchToken] = intent.RetryToken
			for range 2 {
				state, err := controller.observe(t.Context())
				if err != nil || len(state.Nodes) != 1 || state.Nodes[0].ID != "accepted-id" {
					t.Fatalf("accepted instance was not observed: state=%+v err=%v", state, err)
				}
			}
			intent.InstanceID = "accepted-id"
			want, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(cloud.launches[intent.Name])
			if err != nil || len(cloud.launches) != 1 || !bytes.Equal(got, want) {
				t.Fatalf("reconciliation lost frozen intent or terminal proof: states=%+v err=%v", cloud.launches, err)
			}
			afterBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if dryRun {
				if saves != 0 || !bytes.Equal(beforeBytes, afterBytes) || !os.SameFile(before, after) {
					t.Fatalf("dry run changed the launch journal: saves=%d same_bytes=%t same_inode=%t", saves, bytes.Equal(beforeBytes, afterBytes), os.SameFile(before, after))
				}
			} else {
				manifest.Launches = []OCILaunchState{intent}
				wantBytes, err := json.Marshal(manifest)
				if err != nil || saves != 1 || !bytes.Equal(wantBytes, afterBytes) || os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
					t.Fatalf("live reconciliation was not durably replaced: saves=%d journal=%s err=%v", saves, afterBytes, err)
				}
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 || entries[0].Name() != launchJournalName {
				t.Fatalf("reconciliation left temporary files: entries=%v err=%v", entries, err)
			}
			if len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 || len(members.callLog()) != 0 {
				t.Fatalf("observation caused effects: launches=%v updates=%v terminates=%v members=%v", fake.launches, fake.updates, fake.terminates, members.callLog())
			}
		})
	}
}

func TestRunLaunchStateDryRunRejectsInvalidJournal(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "invalid intent"} {
		t.Run(kind, func(t *testing.T) {
			config, parent, path := provisionTestJournal(t)
			config.Policy.DryRun = true
			fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
			cloud := newTestCloud(t, fake)
			cloud.requireLaunchPersistence = true
			var data []byte
			switch kind {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				data = []byte("{")
			case "invalid intent":
				manifest := initialLaunchJournal(config)
				manifest.Launches = []OCILaunchState{{Name: "gru-1-db-1", Template: config.Template, Shape: small,
					RetryToken: "original-token", StartedAt: time.Now().UTC().Add(-time.Minute)}}
				var err error
				data, err = json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
			}
			if data != nil {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			uid := uint32(os.Geteuid())
			journal, states, err := openLaunchJournalAt(config, parent, uid, uid)
			saves := 0
			if err == nil {
				defer journal.directory.Close()
				err = restoreRunLaunchState(cloud, states, func(snapshot []OCILaunchState) error {
					saves++
					return journal.save(snapshot)
				}, config.Policy.DryRun)
			}
			if err == nil || saves != 0 || cloud.saveLaunches != nil || len(cloud.launches) != 0 || len(fake.listCalls)+len(fake.launches)+len(fake.updates)+len(fake.terminates) != 0 {
				t.Fatalf("invalid journal reached execution: err=%v saves=%d states=%+v", err, saves, cloud.launches)
			}
			after, err := os.ReadFile(path)
			if kind == "missing" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dry run recreated missing journal: %v", err)
				}
			} else if err != nil || !bytes.Equal(data, after) {
				t.Fatalf("dry run changed invalid journal: data=%s err=%v", after, err)
			}
		})
	}
}

func TestLaunchJournalReplaysLostResponseAfterRestart(t *testing.T) {
	config, parent, path := provisionTestJournal(t)
	j, states := testLaunchJournal(t, config, parent)
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}, launchError: io.ErrUnexpectedEOF}
	cloud, err := newOCICloud(config.Cell, config.Template, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	cloud.requireLaunchPersistence = true
	if err := cloud.RestoreLaunchState(states, j.save); err != nil {
		t.Fatal(err)
	}
	if _, err := cloud.Launch(t.Context(), "gru-1-db-1", small); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	first := fake.launches[0]
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.directory.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, recovered := testLaunchJournal(t, config, parent)
	if len(recovered) != 1 || recovered[0].RetryToken != deref(first.OpcRetryToken) || recovered[0].InstanceID != "" {
		t.Fatalf("lost accepted intent: %+v", recovered)
	}
	restarted, err := newOCICloud(config.Cell, config.Template, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.requireLaunchPersistence = true
	if err := restarted.RestoreLaunchState(recovered, reopened.save); err != nil {
		t.Fatal(err)
	}
	fake.launchError = nil
	if _, err := restarted.Launch(t.Context(), "gru-1-db-1", small); err != nil {
		t.Fatal(err)
	}
	replay := fake.launches[1]
	firstJSON, _ := json.Marshal(first.LaunchInstanceDetails)
	replayJSON, _ := json.Marshal(replay.LaunchInstanceDetails)
	if deref(first.OpcRetryToken) != deref(replay.OpcRetryToken) || string(firstJSON) != string(replayJSON) {
		t.Fatal("restart changed token or exact frozen payload")
	}
	_, accepted := testLaunchJournal(t, config, parent)
	if len(accepted) != 1 || accepted[0].InstanceID == "" {
		t.Fatal("accepted OCI ID was not persisted")
	}
	after, err := os.Stat(path)
	if err != nil || after.Mode().Perm() != 0o600 || os.SameFile(before, after) {
		t.Fatalf("journal was not atomically replaced with private permissions: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != launchJournalName {
		t.Fatalf("save left temporary files: %v, %v", entries, err)
	}
}

func TestLaunchJournalRejectsMissingCorruptOrUnsafeState(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "corrupt", "trailing", "wrong cell", "wrong region", "missing launches", "null launches", "wrong schema", "unknown field", "symlink", "fifo", "hardlink", "public file", "public directory", "writable parent", "different runner", "different provisioner", "symlink directory"} {
		t.Run(kind, func(t *testing.T) {
			config, parent, path := provisionTestJournal(t)
			provisioner, runner := uint32(os.Geteuid()), uint32(os.Geteuid())
			manifest := initialLaunchJournal(config)
			switch kind {
			case "wrong cell":
				manifest.Cell = "gru-2"
			case "wrong region":
				manifest.Region = "us-ashburn-1"
			case "null launches":
				manifest.Launches = nil
			case "wrong schema":
				manifest.Schema = 2
			}
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "empty":
				data = nil
			case "corrupt":
				data = []byte("{")
			case "trailing":
				data = append(data, " {}"...)
			case "missing launches":
				data = []byte(`{"schema":1,"cell":"gru-1","region":"sa-saopaulo-1"}`)
			case "unknown field":
				data = []byte(strings.TrimSuffix(string(data), "}") + `,"ignored":true}`)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing", "symlink", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(filepath.Join(t.TempDir(), "target"), path)
				}
				if kind == "fifo" {
					err = syscall.Mkfifo(path, 0o600)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(t.TempDir(), "alias"))
			case "public file":
				err = os.Chmod(path, 0o644)
			case "public directory":
				err = os.Chmod(filepath.Dir(path), 0o755)
			case "writable parent":
				err = os.Chmod(parent, 0o777)
			case "different runner":
				runner++
			case "different provisioner":
				provisioner++
			case "symlink directory":
				old := filepath.Dir(path)
				err = os.Rename(old, old+"-original")
				if err == nil {
					err = os.Symlink(old+"-original", old)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			j, _, err := openLaunchJournalAt(config, parent, provisioner, runner)
			if j != nil {
				j.directory.Close()
			}
			if err == nil {
				t.Fatalf("accepted %s launch journal", kind)
			}
			if kind == "missing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recreated missing intent: %v", err)
				}
			}
		})
	}
}

func TestLaunchJournalSaveFailureBlocksLaunch(t *testing.T) {
	config, parent, path := provisionTestJournal(t)
	j, states := testLaunchJournal(t, config, parent)
	fake := &fakeCompute{pages: map[string]core.ListInstancesResponse{"": {}}}
	cloud, err := newOCICloud(config.Cell, config.Template, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cloud.RestoreLaunchState(states, j.save); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := cloud.Launch(t.Context(), "gru-1-db-1", small); !errors.Is(err, os.ErrNotExist) || len(fake.launches) != 0 {
		t.Fatalf("POST escaped lost journal: err=%v calls=%v", err, fake.launches)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("save recreated missing state: %v", err)
	}
}

func TestCheckPrintsLaunchProvisioning(t *testing.T) {
	config := FileConfig{Cell: "gru-1", IntervalSeconds: 60, Endpoint: "http://{node}:9440", Policy: testPolicy(), Template: testTemplate()}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cell.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Run(t.Context(), []string{"check", "--config", path}, &out); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Path    string                `json:"launch_journal"`
		Initial launchJournalManifest `json:"initial_launch_journal"`
	}
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Path != launchJournalPath(config) || !reflect.DeepEqual(report.Initial, initialLaunchJournal(config)) {
		t.Fatalf("incorrect journal provisioning output: %+v", report)
	}
}
