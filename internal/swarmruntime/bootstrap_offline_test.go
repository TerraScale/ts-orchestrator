package swarmruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/agent"
	"github.com/moby/swarmkit/v2/api"
	bolt "go.etcd.io/bbolt"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

// offlineWorkerRoot writes a stopped worker's mounted root: hostname and an old
// agent database holding one assigned regional TerraBase task.
func offlineWorkerRoot(t *testing.T) (string, ColdBootstrap) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hostname"), []byte("ts-fra-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := serviceIntent().serviceSpec()
	if err != nil {
		t.Fatal(err)
	}
	container := serviceIntent().Container.Copy()
	container.Env = []string{"TS_REGION=fra"}
	if spec.Task.Runtime, err = ContainerRuntime(container); err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: "oldownertask", ServiceID: "terrabaseservice", NodeID: "fra2node", Spec: spec.Task,
		ServiceAnnotations: api.Annotations{Labels: map[string]string{LabelServiceSpec: "terrabase"}}, DesiredState: api.TaskStateRunning}
	database := filepath.Join(root, "var/lib/ts-orch", offlineAgentDB)
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(database, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.InitDB(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		history := task.Copy()
		history.ID, history.DesiredState = "shutdownhistory", api.TaskStateShutdown
		return errorsJoin(agent.PutTask(tx, task), agent.SetTaskAssignment(tx, task.ID, true),
			agent.PutTask(tx, history), agent.SetTaskAssignment(tx, history.ID, true))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	job := rolloutmaintenance.Job{ID: "zdt-fra-2", Member: "ts-fra-2", Owner: "ts-fra-2", Epoch: 7, Phase: "held", Process: OfflineExitProcess,
		Source: rolloutmaintenance.Pin{Node: task.NodeID, Service: task.ServiceID, Task: task.ID, Fingerprint: taskFingerprint(task), Image: container.Image},
		Target: rolloutmaintenance.Pin{Node: task.NodeID, Service: task.ServiceID, Image: "example.invalid/fixture@sha256:" + strings.Repeat("b", 64)}}
	return root, ColdBootstrap{Local: job, Owner: job}
}

func errorsJoin(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func TestOfflineArmFencesTheMountedWorkerAndRemovesAgentRestart(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	root, input := offlineWorkerRoot(t)
	pin, err := OfflinePins(root, "/var/lib/ts-orch")
	if err != nil || pin != input.Local.Source {
		t.Fatal("offline pins differ from the agent task", pin, err)
	}
	if err := armOffline(ctx, root, "/var/lib/ts-orch", input); err != nil {
		t.Fatal(err)
	}
	if err := armOffline(ctx, root, "/var/lib/ts-orch", input); err != nil {
		t.Fatal("exact interrupted offline arm must resume", err)
	}
	store, err := rolloutmaintenance.Open(filepath.Join(root, "var/lib/ts-orch"))
	if err != nil {
		t.Fatal(err)
	}
	if job, err := store.Status(ctx); err != nil || job == nil || *job != input.Local {
		t.Fatal("worker executor fence not retained", job, err)
	}
	if owner, err := store.Ingress(ctx); err != nil || owner == nil || *owner != input.Owner {
		t.Fatal("owner ingress hold not retained", owner, err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/ts-orch", offlineAgentDB)); !os.IsNotExist(err) {
		t.Fatal("old agent database can still restart assigned tasks at boot", err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/ts-orch/zdt-retained/tasks.db.zdt-fra-2")); err != nil {
		t.Fatal("old agent database was not retained", err)
	}
	// The fenced staging apply hands both regional slots their candidate at once.
	staged := ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 2, Region: "fra", Node: "ts-fra-1"}
	if normal := swarmForTest(t, staged); normal.Update.Parallelism != 1 {
		t.Fatal("ordinary TerraBase rollout must stay one slot at a time")
	}
	staged.BootstrapStage = true
	if swarm := swarmForTest(t, staged); swarm.Update.Parallelism != 0 || swarm.Update.Order != api.UpdateConfig_STOP_FIRST {
		t.Fatal("bootstrap staging can wait on a fenced follower slot forever")
	}
}

func TestOfflineArmRefusesForeignPinsHostsAndLiveIdentity(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for name, corrupt := range map[string]func(*ColdBootstrap){
		"invented source pin": func(p *ColdBootstrap) { p.Local.Source.Task = "inventedtask"; p.Owner = p.Local },
		"another host":        func(p *ColdBootstrap) { p.Local.Member = "ts-fra-1" },
		"live process": func(p *ColdBootstrap) {
			p.Local.Process = rolloutmaintenance.Process{PID: 1, Start: 1}
			p.Owner = p.Local
		},
	} {
		root, input := offlineWorkerRoot(t)
		corrupt(&input)
		if err := armOffline(ctx, root, "/var/lib/ts-orch", input); err == nil {
			t.Fatal(name, "accepted")
		}
		if _, err := os.Stat(filepath.Join(root, "var/lib/ts-orch", offlineAgentDB)); err != nil {
			t.Fatal(name, "moved agent state after refusal", err)
		}
		if _, err := os.Stat(filepath.Join(root, "var/lib/ts-orch/terrabase-bootstrap/job.json")); !os.IsNotExist(err) {
			t.Fatal(name, "armed after refusal", err)
		}
	}
	if err := offlineMountedRoot("/"); err == nil {
		t.Fatal("live root accepted as an offline volume")
	}
	if err := offlineMountedRoot(t.TempDir()); err == nil {
		t.Fatal("unmounted directory accepted as an offline volume")
	}
}
