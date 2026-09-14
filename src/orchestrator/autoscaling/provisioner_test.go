package autoscaling

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeProcessSpawner is the deterministic ProcessSpawner of the tests: it
// records every spawned spec and termination, returns configured pids in
// order, and never touches a real process.
type fakeProcessSpawner struct {
	spawned      []NodeProcessSpec
	pids         []int
	spawnErr     error
	terminated   []int
	terminateErr error
}

type blockingRetireSpawner struct {
	started    chan struct{}
	release    chan struct{}
	spawnCalls int
}

type stuckTerminateSpawner struct {
	started chan struct{}
	release chan struct{}
	done    chan struct{}
}

func (s *stuckTerminateSpawner) Spawn(context.Context, NodeProcessSpec) (int, error) {
	return 4242, nil
}

func (s *stuckTerminateSpawner) Terminate(context.Context, int) error {
	close(s.started)
	<-s.release
	close(s.done)
	return errors.New("termination was released after shutdown deadline")
}

func (s *blockingRetireSpawner) Spawn(context.Context, NodeProcessSpec) (int, error) {
	s.spawnCalls++
	return 4242, nil
}

func (s *blockingRetireSpawner) Terminate(context.Context, int) error {
	close(s.started)
	<-s.release
	return errors.New("termination stayed retryable")
}

func (s *fakeProcessSpawner) Spawn(ctx context.Context, spec NodeProcessSpec) (int, error) {
	s.spawned = append(s.spawned, spec)
	if s.spawnErr != nil {
		return 0, s.spawnErr
	}
	if len(s.pids) > 0 {
		pid := s.pids[0]
		s.pids = s.pids[1:]
		return pid, nil
	}
	return 4242, nil
}

func (s *fakeProcessSpawner) Terminate(ctx context.Context, pid int) error {
	s.terminated = append(s.terminated, pid)
	return s.terminateErr
}

// isInvalidOperation reports whether err is this package's typed invalid
// operation.
func isInvalidOperation(err error) bool {
	var operationError *InvalidOperationError
	return errors.As(err, &operationError)
}

// isInvalidData reports whether err is this package's typed invalid data.
func isInvalidData(err error) bool {
	var dataError *InvalidDataError
	return errors.As(err, &dataError)
}

func validNodeProcessSpec(t *testing.T) NodeProcessSpec {
	t.Helper()
	spec, err := NewNodeProcessSpec(
		"/opt/terrascale/bin/ts-node",
		"gru-node-9",
		"nats://127.0.0.1:4222",
		[]string{"--region", "gru", "--node-class", "worker-medium"},
		map[string]string{"TS_REGION": "gru"},
		1000)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	return spec
}

func TestNewNodeProcessSpec(t *testing.T) {
	tests := []struct {
		name        string
		binaryPath  string
		nodeId      string
		natsUrl     string
		args        []string
		env         map[string]string
		runAsUid    uint32
		expectParam string
	}{
		{
			name:       "valid spec",
			binaryPath: "/opt/terrascale/bin/ts-node",
			nodeId:     "gru-node-9",
			natsUrl:    "nats://127.0.0.1:4222",
			args:       []string{"--region", "gru"},
			env:        map[string]string{"TS_REGION": "gru"},
			runAsUid:   1000,
		},
		{
			name:        "relative binary path",
			binaryPath:  "bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			runAsUid:    1000,
			expectParam: "binaryPath",
		},
		{
			name:        "dot segment binary path",
			binaryPath:  "/opt/../bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			runAsUid:    1000,
			expectParam: "binaryPath",
		},
		{
			name:        "invalid node id",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru node 9",
			natsUrl:     "nats://127.0.0.1:4222",
			runAsUid:    1000,
			expectParam: "nodeId",
		},
		{
			name:        "root uid",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			runAsUid:    0,
			expectParam: "runAsUid",
		},
		{
			name:        "empty nats url",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "",
			runAsUid:    1000,
			expectParam: "natsUrl",
		},
		{
			name:        "flag-like nats url",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "-injected",
			runAsUid:    1000,
			expectParam: "natsUrl",
		},
		{
			name:        "nats url with whitespace",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222 x",
			runAsUid:    1000,
			expectParam: "natsUrl",
		},
		{
			name:        "reserved identity flag argument",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			args:        []string{"--node-id"},
			runAsUid:    1000,
			expectParam: "args",
		},
		{
			name:        "reserved node identity equals argument",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			args:        []string{"--node-id=attacker"},
			runAsUid:    1000,
			expectParam: "args",
		},
		{
			name:        "reserved nats identity equals argument",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			args:        []string{"--nats-url=nats://attacker"},
			runAsUid:    1000,
			expectParam: "args",
		},
		{
			name:        "argument with control characters",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			args:        []string{"--region\ngru"},
			runAsUid:    1000,
			expectParam: "args",
		},
		{
			name:        "lowercase environment key",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			env:         map[string]string{"ts_region": "gru"},
			runAsUid:    1000,
			expectParam: "env",
		},
		{
			name:        "reserved runtime directory key",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			env:         map[string]string{"XDG_RUNTIME_DIR": "/run/user/1"},
			runAsUid:    1000,
			expectParam: "env",
		},
		{
			name:        "environment value with control characters",
			binaryPath:  "/opt/terrascale/bin/ts-node",
			nodeId:      "gru-node-9",
			natsUrl:     "nats://127.0.0.1:4222",
			env:         map[string]string{"TS_REGION": "gru\n"},
			runAsUid:    1000,
			expectParam: "env",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, err := NewNodeProcessSpec(
				test.binaryPath, test.nodeId, test.natsUrl, test.args, test.env, test.runAsUid)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid spec")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("spec: %v", err)
			}
			if spec.XdgRuntimeDir() != "/run/user/1000" {
				t.Fatalf("xdg runtime dir = %q", spec.XdgRuntimeDir())
			}
		})
	}

	tooManyArguments := make([]string, autoscalingMaximumArgumentCount+1)
	if _, err := NewNodeProcessSpec("/opt/terrascale/bin/ts-node", "gru-node-9",
		"nats://127.0.0.1:4222", tooManyArguments, nil, 1000); !errorsAsParam(err, "args") {
		t.Fatalf("argument count must be bounded, got %v", err)
	}
	tooManyEntries := make(map[string]string, autoscalingMaximumEnvironmentCount+1)
	for index := 0; index < autoscalingMaximumEnvironmentCount+1; index++ {
		tooManyEntries[string(rune('A'+index%26))+string(rune('A'+index/26))] = "v"
	}
	if _, err := NewNodeProcessSpec("/opt/terrascale/bin/ts-node", "gru-node-9",
		"nats://127.0.0.1:4222", nil, tooManyEntries, 1000); !errorsAsParam(err, "env") {
		t.Fatalf("environment count must be bounded, got %v", err)
	}
}

func TestNodeProcessSpecComposesExplicitArgumentsAndEnvironment(t *testing.T) {
	spec := validNodeProcessSpec(t)

	arguments := spec.childArguments()
	expected := []string{
		"--region", "gru", "--node-class", "worker-medium",
		"--node-id", "gru-node-9", "--nats-url", "nats://127.0.0.1:4222",
	}
	if len(arguments) != len(expected) {
		t.Fatalf("arguments = %v", arguments)
	}
	for index := range expected {
		if arguments[index] != expected[index] {
			t.Fatalf("arguments = %v, want %v", arguments, expected)
		}
	}

	environment := spec.environment()
	expectedEnvironment := []string{
		"TS_REGION=gru",
		"XDG_RUNTIME_DIR=/run/user/1000",
	}
	if len(environment) != len(expectedEnvironment) {
		t.Fatalf("environment = %v", environment)
	}
	for index := range expectedEnvironment {
		if environment[index] != expectedEnvironment[index] {
			t.Fatalf("environment = %v, want %v", environment, expectedEnvironment)
		}
	}
}

func TestStaticNodeProvisionerRecordsAndRevalidates(t *testing.T) {
	provisioner := NewStaticNodeProvisioner()
	request := NodeProvisionRequest{
		NodeId:    "gru-node-9",
		NodeClass: "worker-medium",
		Resources: NodeResources{MemoryBytes: 1000, CpuPercent: 100, Tasks: 100},
		Reason:    "unschedulable terrabase demand",
	}
	if err := provisioner.Provision(context.Background(), request); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := provisioner.Provision(context.Background(), request); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(provisioner.Provisions) != 2 || len(provisioner.Retires) != 1 ||
		provisioner.Retires[0] != "gru-node-9" {
		t.Fatalf("records = %+v / %v", provisioner.Provisions, provisioner.Retires)
	}

	invalid := request
	invalid.NodeId = "gru node 9"
	if err := provisioner.Provision(context.Background(), invalid); !errorsAsParam(err, "nodeId") {
		t.Fatalf("an invalid request must be revalidated, got %v", err)
	}
	if err := provisioner.Retire(context.Background(), "gru node 9"); !errorsAsParam(err, "nodeId") {
		t.Fatalf("an invalid node id must be revalidated, got %v", err)
	}

	injected := errors.New("injected provision failure")
	provisioner.ProvisionError = injected
	if err := provisioner.Provision(context.Background(), request); err != injected {
		t.Fatalf("the injected failure must surface after validation, got %v", err)
	}
	// Validation runs first, so an invalid request still reports its own
	// typed error even with an injected failure pending.
	if err := provisioner.Provision(context.Background(), invalid); !errorsAsParam(err, "nodeId") {
		t.Fatalf("validation must precede the injected failure, got %v", err)
	}
	provisioner.RetireError = errors.New("injected retire failure")
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err == nil {
		t.Fatal("the injected retire failure must surface")
	}
	if err := provisioner.Provision(nil, request); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}
	if err := provisioner.Retire(nil, "gru-node-9"); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}
}

func validProvisionerConfig(t *testing.T) LocalProcessProvisionerConfig {
	t.Helper()
	config, err := NewLocalProcessProvisionerConfig(
		"/opt/terrascale/bin/ts-node",
		"nats://127.0.0.1:4222",
		[]string{"--region", "gru"},
		1000)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return config
}

func validProvisionRequest(t *testing.T) NodeProvisionRequest {
	t.Helper()
	request, err := NewNodeProvisionRequest(
		"gru-node-9",
		"worker-medium",
		NodeResources{MemoryBytes: 1000, CpuPercent: 100, Tasks: 100},
		"unschedulable terrabase demand")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return request
}

func TestNewLocalProcessProvisionerRequiresExplicitConfigAndSpawner(t *testing.T) {
	config := validProvisionerConfig(t)
	if _, err := NewLocalProcessNodeProvisioner(config, nil); !errorsAsParam(err, "spawner") {
		t.Fatalf("a nil spawner must be refused, got %v", err)
	}
	rootConfig := config
	rootConfig.RunAsUid = 0
	if _, err := NewLocalProcessNodeProvisioner(rootConfig, &fakeProcessSpawner{}); !errorsAsParam(err, "runAsUid") {
		t.Fatalf("a root configuration must be refused, got %v", err)
	}
	if _, err := NewLocalProcessProvisionerConfig(
		"/opt/terrascale/bin/ts-node", "nats://127.0.0.1:4222", nil, 0); !errorsAsParam(err, "runAsUid") {
		t.Fatalf("a root configuration must be refused, got %v", err)
	}
}

func TestLocalProcessNodeProvisionerSpawnsTheConfiguredAgent(t *testing.T) {
	spawner := &fakeProcessSpawner{pids: []int{4242}}
	provisioner, err := NewLocalProcessNodeProvisioner(validProvisionerConfig(t), spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(spawner.spawned) != 1 {
		t.Fatalf("spawn calls = %d", len(spawner.spawned))
	}
	spec := spawner.spawned[0]
	if spec.BinaryPath != "/opt/terrascale/bin/ts-node" || spec.NodeId != "gru-node-9" ||
		spec.NatsUrl != "nats://127.0.0.1:4222" || spec.RunAsUid != 1000 ||
		spec.XdgRuntimeDir() != "/run/user/1000" {
		t.Fatalf("spec = %+v", spec)
	}
	expectedArguments := []string{"--region", "gru", "--node-class", "worker-medium"}
	if len(spec.Args) != len(expectedArguments) {
		t.Fatalf("args = %v", spec.Args)
	}
	for index := range expectedArguments {
		if spec.Args[index] != expectedArguments[index] {
			t.Fatalf("args = %v, want %v", spec.Args, expectedArguments)
		}
	}

	// An invalid request never reaches the spawner.
	invalid := validProvisionRequest(t)
	invalid.NodeClass = "worker/medium"
	if err := provisioner.Provision(context.Background(), invalid); !errorsAsParam(err, "nodeClass") {
		t.Fatalf("an invalid request must be refused, got %v", err)
	}
	if len(spawner.spawned) != 1 {
		t.Fatalf("spawn calls = %d", len(spawner.spawned))
	}
	if err := provisioner.Provision(nil, validProvisionRequest(t)); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}
}

func TestLocalProcessNodeProvisionerResolvesNodeScopedArguments(t *testing.T) {
	spawner := &fakeProcessSpawner{pids: []int{4242}}
	config := validProvisionerConfig(t)
	config.AgentArgumentsForNode = func(nodeId string) ([]string, error) {
		return []string{"--nats-nkey-file", "/run/credentials/nodes/" + nodeId + ".seed"}, nil
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got := spawner.spawned[0].Args; len(got) < 2 || got[1] != "/run/credentials/nodes/gru-node-9.seed" {
		t.Fatalf("node-scoped arguments = %v", got)
	}
}

func TestLocalProcessNodeProvisionerCommitsNodeIdentityOnlyAfterSpawn(t *testing.T) {
	spawner := &fakeProcessSpawner{spawnErr: errors.New("spawn failed")}
	config := validProvisionerConfig(t)
	resolveCalls := 0
	commitCalls := 0
	rollbackCalls := 0
	releaseCalls := 0
	config.AgentArgumentsForNode = func(nodeId string) ([]string, error) {
		resolveCalls++
		return []string{"--credential-file", "/run/credentials/nodes/" + nodeId}, nil
	}
	config.AgentArgumentsForNodeCommit = func(string, []string) error {
		commitCalls++
		return nil
	}
	config.AgentArgumentsForNodeRollback = func(string, []string) {
		rollbackCalls++
	}
	config.AgentArgumentsForNodeRelease = func(string) {
		releaseCalls++
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	request := validProvisionRequest(t)

	if err := provisioner.Provision(context.Background(), request); err == nil {
		t.Fatal("the spawn failure must surface")
	}
	if resolveCalls != 1 || commitCalls != 0 || rollbackCalls != 1 {
		t.Fatalf("failed spawn callbacks = resolve %d, commit %d, rollback %d", resolveCalls, commitCalls, rollbackCalls)
	}

	spawner.spawnErr = nil
	if err := provisioner.Provision(context.Background(), request); err != nil {
		t.Fatalf("retry provision: %v", err)
	}
	if resolveCalls != 2 || commitCalls != 1 || rollbackCalls != 1 {
		t.Fatalf("successful spawn callbacks = resolve %d, commit %d, rollback %d", resolveCalls, commitCalls, rollbackCalls)
	}

	// The duplicate check runs before the resolver, so a second call cannot
	// trigger any identity side effect after the first child is live.
	if err := provisioner.Provision(context.Background(), request); !isInvalidOperation(err) {
		t.Fatalf("duplicate provision must be refused, got %v", err)
	}
	if resolveCalls != 2 || commitCalls != 1 || rollbackCalls != 1 || releaseCalls != 0 {
		t.Fatalf("duplicate callbacks = resolve %d, commit %d, rollback %d, release %d", resolveCalls, commitCalls, rollbackCalls, releaseCalls)
	}

	// A retryable termination failure retains the child and its identity. Once
	// termination succeeds, release makes the same identity available again.
	spawner.terminateErr = errors.New("termination failed")
	if err := provisioner.Retire(context.Background(), request.NodeId); err == nil {
		t.Fatal("termination failure must surface")
	}
	if releaseCalls != 0 {
		t.Fatalf("failed termination released %d identities", releaseCalls)
	}
	spawner.terminateErr = nil
	if err := provisioner.Retire(context.Background(), request.NodeId); err != nil {
		t.Fatalf("retire retry: %v", err)
	}
	if releaseCalls != 1 {
		t.Fatalf("successful termination releases = %d, want 1", releaseCalls)
	}
	if err := provisioner.Provision(context.Background(), request); err != nil {
		t.Fatalf("reprovision after release: %v", err)
	}
	if commitCalls != 2 {
		t.Fatalf("reprovision commits = %d, want 2", commitCalls)
	}
}

func TestLocalProcessNodeProvisionerCancellationDuringIdentityCommitCleansChild(t *testing.T) {
	spawner := &fakeProcessSpawner{pids: []int{4242}}
	config := validProvisionerConfig(t)
	config.AgentArgumentsForNode = func(nodeId string) ([]string, error) {
		return []string{"--credential-file", "/run/credentials/nodes/" + nodeId}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	config.AgentArgumentsForNodeCommit = func(string, []string) error {
		cancel()
		return nil
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Provision(ctx, validProvisionRequest(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during identity commit error = %v", err)
	}
	if len(spawner.terminated) != 1 || spawner.terminated[0] != 4242 {
		t.Fatalf("canceled commit terminations = %v", spawner.terminated)
	}
}

func TestLocalProcessNodeProvisionerSerializesConcurrentDuplicateResolution(t *testing.T) {
	spawner := &fakeProcessSpawner{}
	config := validProvisionerConfig(t)
	resolveCalls := 0
	commitCalls := 0
	config.AgentArgumentsForNode = func(string) ([]string, error) {
		resolveCalls++
		return []string{"--credential-file", "/run/credentials/nodes/node-seed"}, nil
	}
	config.AgentArgumentsForNodeCommit = func(string, []string) error {
		commitCalls++
		return nil
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	request := validProvisionRequest(t)
	results := make(chan error, 16)
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- provisioner.Provision(context.Background(), request)
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	duplicates := 0
	for result := range results {
		if result == nil {
			successes++
		} else if isInvalidOperation(result) {
			duplicates++
		} else {
			t.Fatalf("concurrent provision error = %v", result)
		}
	}
	if successes != 1 || duplicates != 15 || len(spawner.spawned) != 1 || resolveCalls != 1 || commitCalls != 1 {
		t.Fatalf("concurrent duplicate state: successes=%d duplicates=%d spawns=%d resolves=%d commits=%d", successes, duplicates, len(spawner.spawned), resolveCalls, commitCalls)
	}
}

func TestLocalProcessNodeProvisionerRollsBackResolverFailure(t *testing.T) {
	spawner := &fakeProcessSpawner{}
	config := validProvisionerConfig(t)
	rollbackCalls := 0
	config.AgentArgumentsForNode = func(string) ([]string, error) {
		return []string{"--credential-file", "/run/credentials/nodes/node-seed"}, errors.New("identity unavailable")
	}
	config.AgentArgumentsForNodeRollback = func(_ string, arguments []string) {
		rollbackCalls++
		if len(arguments) != 2 || arguments[1] != "/run/credentials/nodes/node-seed" {
			t.Errorf("rollback arguments = %v", arguments)
		}
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err == nil {
		t.Fatal("resolver failure must surface")
	}
	if rollbackCalls != 1 {
		t.Fatalf("resolver rollback calls = %d, want 1", rollbackCalls)
	}
	if len(spawner.spawned) != 0 {
		t.Fatalf("resolver failure spawned %d children", len(spawner.spawned))
	}
}

func TestLocalProcessNodeProvisionerRollsBackCommitFailureAndCleansChild(t *testing.T) {
	spawner := &fakeProcessSpawner{terminateErr: errors.New("cleanup failed")}
	config := validProvisionerConfig(t)
	rollbackCalls := 0
	config.AgentArgumentsForNode = func(string) ([]string, error) {
		return []string{"--credential-file", "/run/credentials/nodes/node-seed"}, nil
	}
	config.AgentArgumentsForNodeCommit = func(string, []string) error {
		return errors.New("identity already committed")
	}
	config.AgentArgumentsForNodeRollback = func(string, []string) {
		rollbackCalls++
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err == nil {
		t.Fatal("commit failure must surface")
	}
	if rollbackCalls != 0 {
		t.Fatalf("commit rollback calls = %d, want 0 while cleanup is unconfirmed", rollbackCalls)
	}
	if len(spawner.terminated) != 1 || spawner.terminated[0] != 4242 {
		t.Fatalf("commit failure terminations = %v, want [4242]", spawner.terminated)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); !isInvalidOperation(err) {
		t.Fatalf("an unconfirmed cleanup must retain ownership, got %v", err)
	}
	spawner.terminateErr = nil
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if rollbackCalls != 1 {
		t.Fatalf("commit rollback calls after confirmed cleanup = %d, want 1", rollbackCalls)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err == nil {
		t.Fatal("a commit callback that always fails should still fail reprovision")
	}
}

func TestLocalProcessNodeProvisionerShutdownReconcilesChildrenAndCloses(t *testing.T) {
	spawner := &fakeProcessSpawner{pids: []int{4242, 5151}}
	config := validProvisionerConfig(t)
	releases := 0
	config.AgentArgumentsForNode = func(nodeID string) ([]string, error) {
		return []string{"--credential-file", "/run/credentials/nodes/" + nodeID}, nil
	}
	config.AgentArgumentsForNodeCommit = func(string, []string) error { return nil }
	config.AgentArgumentsForNodeRelease = func(string) { releases++ }
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatal(err)
	}
	first := validProvisionRequest(t)
	second := first
	second.NodeId = "gru-node-8"
	if err := provisioner.Provision(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Provision(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provisioner.Shutdown(cancelled); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if len(spawner.terminated) != 2 || spawner.terminated[0] != 5151 || spawner.terminated[1] != 4242 {
		t.Fatalf("shutdown terminations = %v", spawner.terminated)
	}
	if releases != 2 {
		t.Fatalf("shutdown releases = %d, want 2", releases)
	}
	if err := provisioner.Shutdown(context.Background()); err != nil {
		t.Fatalf("idempotent shutdown: %v", err)
	}
	if len(spawner.terminated) != 2 {
		t.Fatalf("idempotent shutdown signaled children again: %v", spawner.terminated)
	}
	if err := provisioner.Provision(context.Background(), first); !isInvalidOperation(err) {
		t.Fatalf("provision after shutdown must fail closed, got %v", err)
	}
}

func TestLocalProcessNodeProvisionerShutdownBoundsUncooperativeSpawner(t *testing.T) {
	spawner := &stuckTerminateSpawner{started: make(chan struct{}), release: make(chan struct{})}
	spawner.done = make(chan struct{})
	defer func() {
		close(spawner.release)
		<-spawner.done
	}()
	provisioner, err := NewLocalProcessNodeProvisioner(validProvisionerConfig(t), spawner)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = provisioner.Shutdown(ctx)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("uncooperative shutdown result=%v duration=%s", err, time.Since(started))
	}
	select {
	case <-spawner.started:
	default:
		t.Fatal("shutdown did not attempt child termination")
	}
}

func TestLocalProcessNodeProvisionerRefusesDuplicatesAndSpawnFailures(t *testing.T) {
	spawner := &fakeProcessSpawner{spawnErr: errors.New("spawn failed")}
	provisioner, err := NewLocalProcessNodeProvisioner(validProvisionerConfig(t), spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	request := validProvisionRequest(t)
	if err := provisioner.Provision(context.Background(), request); err == nil {
		t.Fatal("the spawn failure must surface")
	}
	if err := provisioner.Retire(context.Background(), "gru-node-9"); !isInvalidOperation(err) {
		t.Fatalf("a failed spawn leaves no recorded child, got %v", err)
	}

	// The fake records attempted spawns, including the intentionally failed
	// attempt above. Start the duplicate-suppression assertion from a clean
	// successful-call baseline.
	spawner.spawned = nil
	spawner.spawnErr = nil
	spawner.pids = []int{4242}
	if err := provisioner.Provision(context.Background(), request); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := provisioner.Provision(context.Background(), request); !isInvalidOperation(err) {
		t.Fatalf("a duplicate provision must be refused, got %v", err)
	}
	// Only the successful provision reached the spawner after the baseline
	// reset; the duplicate never spawned a second child.
	if len(spawner.spawned) != 1 {
		t.Fatalf("a duplicate provision must not spawn, calls = %d", len(spawner.spawned))
	}
}

func TestLocalProcessNodeProvisionerRejectsInvalidPids(t *testing.T) {
	spawner := &fakeProcessSpawner{pids: []int{0}}
	config := validProvisionerConfig(t)
	rollbackCalls := 0
	config.AgentArgumentsForNode = func(string) ([]string, error) {
		return []string{"--credential-file", "/run/credentials/nodes/node-seed"}, nil
	}
	config.AgentArgumentsForNodeRollback = func(string, []string) {
		rollbackCalls++
	}
	provisioner, err := NewLocalProcessNodeProvisioner(config, spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); !isInvalidData(err) {
		t.Fatalf("a nonpositive pid is invalid data, got %v", err)
	}
	if rollbackCalls != 1 {
		t.Fatalf("invalid pid rollback calls = %d, want 1", rollbackCalls)
	}
	if err := provisioner.Retire(context.Background(), "gru-node-9"); !isInvalidOperation(err) {
		t.Fatalf("an unrecorded child must fail closed, got %v", err)
	}
}

func TestLocalProcessNodeProvisionerRetireIsFailClosedAndRetryable(t *testing.T) {
	spawner := &fakeProcessSpawner{pids: []int{4242}}
	provisioner, err := NewLocalProcessNodeProvisioner(validProvisionerConfig(t), spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	if err := provisioner.Retire(context.Background(), "gru-node-8"); !isInvalidOperation(err) {
		t.Fatalf("retiring an unknown node must fail closed, got %v", err)
	}
	if len(spawner.terminated) != 0 {
		t.Fatalf("nothing may be terminated for an unknown node, got %v", spawner.terminated)
	}
	if err := provisioner.Retire(nil, "gru-node-8"); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}

	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(spawner.terminated) != 1 || spawner.terminated[0] != 4242 {
		t.Fatalf("terminations = %v", spawner.terminated)
	}
	// The completed retirement removed the record, so a second retire is a
	// fail-closed refusal instead of a second signal.
	if err := provisioner.Retire(context.Background(), "gru-node-9"); !isInvalidOperation(err) {
		t.Fatalf("a completed retirement must fail closed, got %v", err)
	}

	// A failed termination keeps the record so the retry reaches the child.
	spawner.pids = []int{5151}
	if err := provisioner.Provision(context.Background(), validProvisionRequest(t)); err != nil {
		t.Fatalf("provision: %v", err)
	}
	spawner.terminateErr = errors.New("terminate failed")
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err == nil {
		t.Fatal("the termination failure must surface")
	}
	spawner.terminateErr = nil
	if err := provisioner.Retire(context.Background(), "gru-node-9"); err != nil {
		t.Fatalf("retire retry: %v", err)
	}
	if len(spawner.terminated) != 3 || spawner.terminated[1] != 5151 || spawner.terminated[2] != 5151 {
		t.Fatalf("terminations = %v", spawner.terminated)
	}
}

func TestLocalProcessNodeProvisionerSerializesRetireAgainstReprovision(t *testing.T) {
	spawner := &blockingRetireSpawner{started: make(chan struct{}), release: make(chan struct{})}
	provisioner, err := NewLocalProcessNodeProvisioner(validProvisionerConfig(t), spawner)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	request := validProvisionRequest(t)
	if err := provisioner.Provision(context.Background(), request); err != nil {
		t.Fatalf("provision: %v", err)
	}
	retired := make(chan error, 1)
	go func() { retired <- provisioner.Retire(context.Background(), request.NodeId) }()
	<-spawner.started
	if err := provisioner.Provision(context.Background(), request); !isInvalidOperation(err) {
		t.Fatalf("reprovision entered while the previous child was retiring: %v", err)
	}
	if spawner.spawnCalls != 1 {
		t.Fatalf("retire race spawned %d children", spawner.spawnCalls)
	}
	close(spawner.release)
	if err := <-retired; err == nil {
		t.Fatal("the configured termination failure did not surface")
	}
	if err := provisioner.Provision(context.Background(), request); !isInvalidOperation(err) {
		t.Fatalf("failed retirement lost ownership of the old child: %v", err)
	}
}

func TestCommandProcessSpawnerFailsClosedWithoutSpawning(t *testing.T) {
	if _, err := NewCommandProcessSpawner(0); !errorsAsParam(err, "terminateGrace") {
		t.Fatalf("a nonpositive grace period must be refused, got %v", err)
	}
	spawner, err := NewCommandProcessSpawner(time.Second)
	if err != nil {
		t.Fatalf("spawner: %v", err)
	}
	if _, err := spawner.Spawn(nil, validNodeProcessSpec(t)); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}
	rootSpec := validNodeProcessSpec(t)
	rootSpec.RunAsUid = 0
	if _, err := spawner.Spawn(context.Background(), rootSpec); !errorsAsParam(err, "runAsUid") {
		t.Fatalf("a root spec must be refused, got %v", err)
	}
	if err := spawner.Terminate(nil, 4242); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}
	if err := spawner.Terminate(context.Background(), 0); !errorsAsParam(err, "pid") {
		t.Fatalf("a nonpositive pid must be refused, got %v", err)
	}
	if err := spawner.Terminate(context.Background(), 4242); !isInvalidOperation(err) {
		t.Fatalf("a foreign pid must be refused fail-closed, got %v", err)
	}

	// An absent binary makes Start fail before any child exists, on every
	// platform, so the spawn path stays covered without a real process.
	absent := validNodeProcessSpec(t)
	absent.BinaryPath = "/nonexistent/ts-node"
	if _, err := spawner.Spawn(context.Background(), absent); err == nil {
		t.Fatal("spawning an absent binary must fail")
	}
	if err := spawner.Terminate(context.Background(), 4242); !isInvalidOperation(err) {
		t.Fatalf("the failed spawn must leave no recorded child, got %v", err)
	}
}

func TestCommandProcessSpawnerReapsNaturalExitWithoutPIDReuseSignal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the production spawner refuses uid 0")
	}
	spawner, err := NewCommandProcessSpawner(100 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewNodeProcessSpec(
		"/run/current-system/sw/bin/sleep", "gru-node-9", "nats://127.0.0.1:4222", []string{"0"}, nil, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := spawner.Spawn(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		spawner.mutex.Lock()
		_, tracked := spawner.processes[pid]
		_, reaped := spawner.reaped[pid]
		spawner.mutex.Unlock()
		if !tracked && reaped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("natural child pid %d was not reaped", pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
	var exited *processAlreadyExitedError
	if err := spawner.Terminate(context.Background(), pid); !errors.As(err, &exited) {
		t.Fatalf("reusing a naturally exited pid must fail closed without signaling, got %v", err)
	}
}

func TestCommandProcessSpawnerWaitidFallbackDoesNotKillHealthyChild(t *testing.T) {
	spawner, err := NewCommandProcessSpawner(20 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	spawner.waitid = func(int, *unix.Siginfo, int) error { return unix.EIO }
	spawner.pidfdOpen = func(int) (int, error) { return -1, unix.ENOSYS }
	script := filepath.Join(t.TempDir(), "healthy-child")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec /run/current-system/sw/bin/sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	spec, err := NewNodeProcessSpec(
		script, "gru-node-9", "nats://127.0.0.1:4222", nil, nil, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := spawner.Spawn(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	spawner.mutex.Lock()
	_, tracked := spawner.processes[pid]
	spawner.mutex.Unlock()
	if !tracked {
		t.Fatal("waitid observation failure terminated a healthy child")
	}
	if err := spawner.Terminate(context.Background(), pid); err != nil {
		t.Fatalf("explicit termination after waitid fallback: %v", err)
	}
}

func TestCommandProcessSpawnerCancellationDuringPidfdInstallReapsChild(t *testing.T) {
	spawner, err := NewCommandProcessSpawner(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	spawner.pidfdOpen = func(int) (int, error) {
		close(started)
		<-release
		return -1, unix.ENOSYS
	}
	spec, err := NewNodeProcessSpec(
		"/run/current-system/sw/bin/sleep", "gru-node-9", "nats://127.0.0.1:4222", []string{"30"}, nil, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, spawnErr := spawner.Spawn(ctx, spec)
		result <- spawnErr
	}()
	<-started
	cancel()
	select {
	case spawnErr := <-result:
		if !errors.Is(spawnErr, context.Canceled) {
			t.Fatalf("spawn cancellation error = %v", spawnErr)
		}
	case <-time.After(time.Second):
		t.Fatal("spawn did not return after cancellation during pidfd installation")
	}
	close(release)
}

func TestNodeProcessCredentialKeepsSameAccountAndFencesAccountChanges(t *testing.T) {
	credential, err := nodeProcessCredential(1000, 100, 1000)
	if err != nil || credential != nil {
		t.Fatalf("same-account spawn should keep current credentials: credential=%+v err=%v", credential, err)
	}
	credential, err = nodeProcessCredential(0, 0, 1042)
	if err != nil || credential == nil || credential.Uid != 1042 || credential.Gid != 1042 {
		t.Fatalf("root credential drop = %+v, err=%v", credential, err)
	}
	if credential, err = nodeProcessCredential(1000, 1000, 1042); err == nil || credential != nil {
		t.Fatalf("unprivileged account switch was accepted: credential=%+v err=%v", credential, err)
	}
	if credential, err = nodeProcessCredential(0, 0, 0); err == nil || credential != nil {
		t.Fatalf("uid-0 node was accepted: credential=%+v err=%v", credential, err)
	}
	if credential, err = nodeProcessCredential(-1, 1000, 1000); err == nil || credential != nil {
		t.Fatalf("unknown current uid was accepted: credential=%+v err=%v", credential, err)
	}
}
