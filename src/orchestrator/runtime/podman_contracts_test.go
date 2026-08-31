package runtime

import (
	"errors"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func validPodmanRunRequestArguments() []any {
	return []any{
		"terrascale-gru-orchestrator-1",
		"registry.terrascale.internal/terrascale/terrabase-server@sha256:" + hostRuntimePlanDigest,
		"linux/arm64",
		uint32(65532),
		uint32(65532),
		"terrascale/terrascale-gru-orchestrator-1",
		[]string{"ALL"},
		int64(1024 * 1024 * 1024),
		512,
		200,
		500,
		[]PodmanVolumeMount{{VolumeName: "terrabase-gru-1", Destination: "/var/lib/terrabase", ReadOnly: false}},
		map[string]string{
			PodmanLabelAllocation:  "terrascale-gru-orchestrator-1",
			PodmanLabelFingerprint: strings.Repeat("a", 64),
		},
	}
}

func buildPodmanRunRequest(t *testing.T, arguments []any) (PodmanRunRequest, error) {
	t.Helper()
	return NewPodmanRunRequest(
		arguments[0].(string),
		arguments[1].(string),
		arguments[2].(string),
		arguments[3].(uint32),
		arguments[4].(uint32),
		arguments[5].(string),
		arguments[6].([]string),
		arguments[7].(int64),
		arguments[8].(int),
		arguments[9].(int),
		arguments[10].(int),
		arguments[11].([]PodmanVolumeMount),
		arguments[12].(map[string]string),
	)
}

func TestPodmanAllocationStateStringIsAClosedVocabulary(t *testing.T) {
	expected := map[PodmanAllocationState]string{
		PodmanAllocationStateAbsent:   "Absent",
		PodmanAllocationStateCreating: "Creating",
		PodmanAllocationStateStarting: "Starting",
		PodmanAllocationStateRunning:  "Running",
		PodmanAllocationStateStopped:  "Stopped",
		PodmanAllocationStateStopping: "Stopping",
		PodmanAllocationStateFailed:   "Failed",
	}
	if len(expected) != len(AllPodmanAllocationStates) {
		t.Fatalf("vocabulary size = %d, want %d", len(AllPodmanAllocationStates), len(expected))
	}
	for state, name := range expected {
		if state.String() != name {
			t.Fatalf("state %d String() = %q, want %q", int(state), state.String(), name)
		}
	}
	if unknown := PodmanAllocationState(99); unknown.String() != "PodmanAllocationState(99)" {
		t.Fatalf("unknown state String() = %q", unknown.String())
	}
}

func TestNewPodmanAllocationObservation(t *testing.T) {
	tests := []struct {
		name           string
		state          PodmanAllocationState
		imageReference string
		labels         map[string]string
		running        bool
		wantErrorType  string
		expectedParam  string
	}{
		{
			name:    "absent observation",
			state:   PodmanAllocationStateAbsent,
			running: false,
		},
		{
			name:           "running observation",
			state:          PodmanAllocationStateRunning,
			imageReference: "registry.terrascale.internal/terrascale/terrascale-database@sha256:" + hostRuntimePlanDigest,
			labels:         map[string]string{PodmanLabelAllocation: "terrascale-database-api-1"},
			running:        true,
		},
		{
			name:           "stopped observation is not running",
			state:          PodmanAllocationStateStopped,
			imageReference: "registry.terrascale.internal/terrascale/terrascale-database@sha256:" + hostRuntimePlanDigest,
			running:        false,
		},
		{
			name:          "undefined state is rejected",
			state:         PodmanAllocationState(99),
			wantErrorType: "errs.ArgumentOutOfRangeError",
			expectedParam: "state",
		},
		{
			name:           "running flag disagrees with state",
			state:          PodmanAllocationStateStopped,
			imageReference: "registry.terrascale.internal/x@sha256:" + hostRuntimePlanDigest,
			running:        true,
			wantErrorType:  "errs.Argument",
			expectedParam:  "running",
		},
		{
			name:           "absent observation carrying an image is rejected",
			state:          PodmanAllocationStateAbsent,
			imageReference: "registry.terrascale.internal/x@sha256:" + hostRuntimePlanDigest,
			wantErrorType:  "errs.Argument",
			expectedParam:  "state",
		},
		{
			name:          "absent observation carrying labels is rejected",
			state:         PodmanAllocationStateAbsent,
			labels:        map[string]string{PodmanLabelAllocation: "terrascale-database-api-1"},
			wantErrorType: "errs.Argument",
			expectedParam: "state",
		},
		{
			name:          "non-absent observation without an image is rejected",
			state:         PodmanAllocationStateRunning,
			running:       true,
			wantErrorType: "errs.Argument",
			expectedParam: "imageReference",
		},
		{
			name:           "flag-like image reference is rejected",
			state:          PodmanAllocationStateRunning,
			imageReference: "--privileged",
			running:        true,
			wantErrorType:  "errs.Argument",
			expectedParam:  "imageReference",
		},
		{
			name:           "label values containing spaces are rejected",
			state:          PodmanAllocationStateRunning,
			imageReference: "registry.terrascale.internal/x@sha256:" + hostRuntimePlanDigest,
			labels:         map[string]string{PodmanLabelAllocation: "with space"},
			running:        true,
			wantErrorType:  "errs.Argument",
			expectedParam:  "labels",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtimeId := hostRuntimePlanDigest
			if test.state == PodmanAllocationStateAbsent {
				runtimeId = ""
			}
			observation, err := NewPodmanAllocationObservation(
				test.state, runtimeId, test.imageReference, test.labels, test.running)
			if test.wantErrorType != "" {
				if err == nil {
					t.Fatalf("expected %s, got a valid observation", test.wantErrorType)
				}
				if !hasPodmanErrorType(err, test.wantErrorType) {
					t.Fatalf("expected %s, got %T: %v", test.wantErrorType, err, err)
				}
				if !errorsAsParam(err, test.expectedParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectedParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("observation: %v", err)
			}
			if observation.State != test.state {
				t.Fatalf("state = %v, want %v", observation.State, test.state)
			}
			if observation.Running != test.running {
				t.Fatalf("running = %v, want %v", observation.Running, test.running)
			}
			if len(observation.Labels) != len(test.labels) {
				t.Fatalf("label count = %d, want %d", len(observation.Labels), len(test.labels))
			}
		})
	}
}

func TestNewPodmanVolumeMount(t *testing.T) {
	tests := []struct {
		name        string
		volumeName  string
		destination string
		readOnly    bool
		expectErr   bool
		expectParam string
	}{
		{name: "valid mount", volumeName: "terrabase-gru-1", destination: "/var/lib/terrabase", readOnly: true},
		{name: "uppercase volume name", volumeName: "TERRABASE", destination: "/var/lib/terrabase", expectErr: true, expectParam: "volumeName"},
		{name: "empty volume name", volumeName: "", destination: "/var/lib/terrabase", expectErr: true, expectParam: "volumeName"},
		{name: "root destination", volumeName: "terrabase-gru-1", destination: "/", expectErr: true, expectParam: "destination"},
		{name: "relative destination", volumeName: "terrabase-gru-1", destination: "var/lib/terrabase", expectErr: true, expectParam: "destination"},
		{name: "traversal destination", volumeName: "terrabase-gru-1", destination: "/var/lib/../lib", expectErr: true, expectParam: "destination"},
		{name: "double slash destination", volumeName: "terrabase-gru-1", destination: "/var//lib", expectErr: true, expectParam: "destination"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mount, err := NewPodmanVolumeMount(test.volumeName, test.destination, test.readOnly)
			if test.expectErr {
				if err == nil {
					t.Fatal("expected an error, got a valid mount")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("mount: %v", err)
			}
			if mount.VolumeName != test.volumeName || mount.Destination != test.destination {
				t.Fatalf("mount = %+v", mount)
			}
		})
	}
}

func TestNewPodmanRunRequestAcceptsCanonicalRequestAndFixesSafetyEnvelope(t *testing.T) {
	request, err := buildPodmanRunRequest(t, validPodmanRunRequestArguments())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if !request.ReadOnlyRootfs {
		t.Fatal("the read-only root filesystem must be fixed by the constructor")
	}
	if !request.NoNewPrivileges {
		t.Fatal("no-new-privileges must be fixed by the constructor")
	}
	if len(request.CapDrop) != 1 || request.CapDrop[0] != "ALL" {
		t.Fatalf("cap drop = %v", request.CapDrop)
	}
	if request.Labels[PodmanLabelAllocation] != "terrascale-gru-orchestrator-1" {
		t.Fatalf("allocation label missing: %v", request.Labels)
	}
}

func TestNewPodmanRunRequest(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(arguments []any)
		wantErrorType string
		expectParam   string
	}{
		{
			name:          "uppercase container id",
			mutate:        func(a []any) { a[0] = "Terrascale-1" },
			wantErrorType: "errs.Argument",
			expectParam:   "containerId",
		},
		{
			name:          "empty image reference",
			mutate:        func(a []any) { a[1] = "" },
			wantErrorType: "errs.Argument",
			expectParam:   "imageReference",
		},
		{
			name:          "flag-like image reference",
			mutate:        func(a []any) { a[1] = "-v/etc:/etc" },
			wantErrorType: "errs.Argument",
			expectParam:   "imageReference",
		},
		{
			name:          "unknown platform",
			mutate:        func(a []any) { a[2] = "linux/riscv64" },
			wantErrorType: "errs.ArgumentOutOfRangeError",
			expectParam:   "platform",
		},
		{
			name:          "root uid",
			mutate:        func(a []any) { a[3] = uint32(0) },
			wantErrorType: "errs.Argument",
			expectParam:   "runAsUser",
		},
		{
			name:          "root gid",
			mutate:        func(a []any) { a[4] = uint32(0) },
			wantErrorType: "errs.Argument",
			expectParam:   "runAsGroup",
		},
		{
			name:          "empty cgroup parent",
			mutate:        func(a []any) { a[5] = "" },
			wantErrorType: "errs.Argument",
			expectParam:   "cgroupParent",
		},
		{
			name:          "traversal cgroup parent",
			mutate:        func(a []any) { a[5] = "terrascale/../escape" },
			wantErrorType: "errs.Argument",
			expectParam:   "cgroupParent",
		},
		{
			name:          "missing ALL capability drop",
			mutate:        func(a []any) { a[6] = []string{"NET_BIND_SERVICE"} },
			wantErrorType: "errs.Argument",
			expectParam:   "capDrop",
		},
		{
			name:          "lowercase capability token",
			mutate:        func(a []any) { a[6] = []string{"all"} },
			wantErrorType: "errs.Argument",
			expectParam:   "capDrop",
		},
		{
			name:          "memory below the floor",
			mutate:        func(a []any) { a[7] = int64(1024) },
			wantErrorType: "errs.ArgumentOutOfRangeError",
			expectParam:   "memoryMaxBytes",
		},
		{
			name:          "pids below the floor",
			mutate:        func(a []any) { a[8] = 8 },
			wantErrorType: "errs.ArgumentOutOfRangeError",
			expectParam:   "pidsLimit",
		},
		{
			name:          "cpu quota below the floor",
			mutate:        func(a []any) { a[9] = 5 },
			wantErrorType: "errs.ArgumentOutOfRangeError",
			expectParam:   "cpuQuotaPercent",
		},
		{
			name:          "cpu weight above the ceiling",
			mutate:        func(a []any) { a[10] = 10001 },
			wantErrorType: "errs.ArgumentOutOfRangeError",
			expectParam:   "cpuWeight",
		},
		{
			name: "duplicate volume destination",
			mutate: func(a []any) {
				a[11] = []PodmanVolumeMount{
					{VolumeName: "terrabase-gru-1", Destination: "/var/lib/terrabase"},
					{VolumeName: "terrabase-gru-2", Destination: "/var/lib/terrabase"},
				}
			},
			wantErrorType: "errs.Argument",
			expectParam:   "volumes",
		},
		{
			name: "same named volume mounted twice",
			mutate: func(a []any) {
				a[11] = []PodmanVolumeMount{
					{VolumeName: "terrabase-gru-1", Destination: "/var/lib/terrabase"},
					{VolumeName: "terrabase-gru-1", Destination: "/var/lib/terrabase-2"},
				}
			},
			wantErrorType: "errs.Argument",
			expectParam:   "volumes",
		},
		{
			name: "invalid volume inside the request",
			mutate: func(a []any) {
				a[11] = []PodmanVolumeMount{{VolumeName: "bad_volume", Destination: "/data"}}
			},
			wantErrorType: "errs.Argument",
			expectParam:   "volumeName",
		},
		{
			name: "uppercase label key",
			mutate: func(a []any) {
				a[12] = map[string]string{"TerraScale.Allocation": "terrascale-gru-orchestrator-1"}
			},
			wantErrorType: "errs.Argument",
			expectParam:   "labels",
		},
		{
			name: "flag-like label value",
			mutate: func(a []any) {
				a[12] = map[string]string{PodmanLabelAllocation: "--privileged"}
			},
			wantErrorType: "errs.Argument",
			expectParam:   "labels",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := validPodmanRunRequestArguments()
			test.mutate(arguments)
			_, err := buildPodmanRunRequest(t, arguments)
			if err == nil {
				t.Fatal("expected an error, got a valid request")
			}
			if !hasPodmanErrorType(err, test.wantErrorType) {
				t.Fatalf("expected %s, got %T: %v", test.wantErrorType, err, err)
			}
			if !errorsAsParam(err, test.expectParam) {
				t.Fatalf("error %v does not reference param %q", err, test.expectParam)
			}
		})
	}
}

func TestValidateRootlessContextFailsClosedOnRoot(t *testing.T) {
	valid := RootlessPodmanContext{
		PodmanBinaryPath:   "/usr/bin/podman",
		XdgRuntimeDir:      "/run/user/1000",
		SeccompProfilePath: "/etc/terrascale/seccomp/terrascale-default-v1.json",
		RunAsUid:           1000,
	}
	if err := ValidateRootlessContext(valid); err != nil {
		t.Fatalf("valid context: %v", err)
	}

	asRoot := valid
	asRoot.RunAsUid = 0
	err := ValidateRootlessContext(asRoot)
	var argumentError *errs.Argument
	if !errors.As(err, &argumentError) {
		t.Fatalf("expected errs.Argument, got %v", err)
	}
	if argumentError.Param != "RunAsUid" {
		t.Fatalf("param = %q, want RunAsUid", argumentError.Param)
	}

	tests := []struct {
		name      string
		mutate    func(context *RootlessPodmanContext)
		wantParam string
	}{
		{
			name:      "relative binary path",
			mutate:    func(c *RootlessPodmanContext) { c.PodmanBinaryPath = "podman" },
			wantParam: "PodmanBinaryPath",
		},
		{
			name:      "traversal binary path",
			mutate:    func(c *RootlessPodmanContext) { c.PodmanBinaryPath = "/usr/bin/../podman" },
			wantParam: "PodmanBinaryPath",
		},
		{
			name:      "systemd command injection in binary path",
			mutate:    func(c *RootlessPodmanContext) { c.PodmanBinaryPath = "/usr/bin/podman --remote" },
			wantParam: "PodmanBinaryPath",
		},
		{
			name:      "systemd specifier in binary path",
			mutate:    func(c *RootlessPodmanContext) { c.PodmanBinaryPath = "/usr/bin/podman%u" },
			wantParam: "PodmanBinaryPath",
		},
		{
			name:      "relative runtime dir",
			mutate:    func(c *RootlessPodmanContext) { c.XdgRuntimeDir = "run/user/1000" },
			wantParam: "XdgRuntimeDir",
		},
		{
			name:      "missing seccomp profile path",
			mutate:    func(c *RootlessPodmanContext) { c.SeccompProfilePath = "" },
			wantParam: "SeccompProfilePath",
		},
		{
			name:      "relative seccomp profile path",
			mutate:    func(c *RootlessPodmanContext) { c.SeccompProfilePath = "seccomp.json" },
			wantParam: "SeccompProfilePath",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			err := ValidateRootlessContext(candidate)
			if err == nil {
				t.Fatal("expected an error, got a valid context")
			}
			if !errorsAsParam(err, test.wantParam) {
				t.Fatalf("error %v does not reference param %q", err, test.wantParam)
			}
		})
	}
}

func TestNewRootlessPodmanContextRejectsAndAcceptsExplicitly(t *testing.T) {
	if _, err := NewRootlessPodmanContext("/usr/bin/podman", "/run/user/1000",
		"/etc/terrascale/seccomp/terrascale-default-v1.json", 0); err == nil {
		t.Fatal("uid 0 must fail closed")
	}
	if _, err := NewRootlessPodmanContext("/usr/bin/podman", "/run/user/1000", "seccomp.json", 1000); err == nil {
		t.Fatal("a relative seccomp profile path must fail closed")
	}
	context, err := NewRootlessPodmanContext("/usr/bin/podman", "/run/user/1000",
		"/etc/terrascale/seccomp/terrascale-default-v1.json", 1000)
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	if context.PodmanBinaryPath != "/usr/bin/podman" || context.XdgRuntimeDir != "/run/user/1000" ||
		context.SeccompProfilePath != "/etc/terrascale/seccomp/terrascale-default-v1.json" ||
		context.RunAsUid != 1000 {
		t.Fatalf("context = %+v", context)
	}
}

// errorsAsParam reports whether err is one of the package argument errors
// naming the given parameter.
func errorsAsParam(err error, param string) bool {
	var argumentError *errs.Argument
	if errors.As(err, &argumentError) {
		return argumentError.Param == param
	}
	var outOfRange *errs.ArgumentOutOfRangeError
	if errors.As(err, &outOfRange) {
		return outOfRange.Param == param
	}
	return false
}

// hasPodmanErrorType reports whether err unwraps to one of the package's
// typed validation errors. Keep this alongside errorsAsParam so tests remain
// resilient to wrapped errors without relying on string matching.
func hasPodmanErrorType(err error, name string) bool {
	switch name {
	case "errs.Argument":
		var target *errs.Argument
		return errors.As(err, &target)
	case "errs.ArgumentOutOfRangeError":
		var target *errs.ArgumentOutOfRangeError
		return errors.As(err, &target)
	case "InvalidOperationError":
		var target *InvalidOperationError
		return errors.As(err, &target)
	case "InvalidDataError":
		var target *InvalidDataError
		return errors.As(err, &target)
	default:
		return false
	}
}
