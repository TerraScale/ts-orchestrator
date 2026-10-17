package app

import (
	"context"
	"strings"
	"testing"
)

func TestRootOCIControllerRequiresExactLiveMainPID(t *testing.T) {
	const wire = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nControlPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/terrascale-orchestrator-controller.service\n"
	for _, active := range []string{wire, strings.NewReplacer("ActiveState=active", "ActiveState=activating", "SubState=running", "SubState=start").Replace(wire)} {
		service, err := parseRootOCIController([]byte(active))
		if err != nil || service.pid != 123 || !rootOCIProcessCgroup("0::"+service.cgroup+"\n", service.cgroup) {
			t.Fatalf("current MainPID unavailable during start/running: %+v, %v", service, err)
		}
		if rootOCIProcessCgroup("0::"+service.cgroup+"/child\n", service.cgroup) || rootOCIProcessCgroup("0::/\n", service.cgroup) {
			t.Fatal("different process cgroup admitted")
		}
	}
	for _, invalid := range []string{
		wire + "MainPID=456\n",
		strings.Replace(wire, "MainPID=123", "MainPID=0", 1),
		strings.Replace(wire, "ControlPID=0", "ControlPID=123", 1),
		strings.Replace(wire, "ActiveState=active", "ActiveState=inactive", 1),
		strings.Replace(wire, "ControlGroup=/system.slice/terrascale-orchestrator-controller.service", "ControlGroup=/", 1),
		strings.Replace(wire, "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdeg", 1),
	} {
		if _, err := parseRootOCIController([]byte(invalid)); err == nil {
			t.Fatalf("invalid process observation admitted: %q", invalid)
		}
	}
}

func TestRootOCIStartupGenerationSurvivesSessionClear(t *testing.T) {
	source := new(managedRuntimeHost)
	session, cancel := context.WithCancel(t.Context())
	defer cancel()
	source.bind(session, nil, source.transport, nil, "")
	first := source.generation
	if first == 0 {
		t.Fatal("first actual session binding did not end startup generation")
	}
	source.bind(session, nil, source.transport, nil, "")
	if source.generation != first {
		t.Fatal("refreshing the same session replaced its process phase")
	}
	source.clear()
	if source.generation != first || source.session != nil {
		t.Fatal("session clearing restored the pre-session startup generation")
	}
	successor, stop := context.WithCancel(t.Context())
	defer stop()
	source.bind(successor, nil, source.transport, nil, "")
	if source.generation <= first {
		t.Fatal("successor session reused the old startup generation")
	}
}
