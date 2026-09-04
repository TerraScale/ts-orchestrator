package vmnet

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHostRunnerResolvesOnlyAdmittedTools(t *testing.T) {
	tools := testHostTools(t)
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "ip", args: []string{"netns", "add", "ts-n-gru"}, want: []string{"netns", "add", "ts-n-gru"}},
		{name: "nft", args: []string{"netns", "exec", "ts-n-gru", "nft", "list", "ruleset"}, want: []string{"netns", "exec", "ts-n-gru", tools.NFT, "list", "ruleset"}},
		{name: "tc", args: []string{"netns", "exec", "ts-n-gru", "tc", "qdisc", "show"}, want: []string{"netns", "exec", "ts-n-gru", tools.TC, "qdisc", "show"}},
		{name: "sysctl", args: []string{"netns", "exec", "ts-n-gru", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"}, want: []string{"netns", "exec", "ts-n-gru", tools.Sysctl, "-q", "-w", "net.ipv4.ip_forward=1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := append([]string(nil), test.args...)
			path, got, err := runner.resolve("ip", test.args)
			if err != nil {
				t.Fatal(err)
			}
			if path != tools.IP || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("resolved path=%q argv=%v, want path=%q argv=%v", path, got, tools.IP, test.want)
			}
			if !reflect.DeepEqual(test.args, original) {
				t.Fatalf("resolver mutated caller args: %v", test.args)
			}
		})
	}
}

func TestHostRunnerRejectsUnadmittedCommands(t *testing.T) {
	runner, err := NewHostRunner(testHostTools(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		executable string
		args       []string
	}{
		{executable: "/usr/bin/ip", args: []string{"link", "show"}},
		{executable: "sh", args: []string{"-c", "true"}},
		{executable: "ip", args: []string{"netns", "exec", "ts-n-gru"}},
		{executable: "ip", args: []string{"netns", "exec", "ts-n-gru", "sh"}},
	} {
		if _, _, err := runner.resolve(test.executable, test.args); err == nil {
			t.Fatalf("accepted executable=%q args=%v", test.executable, test.args)
		}
	}
	if err := runner.Run(nil, "ip", []string{"link", "show"}); err == nil {
		t.Fatal("accepted nil context")
	}
	if _, _, err := (*HostRunner)(nil).resolve("ip", nil); err == nil {
		t.Fatal("accepted nil runner")
	}
}

func TestCleanupAdmissionIsRestrictedToOwnedResources(t *testing.T) {
	for _, test := range []struct {
		args []string
		want bool
	}{
		{args: []string{"netns", "del", "ts-n-gru"}, want: true},
		{args: []string{"-n", "ts-n-gru", "link", "del", "ts-v-gru-sfo"}, want: true},
		{args: []string{"netns", "exec", "ts-n-fra", "nft", "delete", "table", "inet", "ts_vmnet"}, want: true},
		{args: []string{"netns", "del", "default"}},
		{args: []string{"-n", "ts-n-gru", "link", "del", "eth0"}},
		{args: []string{"-n", "ts-n-gru", "link", "del", "ts-v-sfo-fra"}},
		{args: []string{"netns", "exec", "ts-n-fra", "nft", "delete", "table", "inet", "other_vmnet"}},
	} {
		if got := admittedCleanup("ip", test.args); got != test.want {
			t.Fatalf("admittedCleanup(%v) = %v, want %v", test.args, got, test.want)
		}
	}
	if admittedCleanup("sh", []string{"netns", "del", "ts-n-gru"}) {
		t.Fatal("accepted a non-ip cleanup executable")
	}
	if !missingCleanup([]string{"netns", "del", "ts-n-gru"}, "Cannot remove namespace file: No such file or directory") {
		t.Fatal("did not normalize explicit missing namespace output")
	}
	if missingCleanup([]string{"netns", "del", "ts-n-gru"}, "Operation not permitted") {
		t.Fatal("normalized a permission error")
	}
}

func TestNewHostRunnerValidatesToolPaths(t *testing.T) {
	tools := testHostTools(t)
	tests := []HostTools{
		{IP: "ip", NFT: tools.NFT, TC: tools.TC, Sysctl: tools.Sysctl},
		{IP: tools.NFT, NFT: tools.NFT, TC: tools.TC, Sysctl: tools.Sysctl},
		{IP: filepath.Join(t.TempDir(), "ip"), NFT: tools.NFT, TC: tools.TC, Sysctl: tools.Sysctl},
	}
	for _, candidate := range tests {
		if _, err := NewHostRunner(candidate); err == nil {
			t.Fatalf("accepted invalid tool paths: %+v", candidate)
		}
	}

	nonExecutable := filepath.Join(t.TempDir(), "ip")
	if err := os.WriteFile(nonExecutable, []byte("not executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHostRunner(HostTools{IP: nonExecutable, NFT: tools.NFT, TC: tools.TC, Sysctl: tools.Sysctl}); err == nil || !strings.Contains(err.Error(), "executable regular file") {
		t.Fatalf("non-executable path error = %v", err)
	}
}

func testHostTools(t *testing.T) HostTools {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, 4)
	for _, name := range []string{"ip", "nft", "tc", "sysctl"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return HostTools{IP: paths["ip"], NFT: paths["nft"], TC: paths["tc"], Sysctl: paths["sysctl"]}
}

var _ Runner = (*HostRunner)(nil)
