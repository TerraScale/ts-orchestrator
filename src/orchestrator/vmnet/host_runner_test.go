package vmnet

import (
	"context"
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
		{name: "nft", args: []string{"netns", "exec", "ts-n-gru", tools.NFT, "list", "ruleset"}, want: []string{"netns", "exec", "ts-n-gru", tools.NFT, "list", "ruleset"}},
		{name: "tc", args: []string{"netns", "exec", "ts-n-gru", tools.TC, "qdisc", "show"}, want: []string{"netns", "exec", "ts-n-gru", tools.TC, "qdisc", "show"}},
		{name: "sysctl", args: []string{"netns", "exec", "ts-n-gru", tools.Sysctl, "-q", "-w", "net.ipv4.ip_forward=1"}, want: []string{"netns", "exec", "ts-n-gru", tools.Sysctl, "-q", "-w", "net.ipv4.ip_forward=1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := append([]string(nil), test.args...)
			path, got, err := runner.resolve(tools.IP, test.args)
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
	tools := testHostTools(t)
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		executable string
		args       []string
	}{
		{executable: "ip", args: []string{"link", "show"}},
		{executable: "sh", args: []string{"-c", "true"}},
		{executable: tools.NFT, args: []string{"list", "ruleset"}},
		{executable: tools.IP, args: []string{"netns", "exec", "ts-n-gru"}},
		{executable: tools.IP, args: []string{"netns", "exec", "ts-n-gru", "nft"}},
		{executable: tools.IP, args: []string{"netns", "exec", "ts-n-gru", "/different/bin/nft"}},
		{executable: tools.IP, args: []string{"netns", "exec", "ts-n-gru", "sh"}},
	} {
		if _, _, err := runner.resolve(test.executable, test.args); err == nil {
			t.Fatalf("accepted executable=%q args=%v", test.executable, test.args)
		}
	}
	if err := runner.Run(nil, tools.IP, []string{"link", "show"}); err == nil {
		t.Fatal("accepted nil context")
	}
	if _, _, err := (*HostRunner)(nil).resolve("ip", nil); err == nil {
		t.Fatal("accepted nil runner")
	}
}

func TestCleanupAdmissionIsRestrictedToOwnedResources(t *testing.T) {
	tools := testHostTools(t)
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.RunID = testRunID
	config.Tools = tools
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range plan.Cleanup.Commands {
		if !runner.admittedCleanup(command.Executable, command.Args) {
			t.Fatalf("rejected planned cleanup command: %+v", command)
		}
	}
	if runner.admittedCleanup("sh", []string{"netns", "del", plan.Regions[0].Namespace}) {
		t.Fatal("accepted a non-ip cleanup executable")
	}
	if runner.admittedCleanup(tools.IP, []string{"netns", "del", "default"}) {
		t.Fatal("accepted an unowned namespace")
	}
	cleanupArgs := []string{"netns", "del", plan.Regions[0].Namespace}
	if !runner.missingCleanup(cleanupArgs, "Cannot remove namespace file: No such file or directory") {
		t.Fatal("did not normalize explicit missing namespace output")
	}
	if runner.missingCleanup(cleanupArgs, "Operation not permitted") {
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

func TestNewHostRunnerRejectsReplaceableOrSymlinkedTools(t *testing.T) {
	tools := testHostTools(t)

	if err := os.Chmod(tools.IP, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHostRunner(tools); err == nil {
		t.Fatal("accepted a group/world-writable ip executable")
	}
	if err := os.Chmod(tools.IP, 0700); err != nil {
		t.Fatal(err)
	}

	symlinkDirectory := t.TempDir()
	symlink := filepath.Join(symlinkDirectory, "ip")
	if err := os.Symlink(tools.IP, symlink); err != nil {
		t.Fatal(err)
	}
	symlinked := tools
	symlinked.IP = symlink
	if _, err := NewHostRunner(symlinked); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink error = %v", err)
	}

	writableDirectory := t.TempDir()
	writableIP := filepath.Join(writableDirectory, "ip")
	if err := os.WriteFile(writableIP, []byte("test executable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writableDirectory, 0777); err != nil {
		t.Fatal(err)
	}
	writableParent := tools
	writableParent.IP = writableIP
	if _, err := NewHostRunner(writableParent); err == nil || !strings.Contains(err.Error(), "parent directory") {
		t.Fatalf("writable-parent error = %v", err)
	}
}

func TestHostRunnerRevalidatesExecutableImmediatelyBeforeRun(t *testing.T) {
	tools := testHostTools(t)
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tools.IP, 0777); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), tools.IP, []string{"link", "show"}); err == nil || !strings.Contains(err.Error(), "executable regular file") {
		t.Fatalf("run did not reject executable changed after runner construction: %v", err)
	}
}

func testHostTools(t *testing.T) HostTools {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, 4)
	for _, name := range []string{"ip", "nft", "tc", "sysctl", "iptables"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return HostTools{IP: paths["ip"], NFT: paths["nft"], TC: paths["tc"], Sysctl: paths["sysctl"], IPTables: paths["iptables"]}
}

var _ Runner = (*HostRunner)(nil)
