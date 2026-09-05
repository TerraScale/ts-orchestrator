package vmimage

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

func TestNoCloudSeedIsDeterministicAndComplete(t *testing.T) {
	t.Parallel()
	if GuestSeedPath != "/etc/terrascale/vmqual-guest-seed.json" {
		t.Fatalf("guest seed path is not durable: %q", GuestSeedPath)
	}
	spec := validNoCloudSpec(t)
	first, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.MetaData, second.MetaData) || !bytes.Equal(first.NetworkConfig, second.NetworkConfig) || !bytes.Equal(first.UserData, second.UserData) {
		t.Fatal("NoCloud output changed for identical input")
	}
	for _, expected := range []string{"instance-id: 'gru-member-1'", "terrascale-region: 'gru'"} {
		if !strings.Contains(string(first.MetaData), expected) {
			t.Fatalf("metadata does not contain %q", expected)
		}
	}
	for _, expected := range []string{"macaddress: '02:fc:00:00:00:01'", "10.77.0.10/24", "via: 10.77.0.1", "addresses: [1.1.1.1, 9.9.9.9]"} {
		if !strings.Contains(string(first.NetworkConfig), expected) {
			t.Fatalf("network config does not contain %q", expected)
		}
	}
	for _, expected := range []string{"#cloud-config", "ssh_pwauth: false", "lock_passwd: true", `restrict,command="/usr/local/libexec/terrascale-vmqual-control"`, GuestSeedPath, "terrascale-data", "/var/lib/terrascale", "terrascale-ts-node.service", "sha256sum --check --strict", "openssl pkeyutl -verify", "10.77.0.1 releases.terrascale.tech", cloudHostsTemplatePath, "cloud-init single --name update_etc_hosts", "update-ca-certificates", "set -eu", "server 10.77.0.1 iburst minpoll 4 maxpoll 5", "chronyc waitsync", "systemctl enable --now terrascale-vmqual-chrony.service", tsNodeBootstrapManifestPath, desiredHostManifestPath} {
		if !strings.Contains(string(first.UserData), expected) {
			t.Fatalf("user data does not contain %q", expected)
		}
	}
	if strings.Contains(string(first.UserData), "is-system-running") {
		t.Fatal("cloud-final contains a self-waiting systemd readiness command")
	}
	if strings.Contains(string(first.UserData), "PRIVATE KEY") {
		t.Fatal("NoCloud seed contains private key material")
	}
	if strings.Contains(string(first.UserData), "/opt/terrascale/orchestrator") || strings.Contains(string(first.UserData), "/opt/terrascale/terrabase") || strings.Contains(string(first.UserData), "curl") {
		t.Fatal("NoCloud directly installs a non-bootstrap artifact")
	}
	if strings.Count(string(first.UserData), "path: /etc/systemd/system/terrascale-ts-node.service") != 1 {
		t.Fatal("NoCloud did not write exactly one ts-node unit")
	}
	if strings.Count(string(first.UserData), "path: "+tsNodeBootstrapManifestPath) != 1 {
		t.Fatal("NoCloud did not stage exactly one desired host manifest")
	}
	if strings.Contains(string(first.UserData), "path: "+desiredHostManifestPath) {
		t.Fatal("NoCloud write_files placed the manifest beneath the not-yet-mounted data volume")
	}
	if len(first.RootFiles) != 9 || first.RootFiles[0].Path != GuestControlPath || first.RootFiles[0].Mode != 0500 || !bytes.Equal(first.RootFiles[0].Content, spec.GuestControl) || first.RootFiles[1].Path != tsNodeBootstrapBinaryPath || first.RootFiles[1].Mode != 0600 || !bytes.Equal(first.RootFiles[1].Content, spec.TSNode.Binary) {
		t.Fatal("root payloads do not preserve validated binaries and modes")
	}
	if strings.Contains(string(first.UserData), "f0VMRgIBAQA") || strings.Contains(string(first.UserData), "path: "+GuestControlPath) || strings.Contains(string(first.UserData), "path: "+tsNodeBootstrapBinaryPath+"\n") {
		t.Fatal("cloud-init YAML still embeds a binary")
	}
	if strings.HasPrefix(tsNodeBootstrapBinaryPath, "/run/") || strings.HasPrefix(tsNodeBootstrapBinaryPath, defaultDataMount+"/") {
		t.Fatal("bootstrap binary is hidden by a boot mount")
	}
	wantRunCmd := "runcmd:\n  - [/bin/sh, " + tsNodeBootstrapScriptPath + "]\n"
	if index := strings.Index(string(first.UserData), "runcmd:\n"); index < 0 || string(first.UserData[index:]) != wantRunCmd {
		t.Fatalf("NoCloud bootstrap is not one fail-closed runcmd operation:\n%s", first.UserData)
	}
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := fmt.Sprintf("%x", spec.TSNode.ReleasePublicKey)
	if !strings.Contains(string(material.config), `"releasePublicKey":"`+wantKey+`"`) || strings.ToLower(wantKey) != wantKey {
		t.Fatal("ts-node config does not pin the lowercase release key")
	}
	if !strings.Contains(string(material.config), `"manifestPath":"`+desiredHostManifestPath+`"`) {
		t.Fatalf("ts-node config does not use the reserved manifest path: %s", material.config)
	}
}

func TestNoCloudBinarySizeDoesNotExpandCloudInitYAML(t *testing.T) {
	spec := validNoCloudSpec(t)
	small, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.GuestControl = append(spec.GuestControl, make([]byte, 20<<20)...)
	large, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(small.UserData, large.UserData) || len(large.UserData) > 32<<10 || !bytes.Equal(large.RootFiles[0].Content, spec.GuestControl) {
		t.Fatal("large guest control expanded cloud-init YAML or lost payload bytes")
	}
}

func TestNoCloudRootFileRejectsUnboundDestination(t *testing.T) {
	for _, file := range []NoCloudRootFile{
		{Path: "/etc/shadow", Mode: 0600, Content: []byte("x")},
		{Path: GuestControlPath, Mode: 04755, Content: []byte("x")},
		{Path: GuestControlPath, Mode: 0500},
	} {
		if file.Validate() == nil {
			t.Fatalf("accepted invalid root payload: %s", file.Path)
		}
	}
}

func TestTSNodeBootstrapScriptStopsOnVerificationFailure(t *testing.T) {
	t.Parallel()
	spec := validNoCloudSpec(t)
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		fail      string
		wantTrace string
	}{
		{name: "digest", fail: "sha256sum", wantTrace: "cloud-init\nupdate-ca-certificates\nsha256sum\n"},
		{name: "signature", fail: "openssl", wantTrace: "cloud-init\nupdate-ca-certificates\nsha256sum\nopenssl\n"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			trace := filepath.Join(directory, "trace")
			replacements := []string{
				"/usr/bin/cloud-init", fakeBootstrapCommand(t, directory, "cloud-init", test.fail == "cloud-init"),
				"/usr/sbin/update-ca-certificates", fakeBootstrapCommand(t, directory, "update-ca-certificates", test.fail == "update-ca-certificates"),
				"/usr/bin/sha256sum", fakeBootstrapCommand(t, directory, "sha256sum", test.fail == "sha256sum"),
				"/usr/bin/openssl", fakeBootstrapCommand(t, directory, "openssl", test.fail == "openssl"),
				"/usr/bin/install", fakeBootstrapCommand(t, directory, "install", false),
				"/usr/bin/ln", fakeBootstrapCommand(t, directory, "ln", false),
				"/usr/bin/systemctl", fakeBootstrapCommand(t, directory, "systemctl", false),
				"/usr/bin/rmdir", fakeBootstrapCommand(t, directory, "rmdir", false),
				"/usr/bin/rm", fakeBootstrapCommand(t, directory, "rm", false),
				tsNodeBootstrapDirectory, filepath.Join(directory, "staging"),
				"/opt/terrascale/ts-node", filepath.Join(directory, "installed"),
			}
			script := strings.NewReplacer(replacements...).Replace(buildTSNodeBootstrapScript(material))
			scriptPath := filepath.Join(directory, "bootstrap.sh")
			if err := os.WriteFile(scriptPath, []byte(script), 0o500); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/bin/sh", scriptPath)
			command.Env = append(os.Environ(), "TRACE="+trace)
			if err := command.Run(); err == nil {
				t.Fatal("verification failure did not fail the bootstrap")
			}
			got, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.wantTrace {
				t.Fatalf("commands after failed verification were reached:\n got %q\nwant %q", got, test.wantTrace)
			}
		})
	}
}

func TestTSNodeBootstrapInstallsManifestAfterVerification(t *testing.T) {
	t.Parallel()
	material, err := canonicalTSNodeBootstrap(validNoCloudSpec(t).TSNode, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	script := buildTSNodeBootstrapScript(material)
	ordered := []string{
		"sha256sum --check --strict",
		"openssl pkeyutl -verify",
		"install -d -o root -g root -m 0700 " + tsNodeStateDirectory,
		"install -o root -g root -m 0600 " + tsNodeBootstrapManifestPath + " " + desiredHostManifestPath,
		"systemctl enable --now",
		"rm -f",
	}
	previous := -1
	for _, command := range ordered {
		index := strings.Index(script, command)
		if index <= previous {
			t.Fatalf("bootstrap command %q is missing or out of order:\n%s", command, script)
		}
		previous = index
	}
}

func fakeBootstrapCommand(t *testing.T, directory, name string, fail bool) string {
	t.Helper()
	path := filepath.Join(directory, name)
	exit := "0"
	if fail {
		exit = "1"
	}
	content := "#!/bin/sh\nprintf '%s\\n' '" + name + "' >> \"$TRACE\"\nexit " + exit + "\n"
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNoCloudSeedRejectsInvalidTSNodeBootstrap(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	tests := []struct {
		name   string
		mutate func(*TSNodeBootstrap)
	}{
		{name: "digest", mutate: func(value *TSNodeBootstrap) { value.SHA256 = strings.Repeat("1", 64) }},
		{name: "signature", mutate: func(value *TSNodeBootstrap) { value.Signature[0] ^= 0xff }},
		{name: "architecture", mutate: func(value *TSNodeBootstrap) {
			value.Binary = runnableELF64(elf.EM_X86_64)
			value.SHA256 = digest(value.Binary)
			value.Signature = ed25519.Sign(value.ReleasePublicKeyPrivateForTest(), value.Binary)
		}},
		{name: "NATS URL", mutate: func(value *TSNodeBootstrap) { value.Config.NATSURL = "tls://example.com:4222" }},
		{name: "NATS port", mutate: func(value *TSNodeBootstrap) { value.Config.NATSURL = "tls://10.77.0.1:4223" }},
		{name: "manifest host", mutate: func(value *TSNodeBootstrap) {
			value.DesiredHostManifest = bytes.ReplaceAll(value.DesiredHostManifest, []byte("releases.terrascale.tech"), []byte("evil.example"))
		}},
		{name: "host address", mutate: func(value *TSNodeBootstrap) { value.ArtifactHostAddress = "8.8.8.8" }},
		{name: "CA private key", mutate: func(value *TSNodeBootstrap) {
			key := value.ReleasePublicKeyPrivateForTest()
			der, _ := x509.MarshalPKCS8PrivateKey(key)
			value.ArtifactCACertificate = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneNoCloudSpec(base)
			test.mutate(&candidate.TSNode)
			if _, err := BuildNoCloudSeed(candidate); err == nil {
				t.Fatal("invalid ts-node bootstrap was accepted")
			}
		})
	}
}

func TestNoCloudSeedRejectsReservedBootstrapVersions(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	for _, version := range reservedVersionTestCases() {
		version := version
		t.Run(version, func(t *testing.T) {
			candidate := cloneNoCloudSpec(base)
			candidate.TSNode.Version = version
			if _, err := BuildNoCloudSeed(candidate); err == nil {
				t.Fatalf("reserved bootstrap version %q was accepted", version)
			}
		})
	}
}

func TestGuestSeedRejectsReservedReleaseVersions(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	seed, err := DecodeGuestChannelSeed(base.GuestSeed)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range reservedVersionTestCases() {
		version := version
		t.Run(version, func(t *testing.T) {
			artifacts := append([]GuestArtifact(nil), seed.Artifacts...)
			artifacts[0].Version = version
			_, err := BuildGuestChannelSeed(GuestSeedSpec{
				Image: seed.Image, Hostname: seed.Hostname, InstanceID: seed.InstanceID, Region: seed.Region,
				DataDiskPath: seed.DataDiskPath, NetworkExchangeEndpoint: seed.NetworkExchangeEndpoint, Artifacts: artifacts,
			})
			if err == nil {
				t.Fatalf("reserved guest artifact version %q was accepted", version)
			}
		})
	}
}

func reservedVersionTestCases() []string {
	return []string{"bootstrap.sh", "current", "manifest.json", "previous", "terrascale-ts-node.service", "ts-node", "ts-node.pub", "ts-node.sha256", "ts-node.sig"}
}

func TestNoCloudSeedRejectsCrossFieldMismatches(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	tests := []struct {
		name   string
		mutate func(*NoCloudSeedSpec)
	}{
		{name: "node identity", mutate: func(value *NoCloudSeedSpec) { value.TSNode.Config.NodeID = "gru-member-2" }},
		{name: "NATS gateway", mutate: func(value *NoCloudSeedSpec) { value.TSNode.Config.NATSURL = "tls://10.77.0.2:4222" }},
		{name: "artifact gateway", mutate: func(value *NoCloudSeedSpec) { value.TSNode.ArtifactHostAddress = "10.77.0.2" }},
		{name: "network exchange gateway", mutate: func(value *NoCloudSeedSpec) {
			value.GuestSeed = bytes.Replace(value.GuestSeed, []byte("10.77.0.1:18080"), []byte("10.77.0.2:18080"), 1)
		}},
		{name: "bootstrap version", mutate: func(value *NoCloudSeedSpec) { value.TSNode.Version = "3.0.1" }},
		{name: "bootstrap digest", mutate: func(value *NoCloudSeedSpec) {
			value.TSNode.Binary[len(value.TSNode.Binary)-1] ^= 0xff
			value.TSNode.SHA256 = digest(value.TSNode.Binary)
			value.TSNode.Signature = ed25519.Sign(value.TSNode.ReleasePublicKeyPrivateForTest(), value.TSNode.Binary)
		}},
		{name: "bootstrap size", mutate: func(value *NoCloudSeedSpec) {
			value.TSNode.Binary = append(value.TSNode.Binary, 0)
			value.TSNode.SHA256 = digest(value.TSNode.Binary)
			value.TSNode.Signature = ed25519.Sign(value.TSNode.ReleasePublicKeyPrivateForTest(), value.TSNode.Binary)
		}},
		{name: "orchestrator version", mutate: func(value *NoCloudSeedSpec) {
			value.TSNode.DesiredHostManifest = mutateDesiredManifest(t, value.TSNode.DesiredHostManifest, func(manifest *hostagent.HostManifest) {
				manifest.Components[0] = productionComponent("orchestrator", "3.0.1", manifest.Components[0].Sha256)
			})
		}},
		{name: "orchestrator digest", mutate: func(value *NoCloudSeedSpec) {
			value.TSNode.DesiredHostManifest = mutateDesiredManifest(t, value.TSNode.DesiredHostManifest, func(manifest *hostagent.HostManifest) {
				manifest.Components[0].Sha256 = strings.Repeat("1", 64)
			})
		}},
		{name: "terrabase version", mutate: func(value *NoCloudSeedSpec) {
			value.TSNode.DesiredHostManifest = mutateDesiredManifest(t, value.TSNode.DesiredHostManifest, func(manifest *hostagent.HostManifest) {
				manifest.Components[1] = productionComponent("terrabase", "3.0.1", manifest.Components[1].Sha256)
			})
		}},
		{name: "terrabase digest", mutate: func(value *NoCloudSeedSpec) {
			value.TSNode.DesiredHostManifest = mutateDesiredManifest(t, value.TSNode.DesiredHostManifest, func(manifest *hostagent.HostManifest) {
				manifest.Components[1].Sha256 = strings.Repeat("2", 64)
			})
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneNoCloudSpec(base)
			test.mutate(&candidate)
			if _, err := BuildNoCloudSeed(candidate); err == nil {
				t.Fatal("cross-field mismatch was accepted")
			}
		})
	}
}

func TestNoCloudSeedRejectsNonProductionDesiredManifest(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	tests := []struct {
		name   string
		mutate func(*hostagent.HostManifest)
	}{
		{name: "missing component", mutate: func(value *hostagent.HostManifest) { value.Components = value.Components[:1] }},
		{name: "extra component", mutate: func(value *hostagent.HostManifest) {
			value.Components = append(value.Components, productionComponent("worker", "3.0.0", strings.Repeat("3", 64)))
		}},
		{name: "component order", mutate: func(value *hostagent.HostManifest) {
			value.Components[0], value.Components[1] = value.Components[1], value.Components[0]
		}},
		{name: "component name", mutate: func(value *hostagent.HostManifest) { value.Components[0].Name = "worker" }},
		{name: "reserved version", mutate: func(value *hostagent.HostManifest) { value.Components[0].Version = "current" }},
		{name: "user", mutate: func(value *hostagent.HostManifest) { value.Components[0].User = "terrascale-worker" }},
		{name: "data volume", mutate: func(value *hostagent.HostManifest) { value.Components[0].DataVolume = "/var/lib/terrascale/worker" }},
		{name: "ts-node data ancestor", mutate: func(value *hostagent.HostManifest) { value.Components[0].DataVolume = "/var/lib/terrascale" }},
		{name: "ts-node data root", mutate: func(value *hostagent.HostManifest) { value.Components[0].DataVolume = tsNodeStateDirectory }},
		{name: "ts-node data descendant", mutate: func(value *hostagent.HostManifest) {
			value.Components[0].DataVolume = tsNodeStateDirectory + "/orchestrator"
		}},
		{name: "CPU profile", mutate: func(value *hostagent.HostManifest) { value.Components[0].CPUWeight++ }},
		{name: "memory profile", mutate: func(value *hostagent.HostManifest) { value.Components[0].MemoryMaxBytes++ }},
		{name: "IO profile", mutate: func(value *hostagent.HostManifest) { value.Components[0].IOWeight++ }},
		{name: "netlink profile", mutate: func(value *hostagent.HostManifest) { value.Components[0].NeedsNetlink = true }},
		{name: "artifact port", mutate: func(value *hostagent.HostManifest) {
			value.Components[0].ArtifactURL = strings.Replace(value.Components[0].ArtifactURL, ":8443", ":9443", 1)
		}},
		{name: "artifact query", mutate: func(value *hostagent.HostManifest) { value.Components[0].ArtifactURL += "?token=secret" }},
		{name: "signature query", mutate: func(value *hostagent.HostManifest) { value.Components[0].SignatureURL += "?token=secret" }},
		{name: "artifact fragment", mutate: func(value *hostagent.HostManifest) { value.Components[0].ArtifactURL += "#fragment" }},
		{name: "signature fragment", mutate: func(value *hostagent.HostManifest) { value.Components[0].SignatureURL += "#fragment" }},
		{name: "artifact userinfo", mutate: func(value *hostagent.HostManifest) {
			value.Components[0].ArtifactURL = strings.Replace(value.Components[0].ArtifactURL, "https://", "https://user:password@", 1)
		}},
		{name: "signature userinfo", mutate: func(value *hostagent.HostManifest) {
			value.Components[0].SignatureURL = strings.Replace(value.Components[0].SignatureURL, "https://", "https://user:password@", 1)
		}},
		{name: "artifact path", mutate: func(value *hostagent.HostManifest) { value.Components[0].ArtifactURL += ".other" }},
		{name: "signature path", mutate: func(value *hostagent.HostManifest) { value.Components[0].SignatureURL += ".other" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneNoCloudSpec(base)
			candidate.TSNode.DesiredHostManifest = mutateDesiredManifest(t, candidate.TSNode.DesiredHostManifest, test.mutate)
			if _, err := BuildNoCloudSeed(candidate); err == nil {
				t.Fatal("non-production desired manifest was accepted")
			}
		})
	}
}

func TestNoCloudSeedRejectsInvalidGuestControl(t *testing.T) {
	t.Parallel()
	spec := validNoCloudSpec(t)
	tests := []struct {
		name    string
		control []byte
		want    string
	}{
		{name: "missing", want: "size"},
		{name: "malformed", control: []byte("not-elf"), want: "not ELF"},
		{name: "header only", control: elfHeader64(elf.EM_AARCH64), want: "entry segment"},
		{name: "wrong architecture", control: runnableELF64(elf.EM_X86_64), want: "architecture"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := spec
			candidate.GuestControl = test.control
			if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid guest control accepted: %v", err)
			}
		})
	}
}

func TestNoCloudSeedRejectsUnsafeOrInconsistentInput(t *testing.T) {
	t.Parallel()
	base := validNoCloudSpec(t)
	candidate := base
	candidate.GuestSeed = []byte("not-json")
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "guest seed") {
		t.Fatalf("invalid guest seed accepted: %v", err)
	}
	candidate = base
	candidate.Gateway = "10.78.0.1"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("off-subnet gateway accepted: %v", err)
	}
	candidate = base
	candidate.SSHAuthorizedKey = "ssh-rsa AAAA legacy"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("unadmitted SSH key accepted: %v", err)
	}
	candidate = base
	candidate.SSHAuthorizedKey = "ssh-ed25519 AAAA"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("malformed SSH key accepted: %v", err)
	}
	candidate = base
	candidate.SSHAuthorizedKey += "\n"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("SSH key with trailing data accepted: %v", err)
	}
	for _, mac := range []string{"", "00:11:22:33:44:55", "03:11:22:33:44:55", "02:11:22:33:44", " 02:11:22:33:44:55"} {
		candidate = base
		candidate.MACAddress = mac
		if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "MAC") {
			t.Fatalf("unadmitted MAC %q accepted: %v", mac, err)
		}
	}
	candidate = base
	candidate.DataDevice = "/dev/vda"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "/dev/vdb") {
		t.Fatalf("root drive accepted as data disk: %v", err)
	}
	candidate = base
	candidate.DataMount = "/srv/data"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "/var/lib/terrascale") {
		t.Fatalf("unexpected data mount accepted: %v", err)
	}
	candidate = base
	candidate.Hostname = "gru-member-2"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched seed identity accepted: %v", err)
	}
	candidate = base
	candidate.InstanceID = "gru-member-2"
	if _, err := BuildNoCloudSeed(candidate); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched seed instance id accepted: %v", err)
	}
	for _, address := range []string{"127.0.0.2", "10.77.0.0", "10.77.0.255"} {
		candidate = base
		candidate.Address = address
		if _, err := BuildNoCloudSeed(candidate); err == nil {
			t.Fatalf("unusable guest address %q accepted", address)
		}
	}
	for _, gateway := range []string{"127.0.0.1", "10.77.0.0", "10.77.0.255"} {
		candidate = base
		candidate.Gateway = gateway
		if _, err := BuildNoCloudSeed(candidate); err == nil {
			t.Fatalf("unusable gateway %q accepted", gateway)
		}
	}
}

func TestMACForIPv4(t *testing.T) {
	t.Parallel()
	mac, err := MACForIPv4("10.77.2.14")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "06:00:0a:4d:02:0e" {
		t.Fatalf("MAC = %q", mac)
	}
	if _, err := MACForIPv4("not-an-address"); err == nil {
		t.Fatal("invalid address was accepted")
	}
}

func validNoCloudSpec(t *testing.T) NoCloudSeedSpec {
	t.Helper()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	image := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	tsNodeBinary := runnableELF64(elf.EM_AARCH64)
	orchestratorBinary := []byte("orchestrator")
	terrabaseBinary := []byte("terrabase")
	guestSeed, err := BuildGuestChannelSeed(GuestSeedSpec{
		Image: image, Hostname: "gru-member-1", InstanceID: "gru-member-1", Region: "gru", DataDiskPath: "/dev/vdb", NetworkExchangeEndpoint: "10.77.0.1:18080",
		Artifacts: []GuestArtifact{
			guestArtifact("terrabase", "3.0.0", "/artifacts/terrabase", terrabaseBinary),
			guestArtifact("ts-node", "3.0.0", "/artifacts/ts-node", tsNodeBinary),
			guestArtifact("orchestrator", "3.0.0", "/artifacts/orchestrator", orchestratorBinary),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	caCertificate := testCACertificate(t, privateKey)
	membershipKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	membershipDER, err := x509.MarshalPKCS8PrivateKey(membershipKey)
	if err != nil {
		t.Fatal(err)
	}
	membershipPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: membershipDER})
	_, membershipPublic, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(membershipPEM)
	if err != nil {
		t.Fatal(err)
	}
	desiredManifest := marshalDesiredManifest(t, []hostagent.ComponentSpec{
		productionComponent("orchestrator", "3.0.0", digest(orchestratorBinary)),
		productionComponent("terrabase", "3.0.0", digest(terrabaseBinary)),
	})
	return NoCloudSeedSpec{
		InstanceID: "gru-member-1", Hostname: "gru-member-1", Region: "gru",
		Address: "10.77.0.10", PrefixBits: 24, Gateway: "10.77.0.1", MACAddress: "02:FC:00:00:00:01",
		Nameservers:      []string{"9.9.9.9", "1.1.1.1", "9.9.9.9"},
		SSHAuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBB8hhavGePnkrgQT92jQZ3sm2CEuJtBQp8uYpOUwV4v vmqual",
		DataDevice:       "/dev/vdb", DataMount: "/var/lib/terrascale", GuestSeed: guestSeed,
		GuestControl: runnableELF64(elf.EM_AARCH64),
		TSNode: TSNodeBootstrap{
			Version: "3.0.0", Binary: tsNodeBinary, SHA256: digest(tsNodeBinary), Signature: ed25519.Sign(privateKey, tsNodeBinary),
			ReleasePublicKey:             privateKey.Public().(ed25519.PublicKey),
			NATSIdentity:                 testTSNodeNATSIdentity(t, privateKey, caCertificate),
			MembershipIdentityPrivateKey: membershipPEM,
			MembershipPins:               map[string]string{"gru-member-1": membershipPublic},
			Config:                       TSNodeConfig{AuthorityBucket: "ORCH_LEADERS", CommandTrustKeys: []TSNodeCommandTrust{{CandidateID: "gru-controller-gru-member-1", PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustDecodeBase64(t, membershipPublic)})}}, NodeID: "gru-member-1", NATSURL: "tls://10.77.0.1:4222", HeartbeatInterval: time.Second, ReconcileInterval: 250 * time.Millisecond},
			DesiredHostManifest:          desiredManifest,
			ArtifactCACertificate:        caCertificate, ArtifactHostAddress: "10.77.0.1",
		},
	}
}

func cloneNoCloudSpec(input NoCloudSeedSpec) NoCloudSeedSpec {
	cloned := input
	cloned.Nameservers = append([]string(nil), input.Nameservers...)
	cloned.GuestSeed = append([]byte(nil), input.GuestSeed...)
	cloned.GuestControl = append([]byte(nil), input.GuestControl...)
	cloned.TSNode.MembershipIdentityPrivateKey = append([]byte(nil), input.TSNode.MembershipIdentityPrivateKey...)
	cloned.TSNode.MembershipPins = make(map[string]string, len(input.TSNode.MembershipPins))
	for id, pin := range input.TSNode.MembershipPins {
		cloned.TSNode.MembershipPins[id] = pin
	}
	cloned.TSNode.Config.CommandTrustKeys = append([]TSNodeCommandTrust(nil), input.TSNode.Config.CommandTrustKeys...)
	for index := range cloned.TSNode.Config.CommandTrustKeys {
		cloned.TSNode.Config.CommandTrustKeys[index].PublicKeyPEM = append([]byte(nil), input.TSNode.Config.CommandTrustKeys[index].PublicKeyPEM...)
	}
	cloned.TSNode.Binary = append([]byte(nil), input.TSNode.Binary...)
	cloned.TSNode.Signature = append([]byte(nil), input.TSNode.Signature...)
	cloned.TSNode.ReleasePublicKey = append(ed25519.PublicKey(nil), input.TSNode.ReleasePublicKey...)
	cloned.TSNode.DesiredHostManifest = append([]byte(nil), input.TSNode.DesiredHostManifest...)
	cloned.TSNode.ArtifactCACertificate = append([]byte(nil), input.TSNode.ArtifactCACertificate...)
	if input.TSNode.NATSIdentity != nil {
		identity := *input.TSNode.NATSIdentity
		identity.NKeySeed = append([]byte(nil), identity.NKeySeed...)
		identity.TLSCA = append([]byte(nil), identity.TLSCA...)
		identity.TLSCertificate = append([]byte(nil), identity.TLSCertificate...)
		identity.TLSPrivateKey = append([]byte(nil), identity.TLSPrivateKey...)
		cloned.TSNode.NATSIdentity = &identity
	}

	return cloned
}

func productionComponent(name, version, sha256 string) hostagent.ComponentSpec {
	artifactURL := "https://releases.terrascale.tech:8443/releases/" + name + "/" + version + "/" + name
	return hostagent.ComponentSpec{
		Name: name, Version: version, ArtifactURL: artifactURL, SignatureURL: artifactURL + ".sig",
		Sha256: sha256, User: "terrascale-" + name, DataVolume: "/var/lib/terrascale/" + name,
		CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100,
	}
}

func marshalDesiredManifest(t *testing.T, components []hostagent.ComponentSpec) []byte {
	t.Helper()
	data, err := json.Marshal(hostagent.HostManifest{Components: components})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mutateDesiredManifest(t *testing.T, data []byte, mutate func(*hostagent.HostManifest)) []byte {
	t.Helper()
	manifest, err := hostagent.ParseHostManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&manifest)
	return marshalDesiredManifest(t, manifest.Components)
}

func (bootstrap TSNodeBootstrap) ReleasePublicKeyPrivateForTest() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func testCACertificate(t *testing.T, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TerraScale vmqual artifact CA"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func elfHeader64(machine elf.Machine) []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F'})
	data[4] = byte(elf.ELFCLASS64)
	data[5] = byte(elf.ELFDATA2LSB)
	data[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(data[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[54:56], 56)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	return data
}

func runnableELF64(machine elf.Machine) []byte {
	data := append(elfHeader64(machine), make([]byte, 60)...)
	const (
		programOffset  = 64
		segmentOffset  = 120
		virtualAddress = 0x400078
	)
	binary.LittleEndian.PutUint64(data[24:32], virtualAddress)
	binary.LittleEndian.PutUint64(data[32:40], programOffset)
	binary.LittleEndian.PutUint16(data[56:58], 1)
	binary.LittleEndian.PutUint32(data[programOffset:programOffset+4], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(data[programOffset+4:programOffset+8], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(data[programOffset+8:programOffset+16], segmentOffset)
	binary.LittleEndian.PutUint64(data[programOffset+16:programOffset+24], virtualAddress)
	binary.LittleEndian.PutUint64(data[programOffset+24:programOffset+32], virtualAddress)
	binary.LittleEndian.PutUint64(data[programOffset+32:programOffset+40], 4)
	binary.LittleEndian.PutUint64(data[programOffset+40:programOffset+48], 4)
	binary.LittleEndian.PutUint64(data[programOffset+48:programOffset+56], 1)
	if machine == elf.EM_AARCH64 {
		binary.LittleEndian.PutUint32(data[segmentOffset:], 0xd65f03c0)
	} else {
		data[segmentOffset] = 0xc3
	}
	return data
}

func testTSNodeNATSIdentity(t *testing.T, caKey ed25519.PrivateKey, caPEM []byte) *TSNodeNATSIdentity {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, ed25519.SeedSize))
	uri, _ := url.Parse("spiffe://vmqual.terrascale.test/test-run/ts-node/gru-member-1")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.FromRawSeed(nkeys.PrefixByteUser, bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return &TSNodeNATSIdentity{NKeySeed: append([]byte(nil), seed...), TLSCA: caPEM, TLSCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), TLSPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func TestNoCloudNATSIdentityIsPrivateAndBoundToGuest(t *testing.T) {
	spec := validNoCloudSpec(t)
	seed, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{spec.TSNode.NATSIdentity.NKeySeed, spec.TSNode.NATSIdentity.TLSPrivateKey} {
		for _, evidence := range [][]byte{seed.UserData, seed.MetaData, seed.NetworkConfig, spec.GuestSeed} {
			if bytes.Contains(evidence, secret) || bytes.Contains(evidence, []byte(base64.StdEncoding.EncodeToString(secret))) {
				t.Fatal("private identity entered cloud-init or guest evidence")
			}
		}
	}
	for _, file := range seed.RootFiles[2:6] {
		if file.Mode != 0600 || file.Validate() != nil {
			t.Fatal("credential file lacks fixed private admission")
		}
		file.Mode = 0644
		if file.Validate() == nil {
			t.Fatal("public credential file accepted")
		}
	}
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	var config tsNodeConfigurationFile
	if err := json.Unmarshal(material.config, &config); err != nil {
		t.Fatal(err)
	}
	if config.NATSNKeyFile != tsNodeNKeyPath || config.NATSTLSCAFile != tsNodeTLSCAPath || config.NATSTLSCertFile != tsNodeTLSCertPath || config.NATSTLSKeyFile != tsNodeTLSKeyPath {
		t.Fatal("ts-node did not receive private identity file paths")
	}
	spec.TSNode.NATSIdentity.NKeySeed[0] ^= 1
	if bytes.Equal(seed.RootFiles[2].Content, spec.TSNode.NATSIdentity.NKeySeed) {
		t.Fatal("seed retains caller-owned secret bytes")
	}
}

func TestNoCloudRejectsMissingOrMismatchedNATSIdentity(t *testing.T) {
	for _, kind := range []string{"missing", "partial", "key-mismatch", "ca-mismatch", "oversize", "wrong-node", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			spec := validNoCloudSpec(t)
			switch kind {
			case "missing":
				spec.TSNode.NATSIdentity = nil
			case "partial":
				spec.TSNode.NATSIdentity.TLSCA = nil
			case "key-mismatch":
				spec.TSNode.NATSIdentity.TLSPrivateKey = []byte("PRIVATE_CANARY")
			case "ca-mismatch":
				spec.TSNode.NATSIdentity.TLSCA = testCACertificate(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x88}, 32)))
			case "oversize":
				spec.TSNode.NATSIdentity.NKeySeed = bytes.Repeat([]byte("PRIVATE_CANARY"), 65536)
			case "wrong-node":
				spec.TSNode.Config.NodeID = "another-node"
			case "plaintext":
				spec.TSNode.Config.NATSURL = "nats://10.77.0.1:4222"
			}
			if _, err := BuildNoCloudSeed(spec); err == nil || strings.Contains(err.Error(), "PRIVATE_CANARY") {
				t.Fatalf("identity rejection: %v", err)
			}
		})
	}
}

func mustDecodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
