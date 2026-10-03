package deploy_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type netbirdArchive struct {
	URL          string `json:"url"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	BinarySHA256 string `json:"binary_sha256"`
}
type netbirdPin struct {
	Version  string `json:"version"`
	Archives struct {
		Arm64 netbirdArchive `json:"arm64"`
		AMD64 netbirdArchive `json:"amd64"`
	} `json:"archives"`
	Enrollment jsontext.Value `json:"enrollment_config"`
}
type netbirdFixture struct {
	t                            *testing.T
	root, archive, output, cache string
	binary                       []byte
	pin                          netbirdPin
}

func elf(architecture, body string) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	machine := uint16(183)
	if architecture == "amd64" {
		machine = 62
	}
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	return append(b, body...)
}
func newNetbird(t *testing.T) *netbirdFixture {
	t.Helper()
	dir := t.TempDir()
	f := &netbirdFixture{t: t, root: dir, archive: filepath.Join(dir, "upstream.tar.gz"), output: filepath.Join(dir, "result/netbird"), cache: filepath.Join(dir, "cache"), binary: elf("arm64", "test NetBird")}
	var inputs struct {
		Netbird netbirdPin `json:"netbird"`
	}
	if err := json.Unmarshal(read(t, filepath.Join(deployRoot(t), "deploy/image/image-inputs.json")), &inputs); err != nil {
		t.Fatal(err)
	}
	f.pin = inputs.Netbird
	f.makeArchive(tar.TypeReg, false)
	return f
}
func (f *netbirdFixture) makeArchive(kind byte, duplicate bool) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	add := func(name string, kind byte, data []byte, link string) {
		f.t.Helper()
		h := &tar.Header{Name: name, Typeflag: kind, Mode: 0644, Size: int64(len(data)), Linkname: link}
		if err := tw.WriteHeader(h); err != nil {
			f.t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			f.t.Fatal(err)
		}
	}
	add("../../escape", tar.TypeReg, []byte("evil"), "")
	data := f.binary
	link := ""
	if kind != tar.TypeReg {
		data = nil
		link = "../../escape"
	}
	add("netbird", kind, data, link)
	if duplicate {
		add("netbird", kind, f.binary, link)
	}
	if err := tw.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		f.t.Fatal(err)
	}
	write(f.t, f.archive, b.Bytes(), 0600)
	f.pin.Archives.Arm64.Bytes = int64(b.Len())
	f.pin.Archives.Arm64.SHA256 = digest(b.Bytes())
	f.pin.Archives.Arm64.BinarySHA256 = digest(f.binary)
}

type roundTripper func(*http.Request) (*http.Response, error)

func (r roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return r(request) }
func (f *netbirdFixture) invoke(args map[string]any) map[string]any {
	f.t.Helper()
	calls := []any{}
	transport := roundTripper(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.String())
		if args["forbid_download"] == true {
			return nil, errors.New("unexpected download")
		}
		payload := read(f.t, args["payload"].(string))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(payload)), Header: make(http.Header)}, nil
	})
	var err error
	if args["operation"] == "fetch" {
		var pin client.Pin
		if err = json.Unmarshal(jsonBytes(f.t, args["pin"]), &pin); err != nil {
			f.t.Fatal(err)
		}
		cache, _ := args["cache"].(string)
		err = client.Fetch(f.t.Context(), pin, args["architecture"].(string), args["output"].(string), cache, &http.Client{Transport: transport})
	} else {
		var pin client.Archive
		if err = json.Unmarshal(jsonBytes(f.t, args["archive_pin"]), &pin); err != nil {
			f.t.Fatal(err)
		}
		err = client.Extract(args["archive"].(string), args["output"].(string), pin, args["architecture"].(string))
	}
	result := map[string]any{"calls": calls, "error": nil}
	if err != nil {
		result["error"] = map[string]any{"message": err.Error()}
	}
	return result
}
func (f *netbirdFixture) fetch(payload string, cache bool, forbid bool) map[string]any {
	args := map[string]any{"operation": "fetch", "pin": f.pin, "architecture": "arm64", "output": f.output, "payload": payload, "forbid_download": forbid}
	if cache {
		args["cache"] = f.cache
	}
	return f.invoke(args)
}
func noNetbirdError(t *testing.T, r map[string]any) { t.Helper(); equal(t, r["error"], nil) }
func netbirdError(t *testing.T, r map[string]any, message string) {
	t.Helper()
	e, ok := r["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected ValueError, got %#v", r)
	}

	contains(t, e["message"].(string), message)
}
func TestNetbirdFetchChecksArchiveAndInstallsOnlyBinary(t *testing.T) {
	f := newNetbird(t)
	r := f.fetch(f.archive, true, false)
	noNetbirdError(t, r)
	equal(t, len(r["calls"].([]any)), 1)
	equal(t, read(t, f.output), f.binary)
	equal(t, mode(t, f.output), os.FileMode(0755))
	absent(t, filepath.Join(f.root, "escape"))
	equal(t, read(t, filepath.Join(f.cache, f.pin.Archives.Arm64.SHA256)), read(t, f.archive))
}
func TestNetbirdVerifiedCacheReusesDownloadAndRechecksBytes(t *testing.T) {
	f := newNetbird(t)
	cached := filepath.Join(f.cache, f.pin.Archives.Arm64.SHA256)
	write(t, cached, read(t, f.archive), 0600)
	r := f.fetch(f.archive, true, true)
	noNetbirdError(t, r)
	equal(t, len(r["calls"].([]any)), 0)
	write(t, cached, []byte("corrupt cached archive"), 0600)
	r = f.fetch(f.archive, true, false)
	noNetbirdError(t, r)
	equal(t, len(r["calls"].([]any)), 1)
	equal(t, read(t, f.output), f.binary)
}
func TestNetbirdWrongArchiveDigestPreservesExistingClient(t *testing.T) {
	f := newNetbird(t)
	write(t, f.output, []byte("existing client"), 0600)
	b := read(t, f.archive)
	b[len(b)-1] ^= 1
	payload := filepath.Join(f.root, "corrupt")
	write(t, payload, b, 0600)
	r := f.fetch(payload, true, false)
	netbirdError(t, r, "pinned SHA-256")
	equal(t, read(t, f.output), []byte("existing client"))
	absent(t, f.cache)
}
func TestNetbirdRejectsArchiveLinksAndDuplicateBinaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      byte
		duplicate bool
	}{{"symlink", tar.TypeSymlink, false}, {"hardlink", tar.TypeLink, false}, {"duplicate", tar.TypeReg, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNetbird(t)
			f.makeArchive(tc.kind, tc.duplicate)
			netbirdError(t, f.fetch(f.archive, false, false), "one regular root-level")
			absent(t, f.output)
		})
	}
}
func TestNetbirdChecksExtractedDigestAndArchitecture(t *testing.T) {
	for _, tc := range []struct {
		name, architecture, message string
		badDigest                   bool
	}{{"digest", "arm64", "pinned SHA-256", true}, {"architecture", "amd64", "amd64 executable", false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNetbird(t)
			pin := f.pin.Archives.Arm64
			if tc.badDigest {
				pin.BinarySHA256 = strings.Repeat("0", 64)
			}
			netbirdError(t, f.invoke(map[string]any{"operation": "extract", "archive": f.archive, "output": filepath.Join(f.root, "binary"), "archive_pin": pin, "architecture": tc.architecture}), tc.message)
		})
	}
}
func validNetbirdConfig() map[string]any {
	return map[string]any{"management_url": "https://netbird.terrascale.tech", "management_ip": "10.250.10.155", "region": "sa-saopaulo-1", "setup_key_secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test"}
}
func TestNetbirdAdditiveInstallerPreservesOrchestrator(t *testing.T) {
	f := newNetbird(t)
	stage := filepath.Join(f.root, "server")
	oldBinary := filepath.Join(stage, "usr/local/bin/terrascale-orchestrator")
	oldConfig := filepath.Join(stage, "etc/terrascale-orchestrator/controller.json")
	write(t, oldBinary, []byte("currently running orchestrator"), 0600)
	write(t, oldConfig, []byte("existing controller configuration"), 0600)
	if err := os.Chmod(filepath.Dir(oldConfig), 0700); err != nil {
		t.Fatal(err)
	}
	client, enroll, config, inputs := filepath.Join(f.root, "client"), filepath.Join(f.root, "enroll"), filepath.Join(f.root, "netbird.json"), filepath.Join(f.root, "inputs.json")
	write(t, client, f.binary, 0600)
	enrollment := elf("arm64", "new enrollment command")
	write(t, enroll, enrollment, 0600)
	write(t, config, jsonBytes(t, validNetbirdConfig()), 0600)
	write(t, inputs, jsonBytes(t, struct {
		Netbird netbirdPin `json:"netbird"`
	}{f.pin}), 0600)
	successful(t, runTool(t, "netbird", "install", "--root", stage, "--architecture", "arm64", "--inputs", inputs, "--client-binary", client, "--enroll-binary", enroll, "--enroll-sha256", digest(enrollment), "--config", config))
	equal(t, read(t, oldBinary), []byte("currently running orchestrator"))
	equal(t, read(t, oldConfig), []byte("existing controller configuration"))
	equal(t, mode(t, filepath.Dir(oldConfig)), os.FileMode(0700))
	equal(t, read(t, filepath.Join(stage, "usr/local/bin/netbird")), f.binary)
	equal(t, read(t, filepath.Join(stage, "usr/local/lib/terrascale-orchestrator/netbird-enroll")), enrollment)
	for _, name := range []string{"netbird.service", "terrascale-netbird-enroll.service"} {
		symlink(t, filepath.Join(stage, "etc/systemd/system/multi-user.target.wants", name))
	}
	contains(t, string(read(t, filepath.Join(stage, "etc/systemd/system/terrascale-netbird-enroll.service.d/command.conf"))), "/usr/local/lib/terrascale-orchestrator/netbird-enroll netbird-enroll")
	equal(t, mode(t, filepath.Join(stage, "var/lib/netbird")), os.FileMode(0700))
}
func TestNetbirdUnitsRetryWithoutGatingOrchestrator(t *testing.T) {
	daemon := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/netbird.service")))
	enrollment := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-netbird-enroll.service")))
	for _, want := range []string{"service run --config /var/lib/netbird/config.json --log-file console", "StateDirectoryMode=0700", "KillMode=process",
		"\nEnvironment=NB_FORCE_RELAY=true\n", "\nEnvironment=NB_LAZY_CONN=on\n"} {
		contains(t, daemon, want)
	}
	// Only connectivity tuning belongs in the daemon environment: a manager,
	// setup key or relay override there would bypass enrollment's checks.
	for line := range strings.SplitSeq(daemon, "\n") {
		if strings.HasPrefix(line, "Environment") && line != "Environment=NB_FORCE_RELAY=true" && line != "Environment=NB_LAZY_CONN=on" {
			t.Errorf("unexpected NetBird daemon environment: %s", line)
		}
	}
	for _, confinement := range []string{"CapabilityBoundingSet", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "RestrictSUIDSGID", "DevicePolicy"} {
		if strings.Contains(daemon, confinement) {
			t.Errorf("NetBird SSH sessions need an unconfined daemon: %s", confinement)
		}
	}
	for _, want := range []string{"Restart=on-failure", "\nRestartSec=5s\n", "StartLimitIntervalSec=0", "TimeoutStartSec=180s", "ConditionPathExists=/etc/terrascale-orchestrator/netbird.json", "UnsetEnvironment=OCI_GO_SDK_DEBUG",
		"\nWants=network-online.target netbird.service systemd-time-wait-sync.service\n", "\nAfter=network-online.target netbird.service systemd-time-wait-sync.service\n"} {
		contains(t, enrollment, want)
	}
	for _, role := range []string{"controller", "host"} {
		unit := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-"+role+".service")))
		if strings.Contains(unit, "netbird") {
			t.Fatalf("%s startup depends on netbird", role)
		}
	}
}
func TestNetbirdPublicConfigRejectsForeignOriginAddressOrSecretRegion(t *testing.T) {
	for _, tc := range []struct{ field, value string }{{"management_url", "https://other.example"}, {"management_ip", "8.8.8.8"}, {"management_ip", "127.0.0.1"}, {"management_ip", "::ffff:10.250.10.155"}, {"setup_key_secret_id", "ocid1.vaultsecret.oc1.us-ashburn-1.test"}, {"setup_key_secret_id", "REQUIRED_SECRET_OCID"}} {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			config := validNetbirdConfig()
			config[tc.field] = tc.value
			write(t, path, jsonBytes(t, config), 0600)

			_, err := client.ValidateConfig(path)
			if err == nil {
				t.Fatal("accepted invalid public enrollment configuration")
			}

			message := map[string]string{
				"management_url":      "management_url must be https://netbird.terrascale.tech",
				"management_ip":       "management_ip must be a private IPv4 or IPv6 address",
				"setup_key_secret_id": "setup_key_secret_id must identify an OCI Vault secret in the configured region",
			}[tc.field]
			contains(t, err.Error(), message)
		})
	}
}

func TestNetbirdCacheSymlinkIsReplacedWithoutFollowingIt(t *testing.T) {
	f := newNetbird(t)
	outside := filepath.Join(f.root, "outside.tar.gz")
	original := read(t, f.archive)
	write(t, outside, original, 0600)
	if err := os.MkdirAll(f.cache, 0755); err != nil {
		t.Fatal(err)
	}
	cached := filepath.Join(f.cache, f.pin.Archives.Arm64.SHA256)
	if err := os.Symlink(outside, cached); err != nil {
		t.Fatal(err)
	}
	r := f.fetch(f.archive, true, false)
	noNetbirdError(t, r)
	equal(t, len(r["calls"].([]any)), 1)
	equal(t, read(t, outside), original)
	info, err := os.Lstat(cached)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, info.Mode().IsRegular(), true)
	equal(t, read(t, f.output), f.binary)
}

func TestNetbirdCancelledFetchPreservesExistingClient(t *testing.T) {
	f := newNetbird(t)
	write(t, f.output, []byte("existing client"), 0600)
	var pin client.Pin
	if err := json.Unmarshal(jsonBytes(t, f.pin), &pin); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	transport := roundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("cancelled fetch started a download")
		return nil, nil
	})
	err := client.Fetch(ctx, pin, "arm64", f.output, f.cache, &http.Client{Transport: transport})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want cancellation", err)
	}
	equal(t, read(t, f.output), []byte("existing client"))
	absent(t, f.cache)
}

func TestNetbirdPublicConfigRejectsInvalidPeerNames(t *testing.T) {
	for name, names := range map[string]map[string]string{
		"public address": {"8.8.8.8": "gru-controller-a"},
		"invalid label":  {"10.251.0.11": "GRU_controller_a"},
		"duplicate name": {"10.251.0.11": "gru-controller-a", "10.251.0.12": "gru-controller-a"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			config := validNetbirdConfig()
			config["peer_names"] = names
			write(t, path, jsonBytes(t, config), 0600)
			if _, err := client.ValidateConfig(path); err == nil || !strings.Contains(err.Error(), "peer_names") {
				t.Fatalf("accepted invalid peer names: %v", err)
			}
		})
	}
}

func TestGRUNetbirdInputNamesEveryCellSlotStably(t *testing.T) {
	config, err := client.ValidateConfig(filepath.Join(deployRoot(t), "deploy/image/inputs/netbird-gru.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Hosts []struct {
			Slot      string `json:"slot"`
			PrivateIP string `json:"private_ip"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(read(t, filepath.Join(deployRoot(t), "deploy/oci-region/plan.json")), &plan); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"controller-a": "gru-controller-a", "controller-b": "gru-controller-b",
		"controller-c": "gru-controller-c", "member-a": "gru-member-1", "member-b": "gru-member-2"}
	if len(plan.Hosts) != len(want) || len(config.PeerNames) != len(want) {
		t.Fatalf("plan slots %d and peer names %d differ from %d", len(plan.Hosts), len(config.PeerNames), len(want))
	}
	for _, host := range plan.Hosts {
		if got := config.PeerNames[host.PrivateIP]; got != want[host.Slot] {
			t.Errorf("slot %s at %s is named %q, want %q", host.Slot, host.PrivateIP, got, want[host.Slot])
		}
	}
}

func TestNetbirdPublicConfigAdminPATSecretMustBeInRegion(t *testing.T) {
	// An empty or null ID means absent, matching netbird.Config.
	for _, tc := range []struct {
		id   any
		ok   bool
		want string
	}{
		{"ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat", true, "ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat"},
		{"ocid1.vaultsecret.oc1.us-ashburn-1.adminpat", false, ""},
		{"not-an-ocid", false, ""},
		{"", true, ""},
		{nil, true, ""},
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		config := validNetbirdConfig()
		config["admin_pat_secret_id"] = tc.id
		write(t, path, jsonBytes(t, config), 0600)
		parsed, err := client.ValidateConfig(path)
		if tc.ok != (err == nil) || tc.ok && parsed.AdminPATSecretID != tc.want {
			t.Fatalf("admin PAT secret %v: %+v %v", tc.id, parsed, err)
		}
	}
}
