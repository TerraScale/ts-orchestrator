//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

// TestTerraBaseDataVolumeNeverFormatsExistingData formats only a device
// without any filesystem identity or signature whose sampled blocks are all
// zero; it mounts one clean ext4 filesystem and holds everything else.
func TestTerraBaseDataVolumeNeverFormatsExistingData(t *testing.T) {
	const uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
	for _, tc := range []struct {
		name  string
		probe volumeFilesystemProbe
		want  volumeInitAction
	}{
		{"mounted", volumeFilesystemProbe{Mounted: true, BlankSample: true}, volumeInitHold},
		{"mounted ext4", volumeFilesystemProbe{Mounted: true, FSUUID: uuid, FSType: "ext4", Signatures: true}, volumeInitHold},
		{"ext4", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true}, volumeInitMount},
		{"ext4 blank sample", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true, BlankSample: true}, volumeInitMount},
		{"ext4 with foreign signatures", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true, ForeignSignatures: true}, volumeInitHold},
		{"ext4 without signatures", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4"}, volumeInitHold},
		{"ext4 without uuid", volumeFilesystemProbe{FSType: "ext4", Signatures: true}, volumeInitHold},
		{"xfs", volumeFilesystemProbe{FSUUID: uuid, FSType: "xfs", Signatures: true}, volumeInitHold},
		{"luks", volumeFilesystemProbe{FSUUID: uuid, FSType: "crypto_LUKS", Signatures: true}, volumeInitHold},
		{"uuid without type", volumeFilesystemProbe{FSUUID: uuid, Signatures: true, BlankSample: true}, volumeInitHold},
		{"signatures without type", volumeFilesystemProbe{Signatures: true, BlankSample: true}, volumeInitHold},
		{"non-zero sampled data", volumeFilesystemProbe{}, volumeInitHold},
		{"foreign signatures only", volumeFilesystemProbe{ForeignSignatures: true, BlankSample: true}, volumeInitHold},
		{"blank", volumeFilesystemProbe{BlankSample: true}, volumeInitFormat},
	} {
		action, err := terraBaseVolumeAction(tc.probe)
		if action != tc.want {
			t.Errorf("%s: action %d, want %d", tc.name, action, tc.want)
		}
		if (action == volumeInitHold) != (err != nil) {
			t.Errorf("%s: action %d with error %v", tc.name, action, err)
		}
	}
}

func TestTerraBaseDataVolumeFstab(t *testing.T) {
	const (
		uuid   = "0f8fad5b-d9cb-469f-a165-70867728950e"
		target = "/srv/ts-managed/terrabase/data"
		entry  = "UUID=" + uuid + " " + target + " ext4 nosuid,nodev,noexec,noatime,errors=remount-ro,nofail," +
			"x-systemd.device-timeout=30s,x-systemd.before=terrascale-orchestrator-host.service 0 2\n"
	)
	kept := "# /etc/fstab: static file system information.\n" +
		"UUID=11111111-2222-4333-8444-555555555555 / ext4 defaults 0 1\n" +
		"#UUID=0f8fad5b-d9cb-469f-a165-70867728950e " + target + " ext4 defaults 0 2\n" +
		"# /dev/sdc " + target + " xfs defaults 0 0\n" +
		"\n" +
		"/dev/sda15 /boot/efi vfat umask=0077 0 1\n"
	for _, tc := range []struct{ name, existing, want string }{
		{"missing", "", entry},
		{"other lines", kept, kept + entry},
		{"no trailing newline", "proc /proc proc defaults 0 0", "proc /proc proc defaults 0 0\n" + entry},
		{"old uuid", kept + "UUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee " + target + " ext4 defaults 0 2\n", kept + entry},
		{"device path in the middle", "/dev/sdb " + target + " ext4 defaults 0 2\n" + kept, kept + entry},
		{"indented and tabbed", kept + "  /dev/sdb\t" + target + "\text4 defaults 0 2", kept + entry},
		{"duplicates", entry + kept + entry, kept + entry},
		{"trailing slash", kept + "/dev/sdb " + target + "/ ext4 defaults 0 2\n", kept + entry},
	} {
		got, err := terraBaseFstab([]byte(tc.existing), uuid, target)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
		again, err := terraBaseFstab(got, uuid, target)
		if err != nil || !bytes.Equal(again, got) {
			t.Errorf("%s: second pass changed fstab to %q (%v)", tc.name, again, err)
		}
	}
	for _, bad := range []string{"", "0F8FAD5B-D9CB-469F-A165-70867728950E", "0f8fad5bd9cb469fa16570867728950e", "0f8fad5b-d9cb-469f-a165-70867728950", "not-a-uuid"} {
		if _, err := terraBaseFstab([]byte(kept), bad, target); err == nil {
			t.Errorf("uuid %q accepted", bad)
		}
	}
	for _, bad := range []string{"", "/", "srv/data", "/srv//data", "/srv/data/", "/srv/../data", "/srv/my data", "/srv/my\tdata", "/srv/#data", `/srv/back\slash`, "/srv/new\nline"} {
		if _, err := terraBaseFstab([]byte(kept), uuid, bad); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
}

func TestTerraBaseDataVolumeWriteFstab(t *testing.T) {
	const (
		uuid   = "0f8fad5b-d9cb-469f-a165-70867728950e"
		target = "/srv/ts-managed/terrabase/data"
	)
	path := filepath.Join(t.TempDir(), "fstab")
	if err := writeTerraBaseFstab(path, uuid, target); err != nil {
		t.Fatal(err)
	}
	created, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("created fstab mode: %v %v", info.Mode(), err)
	}
	if want, _ := terraBaseFstab(nil, uuid, target); !bytes.Equal(created, want) {
		t.Fatalf("created fstab %q, want %q", created, want)
	}

	root := "UUID=11111111-2222-4333-8444-555555555555 / ext4 defaults 0 1\n"
	if err := os.WriteFile(path, []byte(root+"/dev/sdb "+target+" ext4 defaults 0 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeTerraBaseFstab(path, uuid, target); err != nil {
		t.Fatal(err)
	}
	rewritten, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := terraBaseFstab([]byte(root), uuid, target); !bytes.Equal(rewritten, want) {
		t.Fatalf("rewritten fstab %q, want %q", rewritten, want)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("rewritten fstab mode: %v %v", info.Mode(), err)
	}
	if err := writeTerraBaseFstab(path, uuid, target); err != nil {
		t.Fatal(err)
	}
	if again, err := os.ReadFile(path); err != nil || !bytes.Equal(again, rewritten) {
		t.Fatalf("second write changed fstab to %q (%v)", again, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files left beside fstab: %v %v", entries, err)
	}
	if err := writeTerraBaseFstab(path, "INVALID", target); err == nil {
		t.Fatal("invalid uuid written")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, rewritten) {
		t.Fatalf("rejected entry changed fstab to %q", after)
	}
}

// TestTerraBaseDataVolumeEmptyMountTarget never mounts over boot disk files.
func TestTerraBaseDataVolumeEmptyMountTarget(t *testing.T) {
	base := t.TempDir()
	missing := filepath.Join(base, "missing")
	// The target ends root-owned, so only root can accept one; every
	// refusal below holds for any user.
	if os.Geteuid() == 0 {
		if err := emptyMountTarget(missing); err != nil {
			t.Fatal(err)
		}
		requireOwned(t, missing, 0, 0o700)
		if err := emptyMountTarget(missing); err != nil {
			t.Fatalf("existing empty directory: %v", err)
		}
	} else if err := os.Mkdir(missing, 0o700); err != nil {
		t.Fatal(err)
	}

	full := filepath.Join(base, "full")
	if err := os.Mkdir(full, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, ".hidden"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := emptyMountTarget(full); err == nil {
		t.Fatal("accepted a directory holding a file")
	}
	nested := filepath.Join(base, "nested")
	if err := os.MkdirAll(filepath.Join(nested, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := emptyMountTarget(nested); err == nil {
		t.Fatal("accepted a directory holding a directory")
	}

	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := emptyMountTarget(file); err == nil {
		t.Fatal("accepted a regular file")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(base, "dangling")
	if err := os.Symlink(filepath.Join(base, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dangling} {
		if err := emptyMountTarget(path); err == nil {
			t.Errorf("accepted symlink %s", path)
		}
	}
	if _, err := os.Lstat(filepath.Join(base, "nowhere")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created the target of a dangling symlink: %v", err)
	}
}

func TestTerraBaseDataVolumeFilesystemUUID(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		uuid, err := newFilesystemUUID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[uuid] {
			t.Fatalf("repeated uuid %s", uuid)
		}
		seen[uuid] = true
		if !hostvolume.ValidUUID(uuid) {
			t.Fatalf("invalid uuid %s", uuid)
		}
		if _, _, err := hostvolume.FormatCommand("ext4", uuid); err != nil {
			t.Fatalf("format refused uuid %s: %v", uuid, err)
		}
		if uuid[14] != '4' || !strings.ContainsRune("89ab", rune(uuid[19])) {
			t.Fatalf("uuid %s is not a version 4, RFC 4122 variant", uuid)
		}
	}
}

func TestTerraBaseDataVolumeExchangeFraming(t *testing.T) {
	serve := func(answer func(net.Conn)) (net.Conn, <-chan []byte) {
		agent, initializer := net.Pipe()
		t.Cleanup(func() { agent.Close() })
		received := make(chan []byte, 1)
		go func() {
			defer initializer.Close()
			var size [4]byte
			if _, err := io.ReadFull(initializer, size[:]); err != nil {
				received <- nil
				return
			}
			wire := make([]byte, binary.BigEndian.Uint32(size[:]))
			if _, err := io.ReadFull(initializer, wire); err != nil {
				received <- nil
				return
			}
			received <- wire
			answer(initializer)
		}()
		return agent, received
	}
	for _, tc := range []struct {
		name   string
		answer func(net.Conn)
		ok     bool
	}{
		{"success", func(c net.Conn) { c.Write([]byte{0}) }, true},
		{"refused", func(c net.Conn) { c.Write([]byte{1}) }, false},
		{"closed", func(net.Conn) {}, false},
	} {
		connection, received := serve(tc.answer)
		err := exchangeVolumeInit(connection, terraBaseDataRequest)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
		if wire := <-received; !bytes.Equal(wire, terraBaseDataRequest) {
			t.Errorf("%s: initializer read %q", tc.name, wire)
		}
	}
}

// TestTerraBaseDataVolumeAgentFailsClosed keeps a member stopped, and its
// data directory uncreated on the boot disk, while the data volume is not
// the verified mount.
func TestTerraBaseDataVolumeAgentFailsClosed(t *testing.T) {
	identity := WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if err := verifyTerraBaseDataMount(t.TempDir(), identity); err == nil {
		t.Fatal("a boot disk directory verified as the data volume")
	}
	socketDir, err := os.MkdirTemp("", "tbv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	absent := filepath.Join(socketDir, "absent.sock")
	if err := requestTerraBaseDataVolume(t.Context(), absent, nil); err == nil {
		t.Fatal("request without an initializer succeeded")
	}

	// An initializer that refuses: the agent sends the fixed request and
	// reports the failure.
	refusing := filepath.Join(socketDir, "refusing.sock")
	listener, err := net.Listen("unix", refusing)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	received := make(chan []byte, 2)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			var size [4]byte
			wire := []byte(nil)
			if _, err := io.ReadFull(connection, size[:]); err == nil {
				wire = make([]byte, binary.BigEndian.Uint32(size[:]))
				_, _ = io.ReadFull(connection, wire)
			}
			received <- wire
			connection.Write([]byte{1})
			connection.Close()
		}
	}()
	if err := requestTerraBaseDataVolume(t.Context(), refusing, nil); err == nil {
		t.Fatal("refused request succeeded")
	}
	if wire := <-received; !bytes.Equal(wire, terraBaseDataRequest) {
		t.Fatalf("initializer read %q", wire)
	}

	root := filepath.Join(traversableTempDir(t), "terrabase")
	agentIdentity := testAgentIdentity()
	agent := &Agent{terraBase: map[string]terraBaseMember{}, runner: &memoryRunner{observed: make(map[string]Observation)},
		cfg: AgentConfig{Node: "gru-1-db-1", TerraBaseRoot: root,
			InstallRoot: "/var/lib/host/install", StateRoot: "/var/lib/host/state", WorkloadIdentity: agentIdentity,
			TerraBaseDataVolume: true, VolumeInitSocket: refusing}}
	d := Desired{Role: terrabase.Role, Env: map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.0.0.1:9443"}}
	if _, _, err := agent.prepareTerraBase(t.Context(), d); err == nil || !strings.Contains(err.Error(), "data volume") {
		t.Fatalf("prepared a member without its data volume: %v", err)
	}
	if wire := <-received; !bytes.Equal(wire, terraBaseDataRequest) {
		t.Fatalf("agent sent %q", wire)
	}
	layout := terrabase.Layout(root)
	if _, err := os.Lstat(layout.Data()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("data directory created on the boot disk: %v", err)
	}
	if _, err := os.Lstat(layout.Key()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("member key written before the data volume was verified: %v", err)
	}
	if !agent.terraBaseVolumeChecked.IsZero() {
		t.Fatal("a failed mount was recorded as checked")
	}
	agent.cfg.VolumeInitSocket = absent
	if _, _, err := agent.prepareTerraBase(t.Context(), d); err == nil {
		t.Fatal("prepared a member without a volume initializer")
	}
}

func TestTerraBaseDataVolumeNeedsTerraBaseRoot(t *testing.T) {
	_, identity, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	controller, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := func(root string) AgentConfig {
		return AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil },
			WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production",
			Roles: []string{"terrabase"}, Conn: &nats.Conn{}, Identity: identity, ControllerPublicKey: controller,
			Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t),
			StateRoot: testAgentStateRoot(t), TerraBaseRoot: root, TerraBaseDataVolume: true,
			TerraBaseDataVolumeID: "ocid1.volume.oc1..first"}
	}
	if _, err := NewAgent(config("")); err == nil || !strings.Contains(err.Error(), "terrabase root") {
		t.Fatalf("data volume without a terrabase root: %v", err)
	}
	if _, err := NewAgent(config(filepath.Join(traversableTempDir(t), "terrabase"))); err != nil {
		t.Fatalf("data volume with a terrabase root: %v", err)
	}
	missingID := config(filepath.Join(traversableTempDir(t), "terrabase"))
	missingID.TerraBaseDataVolumeID = ""
	if _, err := NewAgent(missingID); err == nil || !strings.Contains(err.Error(), "volume OCID") {
		t.Fatalf("data volume without its recorded OCID: %v", err)
	}
}

// TestEnsureOwnedDirWithoutFowner prepares a workload directory the way the
// host unit runs the agent: root without CAP_FOWNER, which cannot chmod a
// directory the workload already owns.
func TestEnsureOwnedDirWithoutFowner(t *testing.T) {
	dir := workloadOwnedDir(t, 0o755)
	if err := withCapabilities(t, []uint{unix.CAP_CHOWN, unix.CAP_DAC_READ_SEARCH, unix.CAP_KILL, unix.CAP_SETGID, unix.CAP_SETUID, unix.CAP_SETPCAP},
		func() error { return ensureOwnedDir(dir, 2000, 2000, 0o700) }); err != nil {
		t.Fatalf("prepare a workload-owned directory without CAP_FOWNER: %v", err)
	}
	requireOwned(t, dir, 2000, 0o700)
}

// TestTerraBaseDataVolumeRootWithInitializerCapabilities owns and reopens
// the workload's 0700 volume root with exactly the initializer unit's
// capabilities; without CAP_DAC_READ_SEARCH root cannot open it at all.
func TestTerraBaseDataVolumeRootWithInitializerCapabilities(t *testing.T) {
	dir := workloadOwnedDir(t, 0o755)
	var stat unix.Stat_t
	if err := unix.Stat(dir, &stat); err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{UID: 2000, GID: 2000}
	initializer := []uint{unix.CAP_SYS_ADMIN, unix.CAP_CHOWN, unix.CAP_SYS_RESOURCE, unix.CAP_DAC_READ_SEARCH}
	for range 2 { // the second pass is the maintenance of an owned root
		if err := withCapabilities(t, initializer, func() error { return ownTerraBaseDataRoot(dir, stat.Dev, identity) }); err != nil {
			t.Fatalf("own the data volume root: %v", err)
		}
		requireOwned(t, dir, 2000, 0o700)
	}
	if err := withCapabilities(t, []uint{unix.CAP_SYS_ADMIN, unix.CAP_CHOWN, unix.CAP_SYS_RESOURCE},
		func() error { return ownTerraBaseDataRoot(dir, stat.Dev, identity) }); !errors.Is(err, unix.EACCES) {
		t.Fatalf("opened the workload-owned root without CAP_DAC_READ_SEARCH: %v", err)
	}
	// A workload-owned empty mount point left on the boot disk is taken
	// back: after an unmount the workload cannot write below it.
	target := workloadOwnedDir(t, 0o700)
	if err := withCapabilities(t, initializer, func() error { return emptyMountTarget(target) }); err != nil {
		t.Fatalf("take back the mount point: %v", err)
	}
	requireOwned(t, target, 0, 0o700)
}

func workloadOwnedDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to own a directory as another user")
	}
	dir := filepath.Join(t.TempDir(), "owned")
	if err := os.Mkdir(dir, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 2000, 2000); err != nil {
		t.Fatal(err)
	}
	return dir
}

// withCapabilities runs fn on a thread whose effective and permitted
// capabilities are only keep. The thread is never unlocked, so the runtime
// discards it with its reduced capabilities when fn returns.
func withCapabilities(t *testing.T, keep []uint, fn func() error) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		var mask [2]uint32
		for _, capability := range keep {
			mask[capability/32] |= 1 << (capability % 32)
		}
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		data := [2]unix.CapUserData{{Effective: mask[0], Permitted: mask[0]}, {Effective: mask[1], Permitted: mask[1]}}
		if err := unix.Capset(&header, &data[0]); err != nil {
			result <- err
			return
		}
		result <- fn()
	}()
	return <-result
}

func requireOwned(t *testing.T, dir string, id uint32, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if owner.Uid != id || owner.Gid != id || info.Mode().Perm() != mode {
		t.Fatalf("%s is %d:%d %v, want %d:%d %v", dir, owner.Uid, owner.Gid, info.Mode().Perm(), id, id, mode)
	}
}

// The pending grant can be redelivered only to the original initializer and
// host registration; replacement hosts learn the UUID without format authority.
func TestTerraBaseDataVolumeFirstFormatIsFenced(t *testing.T) {
	c, _, _, _, _ := testController(t)
	member := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
		TerraBaseDataVolumeID: "ocid1.volume.oc1..first"}
	ask := func(r Registration, attempt string) (terraBaseFormatReply, error) {
		payload, _ := protocol.EncodeJSON(terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, AttemptID: attempt})
		reply, err := c.serveTerraBaseFormat(t.Context(), request{Node: r.Node, Payload: payload}, r)
		if err != nil {
			return terraBaseFormatReply{}, err
		}
		return reply.(terraBaseFormatReply), nil
	}
	const attempt = "014D2PF2DBSQQG28T5CY4TQKFF"
	first, err := ask(member, attempt)
	if err != nil || !first.Granted || !hostvolume.ValidUUID(first.UUID) || first.AttemptID != attempt {
		t.Fatalf("first request = %+v, %v; want a grant with a UUID", first, err)
	}
	if again, err := ask(member, attempt); err != nil || !again.Granted || again.UUID != first.UUID || again.AttemptID != attempt {
		t.Fatalf("original initializer retry = %+v, %v; want the same grant", again, err)
	}
	replacement := member
	replacement.PublicKey = "replacement-host"
	newGeneration := member
	newGeneration.Generation++
	for _, r := range []Registration{replacement, newGeneration} {
		again, err := ask(r, attempt)
		if err != nil || again.Granted || again.UUID != first.UUID {
			t.Fatalf("later request from %s = %+v, %v; want a refusal naming %s", r.PublicKey, again, err, first.UUID)
		}
	}
	if again, err := ask(member, "7YVJX9GXJM688FXQ5TK1V58CGG"); err != nil || again.Granted || again.UUID != first.UUID {
		t.Fatalf("different initializer = %+v, %v; want a refusal", again, err)
	}
	other, err := ask(Registration{Cell: "gru", Node: "gru-1-db-2", Roles: []string{terrabase.Role},
		PublicKey: "other-host", Generation: 1, TerraBaseDataVolumeID: "ocid1.volume.oc1..other"}, attempt)
	if err != nil || !other.Granted || other.UUID == first.UUID {
		t.Fatalf("another member = %+v, %v; want its own grant", other, err)
	}
	for name, r := range map[string]Registration{
		"no terrabase role": {Cell: "gru", Node: "gru-1-db-3", Roles: []string{"host"}},
		"managed host":      {Cell: "gru", Node: "gru-1-db-3", Roles: []string{terrabase.Role}, ManagedOCI: &ManagedOCIBinding{}},
	} {
		if _, err := ask(r, attempt); err == nil {
			t.Fatalf("%s was granted a format", name)
		}
	}
}

// TestTerraBaseDataVolumeFormatGrantVerification accepts only a current,
// controller-signed grant for this node.
func TestTerraBaseDataVolumeFormatGrantVerification(t *testing.T) {
	const uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
	public, controllerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := VolumeInitConfig{Cell: "gru", Node: "gru-1-db-1", ControllerPublicKey: public, StateRoot: t.TempDir(),
		TerraBaseDataVolumeID: "ocid1.volume.oc1..first"}
	attempt, err := pendingTerraBaseFormatAttempt(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(key ed25519.PrivateKey, operation, node string, reply terraBaseFormatReply, issued time.Time) protocol.Envelope {
		if reply.VolumeID == "" {
			reply.VolumeID = cfg.TerraBaseDataVolumeID
		}
		payload, err := protocol.EncodeJSON(reply)
		if err != nil {
			t.Fatal(err)
		}
		data, err := protocol.EncodeJSON(response{Nonce: "0000000000009b876f63d1d8c38ab126", Node: node, SessionID: "00000000007WXF3V7BQMA11AT1", Epoch: 3,
			Operation: operation, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := protocol.SignEnvelope(data, protocol.EnvelopeScope{Region: "gru", Kind: "host.response." + operation,
			Actor: "controller", OperationID: entityid.Derive("host-request", "0000000000009b876f63d1d8c38ab126"), Epoch: 3}, issued, issued.Add(requestTTL), key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	now := time.Now().UTC()
	granted := terraBaseFormatReply{Granted: true, UUID: uuid, AttemptID: attempt}
	if got, err := verifyTerraBaseFormatGrant(cfg, sign(controllerKey, "terrabase-format", cfg.Node, granted, now)); err != nil || got != uuid {
		t.Fatalf("valid grant = %q, %v", got, err)
	}
	refused := sign(controllerKey, "terrabase-format", cfg.Node, terraBaseFormatReply{UUID: uuid}, now)
	if _, err := verifyTerraBaseFormatGrant(cfg, refused); err == nil || !strings.Contains(err.Error(), "restore the volume from a backup") {
		t.Fatalf("refused grant = %v; want a restore instruction", err)
	}
	for name, signed := range map[string]protocol.Envelope{
		"other signer":    sign(otherKey, "terrabase-format", cfg.Node, granted, now),
		"other node":      sign(controllerKey, "terrabase-format", "gru-1-db-2", granted, now),
		"other operation": sign(controllerKey, "terrabase-peer", cfg.Node, granted, now),
		"expired":         sign(controllerKey, "terrabase-format", cfg.Node, granted, now.Add(-time.Minute)),
		"invalid uuid": sign(controllerKey, "terrabase-format", cfg.Node,
			terraBaseFormatReply{Granted: true, UUID: "not-a-uuid", AttemptID: attempt}, now),
		"other volume": sign(controllerKey, "terrabase-format", cfg.Node,
			terraBaseFormatReply{Granted: true, UUID: uuid, VolumeID: "ocid1.volume.oc1..other", AttemptID: attempt}, now),
		"other attempt": sign(controllerKey, "terrabase-format", cfg.Node,
			terraBaseFormatReply{Granted: true, UUID: uuid, AttemptID: "7YVJX9GXJM688FXQ5TK1V58CGG"}, now),
		"missing attempt": sign(controllerKey, "terrabase-format", cfg.Node,
			terraBaseFormatReply{Granted: true, UUID: uuid}, now),
	} {
		if _, err := verifyTerraBaseFormatGrant(cfg, signed); err == nil {
			t.Fatalf("%s grant was accepted", name)
		}
	}
	signed := sign(controllerKey, "terrabase-format", cfg.Node, granted, now)
	missing := cfg
	missing.StateRoot = t.TempDir()
	if _, err := verifyTerraBaseFormatGrant(missing, signed); err == nil {
		t.Fatal("grant accepted without local initializer state")
	}
	replacement := missing
	if next, err := pendingTerraBaseFormatAttempt(replacement); err != nil || next == attempt {
		t.Fatalf("replacement root attempt = %q, %v; want a new attempt", next, err)
	}
	if _, err := verifyTerraBaseFormatGrant(replacement, signed); err == nil {
		t.Fatal("original grant accepted after root replacement with copied host credentials")
	}
}

// TestTerraBaseDataVolumeAsksForGrantOnlyWhenBlank checks the two-phase
// framing: the initializer answers a blank device with the grant result byte,
// and a grant follows the fixed request after a newline.
func TestTerraBaseDataVolumeAsksForGrantOnlyWhenBlank(t *testing.T) {
	const attempt = "014D2PF2DBSQQG28T5CY4TQKFF"
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		var size [4]byte
		if _, err := io.ReadFull(server, size[:]); err != nil {
			return
		}
		if _, err := io.ReadFull(server, make([]byte, binary.BigEndian.Uint32(size[:]))); err != nil {
			return
		}
		_, _ = server.Write(append([]byte{volumeInitNeedsGrant}, attempt...))
	}()
	var needed terraBaseFormatNeeded
	if err := exchangeVolumeInit(client, terraBaseDataRequest); !errors.Is(err, errFormatGrantNeeded) ||
		!errors.As(err, &needed) || needed.AttemptID != attempt {
		t.Fatalf("blank device answer = %v, %+v; want typed attempt %s", err, needed, attempt)
	}
	socket := filepath.Join(t.TempDir(), "volume-init.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		var size [4]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			return
		}
		wire := make([]byte, binary.BigEndian.Uint32(size[:]))
		if _, err := io.ReadFull(connection, wire); err != nil {
			return
		}
		received <- wire
		_, _ = connection.Write([]byte{0})
	}()
	grant := protocol.Envelope{OperationID: entityid.Derive("host-request", "0000000000009b876f63d1d8c38ab126"), Payload: []byte(`{}`)}
	if err := requestTerraBaseDataVolume(t.Context(), socket, &grant); err != nil {
		t.Fatal(err)
	}
	rest, ok := bytes.CutPrefix(<-received, append(slices.Clone(terraBaseDataRequest), '\n'))
	var decoded protocol.Envelope
	if !ok || protocol.DecodeStrict(rest, &decoded, 64<<10) != nil || decoded.OperationID != grant.OperationID {
		t.Fatalf("grant request framing = %q", rest)
	}
}

// TestTerraBaseDataVolumeEffectsFormatOnlyWithAnUnspentGrant runs the ordered
// effects: a blank device is formatted only with a current grant on a host
// that never formatted, after the durable consumption, and is mounted only
// once it reads back the granted filesystem; nothing else is ever formatted.
func TestTerraBaseDataVolumeEffectsFormatOnlyWithAnUnspentGrant(t *testing.T) {
	const granted = "0f8fad5b-d9cb-469f-a165-70867728950e"
	blank := volumeFilesystemProbe{BlankSample: true}
	ext4 := volumeFilesystemProbe{FSUUID: "11111111-2222-4333-8444-555555555555", FSType: "ext4", Signatures: true}
	formatted := volumeFilesystemProbe{FSUUID: granted, FSType: "ext4", Signatures: true}
	later := time.Now().Add(time.Minute)
	for _, tc := range []struct {
		name     string
		probe    volumeFilesystemProbe
		grant    string
		expires  time.Time
		consumed bool
		readback volumeFilesystemProbe
		want     string
		fails    bool
	}{
		{name: "blank without a grant", probe: blank, fails: true},
		{name: "blank with a grant", probe: blank, grant: granted, expires: later, readback: formatted, want: "consume,format,probe,mount"},
		{name: "blank after this host formatted", probe: blank, grant: granted, expires: later, consumed: true, fails: true},
		{name: "consumed blank without a grant", probe: blank, consumed: true, fails: true},
		{name: "blank with an expired grant", probe: blank, grant: granted, expires: time.Now().Add(-time.Second), fails: true},
		{name: "readback of another filesystem", probe: blank, grant: granted, expires: later, readback: ext4, want: "consume,format,probe", fails: true},
		{name: "existing ext4", probe: ext4, grant: granted, expires: later, want: "mount"},
		{name: "existing ext4 after this host formatted", probe: ext4, consumed: true, want: "mount"},
		{name: "xfs with a grant", probe: volumeFilesystemProbe{FSUUID: granted, FSType: "xfs", Signatures: true}, grant: granted, expires: later, fails: true},
		{name: "unknown data with a grant", probe: volumeFilesystemProbe{}, grant: granted, expires: later, fails: true},
	} {
		var calls []string
		err := executeTerraBaseVolume(t.Context(), tc.probe, tc.grant, tc.expires, tc.consumed, volumeInitEffects{
			Consume: func() error { calls = append(calls, "consume"); return nil },
			Format:  func(context.Context) error { calls = append(calls, "format"); return nil },
			Probe: func(context.Context) (volumeFilesystemProbe, error) {
				calls = append(calls, "probe")
				return tc.readback, nil
			},
			Mount: func(context.Context, bool) error { calls = append(calls, "mount"); return nil },
		})
		if got := strings.Join(calls, ","); got != tc.want || (err != nil) != tc.fails {
			t.Errorf("%s: effects %q, error %v; want %q, failure %v", tc.name, got, err, tc.want, tc.fails)
		}
	}
	if err := executeTerraBaseVolume(t.Context(), blank, "", time.Time{}, false, volumeInitEffects{}); !errors.Is(err, errFormatGrantNeeded) {
		t.Fatalf("blank device without a grant = %v, want errFormatGrantNeeded", err)
	}
	// The durable marker makes a grant single-use on a host: a replay of the
	// same grant finds it and holds.
	marker := filepath.Join(t.TempDir(), terraBaseFormatMarker)
	if err := createDurableMarker(marker, []byte(granted+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := createDurableMarker(marker, []byte(granted+"\n")); err == nil {
		t.Fatal("a format grant was consumed twice")
	}
}

// TestTerraBaseDataVolumeAdoptedFilesystemIsRecorded: a mounted filesystem
// the member's grant never formatted is recorded too, so no first format is
// granted for that member afterwards, and a different filesystem is reported
// against the recorded one.
func TestTerraBaseDataVolumeAdoptedFilesystemIsRecorded(t *testing.T) {
	const adopted = "11111111-2222-4333-8444-555555555555"
	c, _, _, _, _ := testController(t)
	member := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
		TerraBaseDataVolumeID: "ocid1.volume.oc1..first"}
	ask := func(query string) terraBaseFormatReply {
		t.Helper()
		var payload terraBaseFormatQuery
		if err := decodeStrict([]byte(query), &payload); err != nil {
			t.Fatal(err)
		}
		payload.VolumeID = member.TerraBaseDataVolumeID
		wire, _ := protocol.EncodeJSON(payload)
		reply, err := c.serveTerraBaseFormat(t.Context(), request{Node: member.Node, Payload: wire}, member)
		if err != nil {
			t.Fatal(err)
		}
		return reply.(terraBaseFormatReply)
	}
	if reply := ask(`{"mounted":"` + adopted + `"}`); reply.Granted || reply.UUID != adopted {
		t.Fatalf("adopting = %+v, want the adopted UUID recorded without a grant", reply)
	}
	if reply := ask(`{"attempt_id":"014D2PF2DBSQQG28T5CY4TQKFF"}`); reply.Granted || reply.UUID != adopted {
		t.Fatalf("first format after adoption = %+v, want a refusal", reply)
	}
	if reply := ask(`{"mounted":"0f8fad5b-d9cb-469f-a165-70867728950e"}`); reply.UUID != adopted {
		t.Fatalf("another mounted filesystem = %+v, want the recorded UUID back", reply)
	}
	if _, err := c.serveTerraBaseFormat(t.Context(), request{Node: member.Node,
		Payload: []byte(`{"mounted":"NOT-A-UUID","volume_id":"ocid1.volume.oc1..first"}`)}, member); err == nil {
		t.Fatal("recorded an invalid filesystem UUID")
	}
}

// TestTerraBaseDataVolumeLossStopsTheRunningMember: a member keeps running
// only while its data volume mount verifies; otherwise it is stopped and
// reported failed.
func TestTerraBaseDataVolumeLossStopsTheRunningMember(t *testing.T) {
	runner := &memoryRunner{observed: map[string]Observation{terrabase.Role: {Role: terrabase.Role, Running: true}}}
	agent := &Agent{terraBase: map[string]terraBaseMember{terrabase.Role: {}}, runner: runner, cfg: AgentConfig{
		Node: "gru-1-db-1", TerraBaseRoot: filepath.Join(traversableTempDir(t), "terrabase"), WorkloadIdentity: testAgentIdentity(),
		TerraBaseDataVolume: true, VolumeInitSocket: filepath.Join(t.TempDir(), "absent.sock")}}
	report := agent.terraBaseRunningReport(t.Context(), Desired{Role: terrabase.Role})
	if report.State != "failed" || !strings.Contains(report.Error, "data volume") {
		t.Fatalf("report = %s %q, want failed for the data volume", report.State, report.Error)
	}
	if observed, _ := runner.Observe(t.Context(), terrabase.Role); observed.Running {
		t.Fatal("the member kept running without its data volume")
	}
	if _, tracked := agent.terraBase[terrabase.Role]; tracked {
		t.Fatal("the stopped member is still tracked")
	}
}

// fakeDataVolume replaces the data volume seams: the mount verifies while
// mounted is true and holds filesystem uuid, and the controller records the
// first filesystem it is asked to confirm.
func fakeDataVolume(t *testing.T, mounted *bool, uuid *string) (recorded *string, confirms *int) {
	t.Helper()
	recorded, confirms = new(string), new(int)
	verify, filesystem, confirm := verifyDataMount, dataFilesystemUUID, confirmDataFilesystem
	t.Cleanup(func() { verifyDataMount, dataFilesystemUUID, confirmDataFilesystem = verify, filesystem, confirm })
	verifyDataMount = func(string, WorkloadIdentity) error {
		if !*mounted {
			return errors.New("not mounted")
		}
		return nil
	}
	dataFilesystemUUID = func() (string, error) { return *uuid, nil }
	confirmDataFilesystem = func(_ context.Context, _ *Agent, mounted string) (string, error) {
		*confirms++
		if *recorded == "" {
			*recorded = mounted
		}
		return *recorded, nil
	}
	return recorded, confirms
}

// TestTerraBaseDataVolumeFilesystemSwapIsRefused: after filesystem A was
// confirmed, a filesystem B mounted on the member's device is checked
// against the record again and refused, and a running member on it is
// stopped without any remount attempt.
func TestTerraBaseDataVolumeFilesystemSwapIsRefused(t *testing.T) {
	const a, b = "0f8fad5b-d9cb-469f-a165-70867728950e", "11111111-2222-4333-8444-555555555555"
	mounted, uuid := true, a
	recorded, confirms := fakeDataVolume(t, &mounted, &uuid)
	runner := &memoryRunner{observed: map[string]Observation{}}
	// A stalling initializer: any request to it would block the test.
	stalled := filepath.Join(t.TempDir(), "stalled.sock")
	listener, err := net.Listen("unix", stalled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	agent := &Agent{terraBase: map[string]terraBaseMember{}, runner: runner, cfg: AgentConfig{Node: "gru-1-db-1",
		TerraBaseRoot: filepath.Join(t.TempDir(), "terrabase"), TerraBaseDataVolume: true, VolumeInitSocket: stalled}}
	agent.terraBaseVolumeChecked = time.Now()
	if err := agent.ensureTerraBaseDataVolume(t.Context()); err != nil || agent.terraBaseVolumeConfirmed != a || *recorded != a {
		t.Fatalf("first mount = %v, confirmed %q, recorded %q", err, agent.terraBaseVolumeConfirmed, *recorded)
	}
	if err := agent.ensureTerraBaseDataVolume(t.Context()); err != nil || *confirms != 1 {
		t.Fatalf("a confirmed filesystem was confirmed again: %v, %d requests", err, *confirms)
	}
	runner.observed[terrabase.Role] = Observation{Role: terrabase.Role, Running: true}
	agent.terraBase[terrabase.Role] = terraBaseMember{}
	if stopped, err := agent.fenceTerraBaseMember(t.Context(), terrabase.Role); stopped || err != nil {
		t.Fatalf("fenced a member on its confirmed filesystem: %v, %v", stopped, err)
	}

	uuid = b
	if stopped, err := agent.fenceTerraBaseMember(t.Context(), terrabase.Role); !stopped || err != nil {
		t.Fatalf("a member on another filesystem kept running: %v, %v", stopped, err)
	}
	if observed, _ := runner.Observe(t.Context(), terrabase.Role); observed.Running || agent.terraBaseVolumeConfirmed != "" {
		t.Fatalf("after the swap: running %v, confirmed %q", observed.Running, agent.terraBaseVolumeConfirmed)
	}
	if err := agent.ensureTerraBaseDataVolume(t.Context()); err == nil || *confirms != 2 || agent.terraBaseVolumeConfirmed != "" {
		t.Fatalf("filesystem B = %v after %d requests, confirmed %q; want a refusal", err, *confirms, agent.terraBaseVolumeConfirmed)
	}
}

// TestTerraBaseDataVolumeFenceStopsBeforeRepair: a lost mount stops the
// running member at once, before the stalled initializer is asked to repair
// it.
func TestTerraBaseDataVolumeFenceStopsBeforeRepair(t *testing.T) {
	mounted, uuid := false, "0f8fad5b-d9cb-469f-a165-70867728950e"
	fakeDataVolume(t, &mounted, &uuid)
	stalled := filepath.Join(t.TempDir(), "stalled.sock")
	listener, err := net.Listen("unix", stalled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		if connection, err := listener.Accept(); err == nil {
			accepted <- struct{}{}
			defer connection.Close()
			<-t.Context().Done()
		}
	}()
	runner := &memoryRunner{observed: map[string]Observation{terrabase.Role: {Role: terrabase.Role, Running: true}}}
	agent := &Agent{terraBase: map[string]terraBaseMember{terrabase.Role: {}}, runner: runner, cfg: AgentConfig{Node: "gru-1-db-1",
		TerraBaseRoot: filepath.Join(t.TempDir(), "terrabase"), TerraBaseDataVolume: true, VolumeInitSocket: stalled},
		terraBaseVolumeConfirmed: uuid}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if stopped, err := agent.fenceTerraBaseMember(ctx, terrabase.Role); !stopped || err != nil {
		t.Fatalf("a member without its mount was not fenced: %v, %v", stopped, err)
	}
	if observed, _ := runner.Observe(t.Context(), terrabase.Role); observed.Running {
		t.Fatal("the member kept running without its mount")
	}
	select {
	case <-accepted:
		t.Fatal("the fence asked the initializer to repair the mount")
	default:
	}
}

// TestTerraBaseDataVolumeReadsTheSuperblockUUID reads the filesystem UUID
// from the ext4 superblock itself, so a brief udev gap never fences a member.
func TestTerraBaseDataVolumeReadsTheSuperblockUUID(t *testing.T) {
	image := make([]byte, 4096)
	image[1024+0x38], image[1024+0x39] = 0x53, 0xef
	copy(image[1024+0x68:], []byte{0x0f, 0x8f, 0xad, 0x5b, 0xd9, 0xcb, 0x46, 0x9f, 0xa1, 0x65, 0x70, 0x86, 0x77, 0x28, 0x95, 0x0e})
	if uuid, err := ext4SuperblockUUID(bytes.NewReader(image)); err != nil || uuid != "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Fatalf("uuid = %q, %v", uuid, err)
	}
	image[1024+0x38] = 0
	if _, err := ext4SuperblockUUID(bytes.NewReader(image)); err == nil {
		t.Fatal("read a UUID without the ext4 magic")
	}
	if _, err := ext4SuperblockUUID(bytes.NewReader(image[:1100])); err == nil {
		t.Fatal("read a UUID from a truncated device")
	}
}

// failingRunner observes and stops a member like memoryRunner, failing on
// request.
type failingRunner struct {
	*memoryRunner
	observeErr, stopErr error
	stops               int
}

func (r *failingRunner) Observe(ctx context.Context, role string) (Observation, error) {
	if r.observeErr != nil {
		return Observation{}, r.observeErr
	}
	return r.memoryRunner.Observe(ctx, role)
}

func (r *failingRunner) Stop(ctx context.Context, role string) error {
	r.stops++
	if r.stopErr != nil {
		return r.stopErr
	}
	return r.memoryRunner.Stop(ctx, role)
}

// TestTerraBaseDataVolumeFenceFailsClosed: a lost volume stops the member
// even when the runner cannot observe it, and a failed stop is an error the
// caller must not go past, so no repair is attempted while a writer may run.
func TestTerraBaseDataVolumeFenceFailsClosed(t *testing.T) {
	mounted, uuid := false, "0f8fad5b-d9cb-469f-a165-70867728950e"
	fakeDataVolume(t, &mounted, &uuid)
	runner := &failingRunner{memoryRunner: &memoryRunner{observed: map[string]Observation{terrabase.Role: {Role: terrabase.Role, Running: true}}},
		observeErr: errors.New("memory.max is unreadable")}
	agent := &Agent{terraBase: map[string]terraBaseMember{terrabase.Role: {}}, runner: runner, cfg: AgentConfig{Node: "gru-1-db-1",
		TerraBaseRoot: filepath.Join(t.TempDir(), "terrabase"), TerraBaseDataVolume: true}, terraBaseVolumeConfirmed: uuid}
	if stopped, err := agent.fenceTerraBaseMember(t.Context(), terrabase.Role); !stopped || err != nil || runner.stops != 1 {
		t.Fatalf("unobservable member on a lost volume: stopped %v, %v, %d stops", stopped, err, runner.stops)
	}
	runner.observeErr, runner.stopErr = nil, errors.New("cgroup kill failed")
	runner.observed[terrabase.Role] = Observation{Role: terrabase.Role, Running: true}
	agent.terraBase[terrabase.Role] = terraBaseMember{}
	if stopped, err := agent.fenceTerraBaseMember(t.Context(), terrabase.Role); stopped || err == nil {
		t.Fatalf("failed stop = stopped %v, %v; want an error", stopped, err)
	}
	if _, tracked := agent.terraBase[terrabase.Role]; !tracked {
		t.Fatal("a member that may still run was untracked")
	}
	// A stopped member on a lost volume needs no stop.
	runner.stopErr = nil
	runner.observed = map[string]Observation{}
	stops := runner.stops
	if stopped, err := agent.fenceTerraBaseMember(t.Context(), terrabase.Role); stopped || err != nil || runner.stops != stops {
		t.Fatalf("stopped member = %v, %v after %d stops", stopped, err, runner.stops-stops)
	}
}

// TestTerraBaseDataVolumeLostDuringMaintenanceStopsTheMember: the mount
// verifies at the first fence, is lost while the bounded maintenance request
// stalls, and the running report then stops the member and reports failed.
func TestTerraBaseDataVolumeLostDuringMaintenanceStopsTheMember(t *testing.T) {
	mounted, uuid := true, "0f8fad5b-d9cb-469f-a165-70867728950e"
	fakeDataVolume(t, &mounted, &uuid)
	timeout := terraBaseMaintenanceTimeout
	terraBaseMaintenanceTimeout = 100 * time.Millisecond
	t.Cleanup(func() { terraBaseMaintenanceTimeout = timeout })
	stalled := filepath.Join(t.TempDir(), "stalled.sock")
	listener, err := net.Listen("unix", stalled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	lost := make(chan struct{})
	go func() {
		if connection, err := listener.Accept(); err == nil {
			defer connection.Close()
			close(lost) // the volume goes while the initializer stalls
			<-t.Context().Done()
		}
	}()
	runner := &memoryRunner{observed: map[string]Observation{terrabase.Role: {Role: terrabase.Role, Running: true}}}
	agent := &Agent{terraBase: map[string]terraBaseMember{terrabase.Role: {}}, runner: runner, cfg: AgentConfig{Node: "gru-1-db-1",
		TerraBaseRoot: filepath.Join(traversableTempDir(t), "terrabase"), WorkloadIdentity: testAgentIdentity(),
		TerraBaseDataVolume: true, VolumeInitSocket: stalled}, terraBaseVolumeConfirmed: uuid}
	verify := verifyDataMount
	verifyDataMount = func(path string, identity WorkloadIdentity) error {
		select {
		case <-lost:
			mounted = false
		default:
		}
		return verify(path, identity)
	}
	d := Desired{Role: terrabase.Role, Env: map[string]string{terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "gru-1-db-1=10.0.0.1:9443"}}
	report := agent.terraBaseRunningReport(t.Context(), d)
	if report.State != "failed" || !strings.Contains(report.Error, "data volume") {
		t.Fatalf("report = %s %q, want failed for the data volume", report.State, report.Error)
	}
	if observed, _ := runner.Observe(t.Context(), terrabase.Role); observed.Running {
		t.Fatal("the member kept running after its volume was lost during maintenance")
	}
}
