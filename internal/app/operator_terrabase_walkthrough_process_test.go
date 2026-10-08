package app

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// walkthroughNamespaceEnv marks the re-executed test process that runs in a
// private user and network namespace owning the deployment member addresses.
const walkthroughNamespaceEnv = "TS_TERRABASE_WALKTHROUGH_NAMESPACE"

// TestTerraBaseWalkthroughAgainstRealMembers runs the customer walkthrough
// against two real tb-server processes serving the generation-one material
// and customer profile that terrabase-deploy produces. Set
// TS_TERRABASE_SERVER to a tb-server built from the paired TerraBase
// revision and run it in a cgroup with a finite memory.max, as tb-server
// requires; `make terrabase-walkthrough-process` does both. The test
// re-executes itself in a private user and network namespace where the two
// member addresses are local, so it needs unprivileged user namespaces and
// ip(8). Members run LocalDurable without the managed host's S3 target,
// member-control socket or material pin manifest; the client listener,
// credentials, catalogs and replication use the generated material unchanged.
func TestTerraBaseWalkthroughAgainstRealMembers(t *testing.T) {
	server := tier.Qualification(t, "TS_TERRABASE_SERVER")[0]
	if os.Getenv(walkthroughNamespaceEnv) == "" {
		requireFiniteMemoryCgroup(t)
		runInMemberNamespace(t)
		return
	}
	for _, command := range [][]string{{"link", "set", "lo", "up"},
		{"addr", "add", "10.251.0.21/32", "dev", "lo"}, {"addr", "add", "10.251.0.22/32", "dev", "lo"}} {
		if output, err := exec.Command("ip", command...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(command, " "), err, output)
		}
	}
	root, err := os.MkdirTemp("", "tbw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	plan := terrabaseDeployPlan{PlacementDatabaseID: "0000000000HX30KC7N7WJ1ZFC8", PartitionID: "00000000003ZJEV7X3HYJENEYG", ManagedRuntimeRoot: root,
		Members: [2]terrabaseDeployMember{{PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1"},
			{PrivateIP: "10.251.0.22", FaultDomain: "FAULT-DOMAIN-2"}},
		ReplicationPort: 9443, ClientPort: 9465,
		LiveS3: managedmaterial.LiveS3Target{Bucket: "ts-preview-gru-20260926-terrabase-live", Region: "sa-saopaulo-1",
			Endpoint:   "https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential: oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.livesecret", VersionNumber: 2}}}
	deployment, err := managedmaterial.NewDeploymentIdentity(plan.base(oci.RegionGRU), 1)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := deployment.DraftSpec()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	spec, err := managedmaterial.SignRecipientGrant(draft, recipient, signer, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := managedmaterial.GenerateInitial(spec, signerPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	members := [2]walkthroughMemberProcess{startWalkthroughMember(t, server, spec, bundle, 0),
		startWalkthroughMember(t, server, spec, bundle, 1)}
	for _, member := range members {
		member.awaitReady(t)
	}

	state, err := openDeployState(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.customer(spec, materialPrepareReply{Customer: bundle.Customer}, recipient, deployment); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = runTerraBaseWalkthrough(t.Context(), []string{"--state", state.directory}, &output)
	t.Logf("walkthrough output:\n%s", output.String())
	if err != nil || !strings.Contains(output.String(), `"check":"walkthrough","result":"passed"`) {
		t.Fatalf("walkthrough against real members failed: %v", err)
	}
}

// requireFiniteMemoryCgroup fails unless this process's cgroup-v2 group has a
// finite memory.max.
func requireFiniteMemoryCgroup(t *testing.T) {
	t.Helper()
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err == nil {
		for line := range strings.Lines(string(membership)) {
			if group, found := strings.CutPrefix(strings.TrimSpace(line), "0::"); found {
				limit, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, "memory.max"))
				if err == nil && strings.TrimSpace(string(limit)) != "max" {
					return
				}
			}
		}
	}
	t.Fatal("tb-server needs a finite cgroup memory.max; run under systemd-run --user --scope -p MemoryMax=10G")
}

// runInMemberNamespace re-executes this test as the root of a fresh user and
// network namespace, mapped to the invoking user and group.
func runInMemberNamespace(t *testing.T) {
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	command.Env = append(os.Environ(), walkthroughNamespaceEnv+"=1")
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	output, err := command.CombinedOutput()
	t.Logf("namespaced run:\n%s", output)
	if err != nil {
		t.Fatalf("namespaced walkthrough run failed: %v", err)
	}
}

type walkthroughMemberProcess struct {
	seat      string
	adminPort int
	log       string
	command   *exec.Cmd
	exited    chan struct{}
}

// startWalkthroughMember writes one member's generated files to its signed
// material directory and starts tb-server with the managed host's arguments
// for authority, replication and the client listener.
func startWalkthroughMember(t *testing.T, server string, spec managedmaterial.InitialSpec,
	bundle managedmaterial.InitialBundle, index int,
) walkthroughMemberProcess {
	t.Helper()
	member, peer := spec.Members[index], spec.Members[1-index]
	material := member.MaterialDirectory
	volume := filepath.Join(filepath.Dir(material), "volume")
	for _, directory := range []string{material, filepath.Join(volume, "data"), filepath.Join(volume, "replication")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, file := range bundle.Members[index].Files {
		if err := os.WriteFile(filepath.Join(material, name), file.Contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	process := walkthroughMemberProcess{seat: member.SeatID, adminPort: listener.Addr().(*net.TCPAddr).Port,
		log: filepath.Join(filepath.Dir(material), "tb-server.log"), exited: make(chan struct{})}
	_ = listener.Close()
	log, err := os.Create(process.log)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	replication := func(ip string) string { return net.JoinHostPort(ip, strconv.Itoa(int(member.ReplicationPort))) }
	process.command = exec.Command(server,
		"--data-dir", filepath.Join(volume, "data"),
		"--memory-limit-bytes", strconv.FormatUint(4<<30, 10),
		"--memory-headroom-bytes", strconv.FormatUint(1<<30, 10),
		"--port", strconv.Itoa(process.adminPort),
		"--replication-listen-addr", replication(member.ReplicationIP),
		"--replication-data-dir", filepath.Join(volume, "replication", "shard"),
		"--authority-certificate", filepath.Join(material, "authority.tbca"),
		"--trusted-public-key", filepath.Join(material, "trusted-public-key"),
		"--replication-server-certificate", filepath.Join(material, "server.crt"),
		"--replication-server-private-key", filepath.Join(material, "server.key"),
		"--replication-client-ca-roots", filepath.Join(material, "client-ca.pem"),
		"--replication-peer-member-id", peer.MemberID,
		"--replication-peer-addr", replication(peer.ReplicationIP),
		"--replication-server-ca-roots", filepath.Join(material, "server-ca.pem"),
		"--cluster-id", spec.Scope.ClusterID,
		"--tenant-id", spec.Scope.TenantID,
		"--database-id", spec.Scope.DatabaseID,
		"--shard-id", strconv.FormatUint(spec.Scope.ShardID, 10),
		"--member-id", member.MemberID,
		"--member-incarnation", member.Incarnation,
		"--client-config", filepath.Join(material, "client-config.json"),
		"--client-allow-nonloopback")
	process.command.Stdout, process.command.Stderr = log, log
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = process.command.Wait()
		close(process.exited)
	}()
	t.Cleanup(func() {
		_ = process.command.Process.Signal(syscall.SIGTERM)
		select {
		case <-process.exited:
		case <-time.After(30 * time.Second):
			_ = process.command.Process.Kill()
			<-process.exited
		}
	})
	return process
}

// awaitReady polls the member's loopback administrative readiness endpoint.
func (process walkthroughMemberProcess) awaitReady(t *testing.T) {
	t.Helper()
	ready := fmt.Sprintf("http://127.0.0.1:%d/readyz", process.adminPort)
	for deadline := time.Now().Add(60 * time.Second); ; {
		if response, err := http.Get(ready); err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-process.exited:
			contents, _ := os.ReadFile(process.log)
			t.Fatalf("member %s exited before readiness: %s\n%s", process.seat, process.command.ProcessState, contents)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			contents, _ := os.ReadFile(process.log)
			t.Fatalf("member %s was not ready within 60s\n%s", process.seat, contents)
		}
	}
}
