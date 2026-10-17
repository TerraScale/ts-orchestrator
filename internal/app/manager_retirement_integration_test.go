//go:build fixturetest

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This crosses signed ledger/SDK/Vault and three actual managers. It exercises
// local-leader mutation and postcommit guard loss, not delayed Raft commitment,
// authenticated leaseholder forwarding or production executable provenance.
func TestControllerManagerRetirementNativeRecovery(t *testing.T) {
	if os.Getenv("TS_MANAGER_RETIREMENT_NAMESPACE") != "1" {
		runManagerRetirementNamespace(t)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	responsePublic, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseKey)
	ca, err := os.ReadFile(auth.tls.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU", Environment: "production",
		ControllerEndpoints: []string{"10.44.0.11:8443", "10.44.0.12:8443", "10.44.0.10:8443"},
		NATSURLs:            []string{"tls://10.44.0.11:4222", "tls://10.44.0.12:4222", "tls://10.44.0.10:4222"},
		CAPEM:               string(ca), ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(responsePublic), CellAccountNKey: auth.cellID,
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	enrollment, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	operatorWire, err := os.ReadFile(auth.operatorFile)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := jwt.DecodeOperatorClaims(string(operatorWire))
	if err != nil {
		t.Fatal(err)
	}
	systemWire, err := os.ReadFile(auth.systemFile)
	if err != nil {
		t.Fatal(err)
	}
	system, err := jwt.DecodeAccountClaims(string(systemWire))
	if err != nil {
		t.Fatal(err)
	}
	broker := identityrekey.BrokerIdentity{Operator: operator.Subject, SystemAccount: system.Subject, CellAccount: auth.cellID}
	for _, target := range []*string{&broker.HostSigner, &broker.RoleSigner} {
		key, err := nkeys.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		*target, err = key.PublicKey()
		key.Wipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(root)
	foundation, grantWire, intent := managerStartupFoundation(t, root)
	fixture := bootstrapstart.NewControllerManagerStartupFixture(t, enrollment, broker, root, foundation)
	observations := fixture.CompleteManagedControllers(t)
	foundations := managerStartupFoundationResolver(t, fixture, grantWire, intent)
	vaultClient, bundles := managerStartupVault(t)
	seed, err := swarmruntime.StartAcceptedNodeFixture(ctx, filepath.Join(t.TempDir(), "manager"), fixture.Reader, fixture.Accepted,
		foundations, vaultClient, bundles, &managerStartupExecutor{Executor: new(swarmruntime.Executor)}, fixture.Observer, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopManagerRetirementFixture(t, seed) })
	client, err := seed.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatal("actual regional cluster unavailable", err)
	}
	managerAddress, err := seed.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := fixture.Reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	join := func(slot string, observation bootstrapstart.InstanceObservation) *swarmruntime.Node {
		t.Helper()
		admission := swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: slot, InstanceID: observation.InstanceOCID,
			FounderID: fixture.Accepted.Slot, Role: "manager", ManagerAddress: managerAddress, JoinToken: clusters.Clusters[0].RootCA.JoinTokens.Manager}
		address := net.JoinHostPort(observation.PrimaryPrivateIP, "2377")
		node, err := swarmruntime.StartNode(ctx, swarmruntime.NodeConfig{StateDir: t.TempDir(), ListenAddress: address, AdvertiseAddress: address, Admission: admission},
			&managerStartupExecutor{Executor: new(swarmruntime.Executor)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stopManagerRetirementFixture(t, node) })
		if _, err := swarmruntime.AdmitNode(ctx, client, node.ID(), admission); err != nil {
			t.Fatal(err)
		}
		return node
	}
	var old *swarmruntime.Node
	var retirementPeers []*swarmruntime.Node
	for index, row := range selected.Plan.Plan().Peers {
		peer := join(row.Slot, observations[index+1])
		retirementPeers = append(retirementPeers, peer)
		if row.Slot == "controller-a" {
			old = peer
		}
	}
	if old == nil {
		t.Fatal("current signed old managed slot unavailable")
	}
	waitManagerRetirementFixture(t, ctx, func() bool {
		response, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil || len(response.Nodes) != 3 {
			return false
		}
		for _, node := range response.Nodes {
			if node.Status.State != api.NodeStatus_READY || node.ManagerStatus == nil || node.ManagerStatus.Reachability != api.RaftMemberStatus_REACHABLE {
				return false
			}
			if node.ID == seed.ID() && !node.ManagerStatus.Leader {
				return false
			}
		}
		return true
	})
	oldID := old.ID()
	oldRow, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
	if err != nil {
		t.Fatal(err)
	}
	oldInstance := oldRow.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID]
	stopManagerRetirementFixture(t, old)
	wire := fixture.SignControllerRetirement(t, "controller-a")
	for _, lifecycle := range []string{"RUNNING", "TERMINATING"} {
		if err := fixture.SetControllerLifecycle(oldInstance, lifecycle); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.ReadControllerManagerRetirement(ctx, "controller-a", wire); err == nil {
			t.Fatalf("signed retirement accepted exact old SDK state %s", lifecycle)
		}
	}
	if err := fixture.SetControllerLifecycle(oldInstance, "TERMINATED"); err != nil {
		t.Fatal(err)
	}
	fixture.AdvanceRetiredController(t, "controller-a", wire)
	waitManagerRetirementFixture(t, ctx, func() bool {
		response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
		return err == nil && response.Node.Status.State != api.NodeStatus_READY
	})
	// Capture the actual current version after dispatcher status transitions.
	oldRow, err = client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
	if err != nil {
		t.Fatal(err)
	}
	originalVersion := oldRow.Node.Meta.Version.Index
	readProof := func(call context.Context) *bootstrapstart.ManagerRetirement {
		t.Helper()
		proof, err := fixture.ReadControllerManagerRetirement(call, "controller-a", nil)
		if err != nil || proof.PriorInstanceID() != oldInstance || proof.RetirementSHA256() == "" {
			t.Fatal("genuine protected predecessor retirement unavailable", err)
		}
		return proof
	}
	proof := readProof(ctx)
	if _, err := seed.RetireControllerManager(ctx, proof, seed.ID(), originalVersion, 7); err == nil {
		t.Fatal("retirement for exact old instance accepted current survivor NodeID")
	}
	if _, err := seed.RetireControllerManager(ctx, proof, oldID, originalVersion+1, 7); err == nil {
		t.Fatal("retirement accepted a different original NodeVersion")
	}
	original, revoke := context.WithCancel(ctx)
	expired := readProof(original)
	revoke()
	if _, err := seed.RetireControllerManager(context.Background(), expired, oldID, originalVersion, 7); err == nil {
		t.Fatal("Background renewed canceled original retirement authority")
	}
	// Guard loss is triggered by reading the real committed immutable pin. This
	// qualifies postcommit response/session loss, not delayed pending commitment.
	session, revokeSession := context.WithCancel(ctx)
	defer revokeSession()
	session = ociclient.WithRequestGuard(session, func(context.Context) error {
		current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
		if err != nil {
			return err
		}
		if current.Node.Spec.Annotations.Labels["terrascale.manager-retirement"] != "" {
			revokeSession()
			return context.Canceled
		}
		return nil
	})
	proof = readProof(session)
	if _, err := seed.RetireControllerManager(session, proof, oldID, originalVersion, 7); !errors.Is(err, manager.ErrMutationAmbiguous) {
		t.Fatalf("committed demotion lost original session without ambiguous outcome: %v", err)
	}
	pinned, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
	if err != nil || pinned.Node.Spec.DesiredRole != api.NodeRoleWorker || pinned.Node.Spec.Availability != api.NodeAvailabilityPause ||
		pinned.Node.Spec.Annotations.Labels["terrascale.manager-retirement"] == "" {
		t.Fatal("ambiguous demotion lost its durable original operation", err)
	}
	pin := pinned.Node.Spec.Annotations.Labels["terrascale.manager-retirement"]
	waitManagerRetirementFixture(t, ctx, func() bool {
		response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
		return err == nil && response.Node.Role == api.NodeRoleWorker && response.Node.ManagerStatus == nil && response.Node.Status.State != api.NodeStatus_READY
	})
	retained, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
	if err != nil || retained.Node.Spec.Annotations.Labels["terrascale.manager-retirement"] != pin {
		t.Fatal("native asynchronous demotion replaced its original pin", err)
	}
	proof = readProof(ctx)
	result, err := seed.RetireControllerManager(ctx, proof, oldID, originalVersion, 8)
	if err != nil || result == nil || result.Stage != "demoted" {
		t.Fatalf("fresh authority failed to observe exact pinned demotion: %+v %v", result, err)
	}
	retained, err = client.GetNode(ctx, &api.GetNodeRequest{NodeID: oldID})
	if err != nil || retained.Node.Spec.Annotations.Labels["terrascale.manager-retirement"] != pin || retained.Node.Spec.Annotations.Labels["terrascale.manager-removal"] != "" {
		t.Fatal("fresh proof renewed the canceled original operation into removal", err)
	}
	var first struct {
		SourceSHA256, ObservationSHA256, OperationSHA256 string
		FirstExpiresAt                                   time.Time
	}
	if err := json.Unmarshal([]byte(pin), &first); err != nil || first.SourceSHA256 == "" || first.ObservationSHA256 == "" || first.OperationSHA256 == "" ||
		first.FirstExpiresAt.IsZero() || proof.ObservationSHA256() == first.ObservationSHA256 {
		t.Fatal("durable first admission/source/operation/deadline missing", err)
	}
	successorObservation := fixture.CompleteReplacementManagedController(t, "controller-a")
	successor := join("controller-a", successorObservation)
	waitManagerRetirementFixture(t, ctx, func() bool {
		current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: successor.ID()})
		return err == nil && current.Node.Role == api.NodeRoleManager && current.Node.Status.State == api.NodeStatus_READY && current.Node.ManagerStatus != nil &&
			current.Node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE
	})
	proof = readProof(ctx)
	if _, err := seed.RetireControllerManager(ctx, proof, successor.ID(), originalVersion, 9); err == nil {
		t.Fatal("old retirement selected the active successor sharing its slot")
	}
	if result, err := seed.RetireControllerManager(ctx, proof, oldID, originalVersion, 9); err == nil && result.Stage == "removed" {
		t.Fatal("new signed successor authority renewed the old removal action")
	}
	currentSuccessor, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: successor.ID()})
	if err != nil || currentSuccessor.Node.Spec.DesiredRole != api.NodeRoleManager ||
		currentSuccessor.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != successorObservation.InstanceOCID ||
		currentSuccessor.Node.Spec.Annotations.Labels["terrascale.manager-retirement"] != "" {
		t.Fatal("old retirement mutated the exact active successor", err)
	}
	// A separate original call may complete both distinct native phases while
	// that exact sealed proof is still live. A new observation cannot replace it.
	response, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var next *api.Node
	for _, node := range response.Nodes {
		if node.Spec.Annotations.Name == "controller-b" {
			next = node
		}
	}
	if next == nil {
		t.Fatal("second actual managed controller unavailable")
	}
	for _, peer := range retirementPeers {
		if peer.ID() == next.ID {
			stopManagerRetirementFixture(t, peer)
		}
	}
	if err := fixture.SetControllerLifecycle(next.Spec.Annotations.Labels[swarmruntime.LabelInstanceID], "TERMINATED"); err != nil {
		t.Fatal(err)
	}
	fixture.AdvanceRetiredController(t, "controller-b", fixture.SignControllerRetirement(t, "controller-b"))
	waitManagerRetirementFixture(t, ctx, func() bool {
		current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: next.ID})
		if err != nil || current.Node.Status.State == api.NodeStatus_READY {
			return false
		}
		next = current.Node
		return true
	})
	nextVersion := next.Meta.Version.Index
	proof, err = fixture.ReadControllerManagerRetirement(ctx, "controller-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := seed.RetireControllerManager(ctx, proof, next.ID, nextVersion, 10); err != nil || result.Stage != "demoted" {
		t.Fatal("original call could not admit its first demotion", err)
	}
	firstCall, stopFirstCall := context.WithDeadline(ctx, proof.ExpiresAt())
	defer stopFirstCall()
	waitManagerRetirementFixture(t, firstCall, func() bool {
		current, err := client.GetNode(firstCall, &api.GetNodeRequest{NodeID: next.ID})
		return err == nil && current.Node.Role == api.NodeRoleWorker && current.Node.ManagerStatus == nil
	})
	if result, err := seed.RetireControllerManager(firstCall, proof, next.ID, nextVersion, 10); err != nil || result.Stage != "removed" {
		t.Fatal("same original proof could not reserve and remove within its first deadline", err)
	}
	if _, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: next.ID}); status.Code(err) != codes.NotFound {
		t.Fatal("original call did not remove the exact native row", err)
	}
}

func stopManagerRetirementFixture(t *testing.T, node *swarmruntime.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := node.Stop(ctx); err != nil {
		t.Error(err)
	}
}

func waitManagerRetirementFixture(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-wait.Done():
			t.Fatal("actual native manager state did not converge", wait.Err())
		case <-ticker.C:
		}
	}
}

func runManagerRetirementNamespace(t *testing.T) {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const script = `set -eu
"$1" link set lo up
"$1" addr add 10.44.0.10/32 dev lo
"$1" addr add 10.44.0.11/32 dev lo
"$1" addr add 10.44.0.12/32 dev lo
TS_MANAGER_RETIREMENT_NAMESPACE=1 GOMAXPROCS=2 exec "$2" -test.v -test.run='^TestControllerManagerRetirementNativeRecovery$' -test.timeout=170s
`
	args := []string{unshare, "--net", "--fork", "--kill-child=SIGKILL", "--", "/bin/sh", "-c", script, "ts-manager-retirement", ip, self}
	if os.Geteuid() != 0 {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			t.Fatal(err)
		}
		args = append([]string{sudo, "-n"}, args...)
	}
	command := exec.CommandContext(t.Context(), args[0], args[1:]...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated manager retirement fixture: %v\n%s", err, output)
	}
	t.Log(string(output))
}
