package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	releasecli "git.terrascale.tech/TerraScale/ts-orchestrator/internal/release/cli"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
)

// TestServiceSetAddsTSAuthToARunningCell bootstraps a three-controller cell
// with the TerraBase profile only, as gru-1 was, then adds ts-auth with the
// committed gru-1 profile and spec through the supported commands: plan,
// root delegation and leaf signature with the release CLI, apply. The cell
// then rolls out a ts-auth release on two hosts, and refuses to remove the
// service while its replicas run.
func TestServiceSetAddsTSAuthToARunningCell(t *testing.T) {
	tier.Integration(t)
	controllerCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	root := t.TempDir()
	controllerPublic, _ := testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	rootKey, rootPrivateKey := writeTestPEMKeyPair(t, root, "root")
	leafKey, leafPrivateKey := writeTestPEMKeyPair(t, root, "leaf")
	const deployment, environment = "lab-gru-1", "canary"
	nodes := []string{"ctl-1", "ctl-2"}
	var grants []natscell.NKeyGrant
	controllerSeeds := make([]string, 3)
	for index := range controllerSeeds {
		public, seed := testNKey(t)
		controllerSeeds[index] = seed
		grants = append(grants, natscell.NKeyGrant{PublicKey: public, Role: "controller"})
	}
	operatorNKey, operatorSeed := testNKey(t)
	grants = append(grants, natscell.NKeyGrant{PublicKey: operatorNKey, Role: "operator"})
	hostKeys := map[string][2]string{}
	for _, node := range nodes {
		public, seed := testNKey(t)
		hostKeys[node] = [2]string{public, seed}
		grants = append(grants, natscell.NKeyGrant{PublicKey: public, Role: "host", Node: node})
	}
	ports := reserveControllerPorts(t, 6)
	routes, urls := make([]string, 3), make([]string, 3)
	for index := range routes {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", ports[3+index])
		urls[index] = fmt.Sprintf("nats://127.0.0.1:%d", ports[index])
	}
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase", tsauth.Role}, Environments: []string{environment}, CanRegisterHosts: true,
		Repositories: []string{tsauth.Repository}}
	children := make([]*controllerChild, 3)
	for index := range children {
		instance := fmt.Sprintf("peer%d", index)
		config := testJSONFile(t, root, instance+".json", Config{
			NATS: natscell.Config{Cell: "gru", Instance: instance, Replicas: 3, Lab: true, NKeySeedFile: controllerSeeds[index],
				Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: ports[index], RouteHost: "127.0.0.1",
					RoutePort: ports[3+index], Routes: natscell.PeerRoutes(routes, routes[index]),
					StoreDir: filepath.Join(root, instance), StoreMaxBytes: 2 << 30, Users: grants}},
			Controller: ControllerConfig{CandidateID: instance, ResponseKeyFile: filepath.Join(root, "controller.key"),
				ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
				Workloads: map[string]WorkloadProfile{"terrabase": {Resources: placement.Resources{
					CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}}},
				ServiceTrust: &ServiceTrustConfig{RootPublicKeyFile: rootKey, DeploymentID: deployment,
					Environment: environment}},
		})
		children[index] = startControllerChild(t, controllerCtx, root, config, 1, index)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for index, child := range children {
				data, _ := os.ReadFile(child.logPath)
				t.Logf("controller peer%d log:\n%s", index, data)
			}
		}
	})
	for _, child := range children {
		waitControllerChildReady(t, controllerCtx, child)
	}
	ctx, cancelScenario := context.WithTimeout(controllerCtx, 4*time.Minute)
	defer cancelScenario()
	operatorConfig := testJSONFile(t, root, "operator.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "operator", Replicas: 3, Lab: true,
			URL: strings.Join(urls, ","), NKeySeedFile: operatorSeed},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}})
	var output bytes.Buffer
	run := func(args ...string) error {
		output.Reset()
		err := Run(ctx, args, &output)
		t.Logf("%s %s: %v\n%s", args[0], args[1], err, output.String())
		return err
	}
	sign := func(candidate, signed string) {
		t.Helper()
		output.Reset()
		if err := releasecli.Run(ctx, []string{"sign-service-set", "--candidate", candidate,
			"--delegation", filepath.Join(root, "service.delegation"), "--root-key", rootKey,
			"--signing-key", leafPrivateKey, "--out", signed}, &output); err != nil {
			t.Fatalf("sign %s: %v", candidate, err)
		}
	}

	// The root delegates service sets for this deployment to the leaf.
	now := time.Now().UTC().Truncate(time.Second)
	if err := releasecli.Run(ctx, []string{"sign-service-delegation", "--subject-public-key", leafKey,
		"--root-key", rootKey, "--signing-key", rootPrivateKey, "--deployment-id", deployment, "--cell", "gru",
		"--environment", environment, "--issued-at", now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		"--out", filepath.Join(root, "service.delegation")}, &output); err != nil {
		t.Fatalf("sign service delegation: %v", err)
	}
	profile := "../../deploy/oci-region/ts-auth-gru-1-profile.json"
	candidate := filepath.Join(root, "add-ts-auth.json")
	if err := run("service", "add", "--config", operatorConfig, "--role", tsauth.Role, "--profile", profile,
		"--spec", "../../deploy/oci-region/ts-auth-gru-1-service.json", "--out", candidate); err != nil ||
		!strings.Contains(output.String(), `"added":["ts-auth"]`) || !strings.Contains(output.String(), `"from_generation":0`) {
		t.Fatalf("plan ts-auth: %v", err)
	}
	signed := filepath.Join(root, "add-ts-auth.signed.json")
	sign(candidate, signed)
	if err := run("service", "apply", "--config", operatorConfig, "--file", signed); err != nil ||
		!strings.Contains(output.String(), `"status":"applied"`) {
		t.Fatalf("apply ts-auth: %v", err)
	}

	identity := testHostWorkloadIdentity()
	secrets := map[string]string{tsauth.EnvAPIKey: "tb_fake-key", tsauth.EnvProjectID: "0192f0c4-7d1e-7a2b-9c3d-4e5f6a7b8c9d"}
	for _, key := range tsauth.Generated {
		secrets[key], _ = tsauth.Generate(ctx)
	}
	vault := bundles{}
	for key, value := range secrets {
		vault[tsauth.SecretName("gru-1", key)] = value
	}
	replicas := map[string]*childRunner{}
	replicaPorts := map[string]int{}
	var agentsDone []chan error
	defer func() {
		cancelScenario()
		for _, done := range agentsDone {
			<-done
		}
		for _, runner := range replicas {
			_ = runner.Close(context.Background())
		}
	}()
	for index, node := range nodes {
		hostPublic, hostPrivate := testEd25519(t, root, node+".key")
		registration := testJSONFile(t, root, node+"-registration.json", host.Registration{Cell: "gru", Node: node,
			Environment: environment, Roles: []string{tsauth.Role}, FailureDomain: fmt.Sprintf("fault-domain-%d", index+1),
			PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostKeys[node][0], Generation: 1,
			Capacity: host.Capacity{CPU: 2, MemoryBytes: 4 << 30, DiskBytes: 8 << 30}})
		if err := run("operator", "host-register", "--config", operatorConfig, "--registration", registration); err != nil {
			t.Fatal(err)
		}
		hostRuntime, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "host-" + node, Replicas: 3,
			Lab: true, URL: strings.Join(urls, ","), NKeySeedFile: hostKeys[node][1], ClientRole: "host"})
		if err != nil {
			t.Fatal(err)
		}
		defer hostRuntime.Close()
		tsAuthRoot := filepath.Join(filepath.Dir(traversableTerraBaseRoot(t)), "ts-auth")
		if _, err := tsauth.WriteEnvFile(ctx, vault, "vault", tsauth.HostConfig{Cell: "gru-1", Root: tsAuthRoot,
			UID: identity.UID, GID: identity.GID}); err != nil {
			t.Fatal(err)
		}
		clock := &testBrokerClock{}
		clock.healthy.Store(true)
		replicaPorts[node] = freeTCPPort(t)
		replicas[node] = &childRunner{log: filepath.Join(root, node+".log"), fake: true, serve: fakeTSAuthReplica(secrets)}
		agent, err := host.NewAgent(host.AgentConfig{WorkloadIdentity: identity, Cell: "gru", Node: node,
			Environment: environment, Roles: []string{tsauth.Role}, Conn: hostRuntime.Conn(), Identity: hostPrivate,
			NATSUserPublicKey: hostKeys[node][0], ControllerPublicKey: controllerPublic, Runner: replicas[node],
			InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), ManagedRuntimeRoot: filepath.Dir(tsAuthRoot),
			TSAuthRoot: tsAuthRoot, TSAuthPort: replicaPorts[node],
			PollInterval: 200 * time.Millisecond, ClockCheck: controllerClockCheck(clock)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		agentsDone = append(agentsDone, done)
		go func() { done <- agent.Run(ctx) }()
	}

	checkout, commit := terraBaseSourceCheckout(t)
	binary := writeTSAuthRelease(t, filepath.Join(root, "release"), []byte(fakeTSAuthMagic+" first"))
	digest, err := tsauth.VerifyRelease(binary, binary+".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if err := run("operator", "ts-auth-release", "--config", operatorConfig, "--binary", binary,
		"--sha256", binary+".sha256", "--source-checkout", checkout, "--commit", commit, "--environment", environment,
		"--profile", profile, "--wait", "2m"); err != nil || !strings.Contains(output.String(), `"step":"ready"`) {
		t.Fatalf("ts-auth release: %v", err)
	}
	for _, node := range nodes {
		if observed, _ := replicas[node].Observe(ctx, tsauth.Role); !observed.Running || observed.Digest != digest {
			t.Fatalf("%s runs %s (running %v), want %s", node, observed.Digest, observed.Running, digest)
		}
		if err := tsauth.Probe(ctx, replicaPorts[node]); err != nil {
			t.Fatalf("%s: %v", node, err)
		}
	}

	removal := filepath.Join(root, "remove-ts-auth.json")
	if err := run("service", "remove", "--config", operatorConfig, "--role", tsauth.Role, "--out", removal); err != nil {
		t.Fatal(err)
	}
	sign(removal, removal+".signed")
	if err := run("service", "apply", "--config", operatorConfig, "--file", removal+".signed"); err == nil ||
		!strings.Contains(err.Error(), "scale it to zero") {
		t.Fatalf("removed ts-auth while its replicas run: %v", err)
	}
}

// writeTestPEMKeyPair writes an Ed25519 PKIX public key and an owner-only
// PKCS#8 private key, the trust key files operators sign with.
func writeTestPEMKeyPair(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicPath, privatePath := filepath.Join(dir, name+".pub.pem"), filepath.Join(dir, name+".key.pem")
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return publicPath, privatePath
}
