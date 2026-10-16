package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	hostservice "github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

const (
	r3BrokerCount            = 3
	r3BrokerStoreMaxBytes    = int64(2 << 30)
	r3IntentStoreMaxBytes    = int64(1 << 30)
	r3HostStateMaxBytes      = int64(256 << 20)
	r3PlacementStateMaxBytes = int64(128 << 20)
	r3ArtifactStoreMaxBytes  = int64(64 << 20)
)

func TestGeneratedFixtureHasPrivateFilesAndScopedClaims(t *testing.T) {
	secrets := t.TempDir()
	if err := os.Chmod(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"--dir", secrets, "--cell", "lab", "--brokers", "c1,c2,c3", "--host-node", "host-a",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("generate JWT fixture: %v; stderr=%s", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful generator wrote to stderr: %s", stderr.String())
	}
	var manifest publicManifest
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatalf("decode public manifest: %v", err)
	}
	if !nkeys.IsValidPublicOperatorKey(manifest.OperatorAccount) ||
		!nkeys.IsValidPublicAccountKey(manifest.SystemAccount) ||
		!nkeys.IsValidPublicAccountKey(manifest.CellAccount) || manifest.SystemAccount == manifest.CellAccount {
		t.Fatalf("manifest has invalid public account identities: %+v", manifest)
	}

	wantNames := outputNames([]string{"c1", "c2", "c3"})
	slices.Sort(wantNames)
	entries, err := os.ReadDir(secrets)
	if err != nil {
		t.Fatal(err)
	}
	gotNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotNames = append(gotNames, entry.Name())
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("fixture output %s has unsafe type or permissions: %v", entry.Name(), info.Mode())
		}
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("fixture outputs differ: got=%v want=%v", gotNames, wantNames)
	}
	directoryInfo, err := os.Stat(secrets)
	if err != nil || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("secrets directory is not private: err=%v", err)
	}
	if strings.Contains(stdout.String(), "-----BEGIN") {
		t.Fatal("public manifest contains decorated credentials")
	}
	for _, name := range []string{"operator.jwt", "system.jwt", "cell.jwt", "system.creds", "c1.creds", "c2.creds", "c3.creds", "host.creds", "operator.creds", "natsdiag.creds", "broker-ticket.key"} {
		contents, err := os.ReadFile(filepath.Join(secrets, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(stdout.Bytes(), contents) {
			t.Fatalf("public manifest contains contents of %s", name)
		}
	}

	operatorRaw := readFixtureJWT(t, filepath.Join(secrets, "operator.jwt"))
	operatorClaims, err := jwt.DecodeOperatorClaims(operatorRaw)
	if err != nil || operatorClaims.Subject != manifest.OperatorAccount || operatorClaims.SystemAccount != manifest.SystemAccount {
		t.Fatalf("operator JWT does not identify the manifest accounts: claims=%+v err=%v", operatorClaims, err)
	}
	systemRaw := readFixtureJWT(t, filepath.Join(secrets, "system.jwt"))
	systemClaims, err := jwt.DecodeAccountClaims(systemRaw)
	if err != nil || systemClaims.Subject != manifest.SystemAccount || !operatorClaims.DidSign(systemClaims) {
		t.Fatalf("system account JWT is not signed by the pinned operator: claims=%+v err=%v", systemClaims, err)
	}
	cellRaw := readFixtureJWT(t, filepath.Join(secrets, "cell.jwt"))
	cellClaims, err := jwt.DecodeAccountClaims(cellRaw)
	if err != nil || cellClaims.Subject != manifest.CellAccount || !operatorClaims.DidSign(cellClaims) {
		t.Fatalf("cell account JWT is not signed by the pinned operator: claims=%+v err=%v", cellClaims, err)
	}
	if cellClaims.Limits.JetStreamLimits.MemoryStorage != cellClaimMemoryBytes ||
		cellClaims.Limits.JetStreamLimits.DiskStorage != cellClaimDiskBytes ||
		cellClaims.Limits.JetStreamLimits.Streams != cellClaimStreams ||
		cellClaims.Limits.JetStreamLimits.Consumer != cellClaimConsumers {
		t.Fatalf("cell JetStream limits differ from the lab profile: %+v", cellClaims.Limits.JetStreamLimits)
	}

	publicUsers := make(map[string]struct{}, len(manifest.Users))
	for _, public := range manifest.Users {
		if !nkeys.IsValidPublicUserKey(public) {
			t.Fatalf("manifest contains invalid user identity %q", public)
		}
		if _, exists := publicUsers[public]; exists {
			t.Fatalf("fixture reused a user identity: %s", public)
		}
		publicUsers[public] = struct{}{}
	}
	if len(manifest.Users) != 7 || manifest.Users["c1"] == "" || manifest.Users["c2"] == "" ||
		manifest.Users["c3"] == "" || manifest.Users["host"] == "" ||
		manifest.Users["operator"] == "" || manifest.Users["natsdiag"] == "" || manifest.Users["system"] == "" {
		t.Fatalf("manifest is missing per-role identities: %+v", manifest.Users)
	}

	for _, broker := range []string{"c1", "c2", "c3"} {
		path := filepath.Join(secrets, broker+".creds")
		claim, public := readFixtureUser(t, path)
		if public != manifest.Users[broker] || claim.IssuerAccount != manifest.CellAccount {
			t.Fatalf("%s credentials have the wrong public identity or account issuer", broker)
		}
		if err := natscell.ValidateBrokerControllerCredentials(path, "lab", broker); err != nil {
			t.Fatalf("runtime rejected %s controller credentials: %v", broker, err)
		}
		wantPublish := []string{
			"ts.orch.v1.lab.>", "ts.control.lab.>", "$JS.API.>", "$KV.>", "$O.>",
			"$JS.ACK.TS_DELIVERY_INTENTS.TS_DELIVERY_WORKER.>",
			"ts.broker.lab.ticket.>", "ts.broker.lab.fence.>",
		}
		wantSubscribe := []string{
			"ts.orch.v1.lab.inbox." + public + ".>", "ts.orch.v1.lab.agent.*.observation.*",
			"ts.orch.v1.lab.delivery.artifact.admit", "ts.orch.v1.lab.host.register",
			"ts.orch.v1.lab.placement.apply", "ts.orch.v1.lab.broker.claim.apply",
			"ts.orch.v1.lab.managed-update.prepare", "ts.orch.v1.lab.backup.operation",
			"ts.broker.lab.ticket.>", "ts.broker.lab.fence." + broker,
			"ts.orch.v1.lab.terminal.>",
		}
		if !slices.Equal([]string(claim.Pub.Allow), wantPublish) || !slices.Equal([]string(claim.Sub.Allow), wantSubscribe) ||
			claim.Resp == nil || claim.Resp.MaxMsgs != 1 || claim.Resp.Expires != 5*time.Second ||
			len(claim.Pub.Deny) != 0 || len(claim.Sub.Deny) != 0 {
			t.Fatalf("%s controller grants differ from the runtime contract: pub=%v sub=%v resp=%+v", broker, claim.Pub.Allow, claim.Sub.Allow, claim.Resp)
		}
	}

	hostClaim, hostID := readFixtureUser(t, filepath.Join(secrets, "host.creds"))
	if hostID != manifest.Users["host"] || hostClaim.IssuerAccount != manifest.CellAccount ||
		!slices.Equal([]string(hostClaim.Pub.Allow), []string{hostObservationSubject("lab", "host-a")}) ||
		!slices.Equal([]string(hostClaim.Sub.Allow), []string{inboxPrefix("lab", hostID) + ".>"}) {
		t.Fatalf("host credential grants are not bound to host-a: pub=%v sub=%v", hostClaim.Pub.Allow, hostClaim.Sub.Allow)
	}

	operatorPath := filepath.Join(secrets, "operator.creds")
	operatorUserClaim, operatorID := readFixtureUser(t, operatorPath)
	if operatorID != manifest.Users["operator"] || operatorUserClaim.IssuerAccount != manifest.CellAccount ||
		!slices.Equal([]string(operatorUserClaim.Pub.Allow), []string(natscell.BrokerOperatorPublishPermissions("lab"))) ||
		!slices.Equal([]string(operatorUserClaim.Sub.Allow), []string{inboxPrefix("lab", operatorID) + ".>"}) ||
		operatorUserClaim.Resp != nil || len(operatorUserClaim.Pub.Deny) != 0 || len(operatorUserClaim.Sub.Deny) != 0 {
		t.Fatalf("operator credential grants are not scoped: pub=%v sub=%v", operatorUserClaim.Pub.Allow, operatorUserClaim.Sub.Allow)
	}
	if err := natscell.ValidateBrokerOperatorCredentials(operatorPath, "lab"); err != nil {
		t.Fatalf("runtime rejected restricted operator credentials: %v", err)
	}
	diagnosticPath := filepath.Join(secrets, "natsdiag.creds")
	diagnosticClaim, diagnosticID := readFixtureUser(t, diagnosticPath)
	if diagnosticID == operatorID || diagnosticID != manifest.Users["natsdiag"] ||
		!slices.Equal([]string(diagnosticClaim.Pub.Allow), diagnosticGrants("lab", "host-a")) ||
		!slices.Equal([]string(diagnosticClaim.Sub.Allow), []string{inboxPrefix("lab", diagnosticID) + ".>"}) {
		t.Fatalf("diagnostic credential grants are not scoped: pub=%v sub=%v", diagnosticClaim.Pub.Allow, diagnosticClaim.Sub.Allow)
	}
	if err := natscell.ValidateBrokerOperatorCredentials(diagnosticPath, "lab"); err == nil {
		t.Fatal("runtime accepted diagnostic credentials with grants beyond the restricted operator surface")
	}
	for _, subject := range diagnosticClaim.Pub.Allow {
		if strings.HasPrefix(subject, "ts.orch.v1.") || strings.HasPrefix(subject, "$JS.API.CONSUMER.CREATE.") ||
			strings.HasPrefix(subject, "$JS.API.CONSUMER.DELETE.") || strings.HasPrefix(subject, "$O.") {
			t.Fatalf("diagnostic JWT has a mutating publish grant %q", subject)
		}
	}
	for _, subject := range []string{
		"$JS.API.STREAM.INFO.KV_TS_HOST_STATE", "$JS.API.STREAM.MSG.GET.KV_TS_HOST_STATE",
		"$JS.API.STREAM.INFO.KV_TS_DELIVERY_OPERATIONS", "$JS.API.STREAM.MSG.GET.KV_TS_DELIVERY_OPERATIONS",
		"$JS.API.DIRECT.GET.KV_TS_HOST_STATE.$KV.TS_HOST_STATE.session.lab.host-a",
		"$JS.API.DIRECT.GET.KV_TS_HOST_STATE.$KV.TS_HOST_STATE.report.lab.host-a.terrabase",
		"$JS.API.DIRECT.GET.KV_TS_DELIVERY_OPERATIONS.$KV.TS_DELIVERY_OPERATIONS.*",
	} {
		if !slices.Contains([]string(diagnosticClaim.Pub.Allow), subject) {
			t.Fatalf("diagnostic JWT lacks the natsdiag read grant %q", subject)
		}
	}
	for _, subject := range []string{
		"$JS.API.>", "$KV.>", "$O.>", "$JS.API.STREAM.LEADER.>",
	} {
		if slices.Contains([]string(operatorUserClaim.Pub.Allow), subject) {
			t.Fatalf("operator JWT has an unnecessarily broad grant %q", subject)
		}
	}

	systemClaim, systemUserID := readFixtureUser(t, filepath.Join(secrets, "system.creds"))
	if systemUserID != manifest.Users["system"] || systemClaim.IssuerAccount != manifest.SystemAccount ||
		!slices.Equal([]string(systemClaim.Pub.Allow), []string{"$SYS.REQ.ACCOUNT." + manifest.CellAccount + ".CLAIMS.UPDATE"}) ||
		!slices.Equal([]string(systemClaim.Sub.Allow), []string{inboxPrefix("lab", systemUserID) + ".>"}) ||
		systemClaim.Resp != nil || len(systemClaim.Pub.Deny) != 0 || len(systemClaim.Sub.Deny) != 0 {
		t.Fatalf("system credentials exceed the claim-update and private-inbox grants: pub=%v sub=%v", systemClaim.Pub.Allow, systemClaim.Sub.Allow)
	}

	privateRaw, err := os.ReadFile(filepath.Join(secrets, "broker-ticket.key"))
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateRaw)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		t.Fatalf("ticket signer has invalid key encoding: %v", err)
	}
	defer clear(private)
	publicRaw, err := os.ReadFile(filepath.Join(secrets, "broker-ticket.pub"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicRaw)))
	if err != nil || len(public) != ed25519.PublicKeySize || !bytes.Equal(private[32:], public) {
		t.Fatalf("ticket signer and public pin do not match: %v", err)
	}

	secondSecrets := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(secondSecrets, 0o700); err != nil {
		t.Fatal(err)
	}
	secondManifest, err := generateFixture(secondSecrets, "lab", []string{"c1", "c2", "c3"}, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OperatorAccount == secondManifest.OperatorAccount || manifest.SystemAccount == secondManifest.SystemAccount ||
		manifest.CellAccount == secondManifest.CellAccount || manifest.Users["c1"] == secondManifest.Users["c1"] {
		t.Fatal("separate fixture runs reused a NATS identity")
	}
}

func TestGeneratedFixtureReservesProductionR3StoresWithProductionJWTAndTLS(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := generateFixture(secrets, "lab", []string{"c1", "c2", "c3"}, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	tlsFiles := testTLSFiles(t, filepath.Join(root, "tls"))
	ports := availablePorts(t, 2*r3BrokerCount)
	clientPorts := ports[:r3BrokerCount]
	routePorts := ports[r3BrokerCount:]
	routes := make([]string, r3BrokerCount)
	for index, routePort := range routePorts {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", routePort)
	}
	routePasswordFile := filepath.Join(root, "route-password")
	writeTestFile(t, routePasswordFile, []byte("jwtsetup-r3-route-password"))
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	brokers := make([]*natscell.Runtime, r3BrokerCount)
	for index := range brokers {
		brokerID := fmt.Sprintf("c%d", index+1)
		broker, err := natscell.Start(ctx, natscell.Config{
			Cell: "lab", Instance: brokerID, Replicas: r3BrokerCount, ClientRole: "controller",
			CredentialsFile: filepath.Join(secrets, brokerID+".creds"), TLS: tlsFiles,
			Embedded: &natscell.Embedded{
				Host: "127.0.0.1", Port: clientPorts[index],
				RouteHost: "127.0.0.1", RoutePort: routePorts[index], Routes: natscell.PeerRoutes(routes, routes[index]),
				RouteUser: "route", RoutePasswordFile: routePasswordFile,
				StoreDir: filepath.Join(root, "store", brokerID), StoreMaxBytes: r3BrokerStoreMaxBytes,
				TLS: tlsFiles, RouteTLS: tlsFiles,
				OperatorJWTFile:       filepath.Join(secrets, "operator.jwt"),
				SystemJWTFile:         filepath.Join(secrets, "system.jwt"),
				CellJWTFile:           filepath.Join(secrets, "cell.jwt"),
				SystemCredentialsFile: filepath.Join(secrets, "system.creds"),
				TicketPublicKeyFile:   filepath.Join(secrets, "broker-ticket.pub"),
				BrokerIDs:             []string{"c1", "c2", "c3"},
			},
		})
		if err != nil {
			t.Fatalf("production embedded runtime rejected generated %s fixture: %v", brokerID, err)
		}
		brokers[index] = broker
		t.Cleanup(func() { _ = broker.Close() })
	}
	broker := brokers[0]
	for _, peer := range brokers {
		if peer.Bridge().Status().Open {
			t.Fatal("production client bridge opened before an account claim was applied")
		}
	}
	cellJWT := readFixtureJWT(t, filepath.Join(secrets, "cell.jwt"))
	for _, peer := range brokers {
		if err := peer.ApplyCellClaim(ctx, 1, cellJWT); err != nil {
			t.Fatalf("apply generated cell JWT through production runtime: %v", err)
		}
	}
	for _, peer := range brokers {
		if err := peer.WaitForCluster(ctx, r3BrokerCount); err != nil {
			t.Fatalf("wait for production R3 broker cluster: %v", err)
		}
	}
	bridgeDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("production bridge fixture requires a bounded test context")
	}
	if err := broker.Bridge().OpenUntil(1, cellJWT, bridgeDeadline); err != nil {
		t.Fatalf("open production bridge for the applied JWT: %v", err)
	}

	operator, err := natscell.Start(ctx, natscell.Config{
		Cell: "lab", Instance: "operator", Replicas: 1, ClientRole: "operator",
		URL: broker.URL(), CredentialsFile: filepath.Join(secrets, "operator.creds"), TLS: tlsFiles,
	})
	if err != nil {
		t.Fatalf("production bridge rejected generated operator credentials: %v", err)
	}
	t.Cleanup(func() { _ = operator.Close() })
	if err := operator.Conn().FlushWithContext(ctx); err != nil {
		t.Fatalf("operator JWT could not complete an authenticated NATS flush: %v", err)
	}

	host, err := natscell.Start(ctx, natscell.Config{
		Cell: "lab", Instance: "host-a", Replicas: 1, ClientRole: "host",
		URL: broker.URL(), CredentialsFile: filepath.Join(secrets, "host.creds"), TLS: tlsFiles,
	})
	if err != nil {
		t.Fatalf("production bridge rejected generated host credentials: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })
	hostDigest := sha256.Sum256([]byte("host-a"))
	observation := "ts.orch.v1.lab.agent." + fmt.Sprintf("%x", hostDigest) + ".observation.status"
	if err := host.Conn().Publish(observation, []byte("{}")); err != nil {
		t.Fatalf("host could not publish its scoped observation: %v", err)
	}
	if err := host.Conn().FlushWithContext(ctx); err != nil {
		t.Fatalf("host observation did not pass the production NATS ACL: %v", err)
	}

	deliveryService, err := delivery.Open(ctx, delivery.Config{
		Conn: broker.Conn(), JS: broker.JetStream(), Cell: "lab", Replicas: r3BrokerCount,
		ArtifactStoreMaxBytes: r3ArtifactStoreMaxBytes,
	})
	if err != nil {
		t.Fatalf("generated cell JWT rejected production delivery stores at R3: %v", err)
	}
	controlLog, err := broker.JetStream().CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: authority.ControlStreamName, Subjects: []string{"ts.control.*.>"},
		Storage: jetstream.FileStorage, Replicas: r3BrokerCount, MaxBytes: -1,
	})
	if err != nil {
		t.Fatalf("create control log required by production host controller: %v", err)
	}
	_, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseKey)
	if _, err := hostservice.NewController(ctx, hostservice.ControllerConfig{
		Cell: "lab", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: deliveryService.Artifacts(),
		ResponseKey: responseKey, StateReplicas: r3BrokerCount,
		AuthorityEpoch: func() uint64 { return 1 }, AuthorityGuard: func(context.Context, uint64) error { return nil },
		HostMutations: quotaTestHostMutations{}, ControlLog: controlLog,
	}); err != nil {
		t.Fatalf("generated cell JWT rejected production host state at R3: %v", err)
	}
	if _, err := placement.NewJetStreamStore(ctx, broker.JetStream(), "lab", r3BrokerCount, emptyPlacementIntentReader{}); err != nil {
		t.Fatalf("generated cell JWT rejected production placement state at R3: %v", err)
	}
	assertR3StreamReservation(t, ctx, broker.JetStream(), "OBJ_"+delivery.ArtifactBucket, r3ArtifactStoreMaxBytes)
	assertR3StreamReservation(t, ctx, broker.JetStream(), delivery.IntentStream, r3IntentStoreMaxBytes)
	assertR3KeyValueReservation(t, ctx, broker.JetStream(), "TS_HOST_STATE", r3HostStateMaxBytes)
	assertR3KeyValueReservation(t, ctx, broker.JetStream(), "TS_PLACEMENT_STATE", r3PlacementStateMaxBytes)

	if broker.Bridge().Status().ActiveSessions != 2 {
		t.Fatalf("production bridge did not retain both authorized TLS clients: %+v", broker.Bridge().Status())
	}
	if manifest.CellAccount != broker.CellAccount() {
		t.Fatal("runtime loaded a different cell account than the public manifest")
	}
}

type quotaTestHostMutations struct{}

func (quotaTestHostMutations) CommitHostMutation(context.Context, uint64, authority.HostMutationKind, string, string, uint64, []byte) (uint64, error) {
	return 1, nil
}

func (quotaTestHostMutations) ReadHostMutation(context.Context, authority.HostMutationKind, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, nil
}

type emptyPlacementIntentReader struct{}

func (emptyPlacementIntentReader) ListPlacementIntents(context.Context, string) ([]placement.Intent, error) {
	return nil, nil
}

func (emptyPlacementIntentReader) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

func assertR3StreamReservation(t *testing.T, ctx context.Context, js jetstream.JetStream, name string, wantMaxBytes int64) {
	t.Helper()
	stream, err := js.Stream(ctx, name)
	if err != nil {
		t.Fatalf("lookup R3 stream %s: %v", name, err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("inspect R3 stream %s: %v", name, err)
	}
	if info.Config.Replicas != r3BrokerCount || info.Config.MaxBytes != wantMaxBytes {
		t.Fatalf("R3 stream %s reservations = replicas %d, max bytes %d; want %d, %d", name,
			info.Config.Replicas, info.Config.MaxBytes, r3BrokerCount, wantMaxBytes)
	}
}

func assertR3KeyValueReservation(t *testing.T, ctx context.Context, js jetstream.JetStream, name string, wantMaxBytes int64) {
	t.Helper()
	kv, err := js.KeyValue(ctx, name)
	if err != nil {
		t.Fatalf("lookup R3 key value %s: %v", name, err)
	}
	status, err := kv.Status(ctx)
	if err != nil {
		t.Fatalf("inspect R3 key value %s: %v", name, err)
	}
	config := status.Config()
	if config.Replicas != r3BrokerCount || config.MaxBytes != wantMaxBytes {
		t.Fatalf("R3 key value %s reservations = replicas %d, max bytes %d; want %d, %d", name,
			config.Replicas, config.MaxBytes, r3BrokerCount, wantMaxBytes)
	}
}

func TestGeneratorRejectsUnsafeOrExistingDestinations(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := generateFixture(unsafe, "lab", []string{"c1", "c2", "c3"}, "host-a"); err == nil {
		t.Fatal("generator accepted a group-readable secrets directory")
	}
	secrets := filepath.Join(root, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	preexisting := filepath.Join(secrets, "operator.jwt")
	if err := os.WriteFile(preexisting, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"--dir", secrets, "--cell", "lab", "--brokers", "c1,c2,c3", "--host-node", "host-a"}, &stdout, &stderr)
	if err == nil || stdout.Len() != 0 {
		t.Fatalf("generator accepted a pre-existing output or emitted a manifest: err=%v stdout=%q", err, stdout.String())
	}
	contents, err := os.ReadFile(preexisting)
	if err != nil || string(contents) != "preserve-me" {
		t.Fatalf("generator modified a pre-existing output: contents=%q err=%v", contents, err)
	}
	entries, err := os.ReadDir(secrets)
	if err != nil || len(entries) != 1 || entries[0].Name() != "operator.jwt" {
		t.Fatalf("failed generation left partial outputs: entries=%v err=%v", entries, err)
	}
}

func readFixtureJWT(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func readFixtureUser(t *testing.T, path string) (*jwt.UserClaims, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nkeys.ParseDecoratedUserNKey(data)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil || public != claim.Subject {
		t.Fatalf("credential seed and signed JWT differ: public=%q subject=%q err=%v", public, claim.Subject, err)
	}
	return claim, public
}

func testTLSFiles(t *testing.T, directory string) natscell.TLSFiles {
	t.Helper()
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "jwtsetup test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	certPath := filepath.Join(directory, "peer.pem")
	keyPath := filepath.Join(directory, "peer-key.pem")
	writeTestFile(t, caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	writeTestFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	writeTestFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return natscell.TLSFiles{CAFile: caPath, CertFile: certPath, KeyFile: keyPath}
}

func writeTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func availablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func availablePorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	ports := make([]int, 0, count)
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, open := range listeners {
				_ = open.Close()
			}
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return ports
}
