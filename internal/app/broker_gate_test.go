package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type testBrokerClock struct{ healthy atomic.Bool }

func (c *testBrokerClock) Measure() (brokerauth.ClockBound, error) {
	if !c.healthy.Load() {
		return brokerauth.ClockBound{}, errors.New("test clock unsynchronized")
	}
	return brokerauth.ClockBound{SampledAt: time.Now(), MaxError: time.Millisecond}, nil
}

func TestBrokerGateR3TicketRevocationAndOfflineFence(t *testing.T) {
	// Includes four adversarial CLI requests before the ordinary R3 fence path.
	// The fast tier covers the forged replies in
	// TestBrokerClaimReplyRejectsForgedReceipts and a ticket for a revoked
	// claim in brokerauth; this lab adds three real brokers, the host
	// disconnect and the offline-broker pending path.
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	tlsFiles, routePassword := testR3TLSMaterial(t, root)
	opKey, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	sysKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	cellKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	opID, _ := opKey.PublicKey()
	sysID, _ := sysKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	op := jwt.NewOperatorClaims(opID)
	op.SystemAccount = sysID
	opRaw, err := op.Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	sysRaw, err := jwt.NewAccountClaims(sysID).Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	cell := jwt.NewAccountClaims(cellID)
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 128 << 20, DiskStorage: 1 << 30, Streams: 40, Consumer: 40}
	cellRaw, err := cell.Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, raw string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	opFile := write("operator.jwt", opRaw)
	sysFile := write("system.jwt", sysRaw)
	cellFile := write("cell.jwt", cellRaw)
	operatorPublic, _ := testEd25519(t, root, "claim-operator.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"test"}, CanRotateBrokerAccount: true}
	ticketPub, ticketPrivate := testEd25519(t, root, "broker-ticket.key")
	ticketPubFile := write("broker-ticket.pub", base64.StdEncoding.EncodeToString(ticketPub))
	brokerIDs := []string{"broker-a", "broker-b", "broker-c"}
	ports := reserveControllerPorts(t, 2*len(brokerIDs))
	clientPorts, routePorts := ports[:len(brokerIDs)], ports[len(brokerIDs):]
	routes := make([]string, len(brokerIDs))
	for index, port := range routePorts {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", port)
	}
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	runtimes := make([]*natscell.Runtime, 3)
	configs := make([]natscell.Config, 3)
	for index, id := range brokerIDs {
		controllerPub, controllerCreds := testBrokerJWTUser(t, root, fmt.Sprintf("controller-%d.creds", index), cellKey, cellID,
			[]string{"ts.control.gru.>", "ts.broker.gru.ticket.>", "ts.broker.gru.fence.>", "$JS.API.>", "$JS.ACK.>"}, nil)
		// ClientOptions sets this exact private inbox prefix for the user.
		controllerClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, controllerCreds))
		if err != nil {
			t.Fatal(err)
		}
		controllerClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + controllerPub + ".>",
			"ts.broker.gru.ticket.>", "ts.broker.gru.fence." + id, "ts.orch.v1.gru.broker.claim.apply",
			"ts.orch.v1.gru.managed-update.prepare", "ts.orch.v1.gru.backup.operation", "ts.orch.v1.gru.terminal.>"}
		controllerClaim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
		controllerCreds = testBrokerJWTUserWithClaim(t, root, fmt.Sprintf("controller-%d.creds", index), cellKey, controllerClaim)
		systemPub, systemCreds := testBrokerJWTUser(t, root, fmt.Sprintf("system-%d.creds", index), sysKey, sysID,
			[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, nil)
		systemClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, systemCreds))
		if err != nil {
			t.Fatal(err)
		}
		systemClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + systemPub + ".>"}
		systemCreds = testBrokerJWTUserWithClaim(t, root, fmt.Sprintf("system-%d.creds", index), sysKey, systemClaim)
		configs[index] = natscell.Config{Cell: "gru", Instance: id, Replicas: 3, CredentialsFile: controllerCreds, TLS: tlsFiles,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: clientPorts[index], RouteHost: "127.0.0.1", RoutePort: routePorts[index],
				Routes: natscell.PeerRoutes(routes, routes[index]), StoreDir: filepath.Join(root, id), StoreMaxBytes: 2 << 30, TLS: tlsFiles, RouteTLS: tlsFiles,
				RouteUser: "r3-test-route", RoutePasswordFile: routePassword,
				OperatorJWTFile: opFile, SystemJWTFile: sysFile, CellJWTFile: cellFile, SystemCredentialsFile: systemCreds,
				TicketPublicKeyFile: ticketPubFile, BrokerIDs: brokerIDs}}
	}
	startErrors := make([]error, len(runtimes))
	var starts sync.WaitGroup
	for index := range runtimes {
		starts.Go(func() { runtimes[index], startErrors[index] = natscell.Start(ctx, configs[index]) })
	}
	starts.Wait()
	for _, peer := range runtimes {
		if peer != nil {
			t.Cleanup(func() { _ = peer.Close() })
		}
	}
	for index, peer := range runtimes {
		if startErrors[index] != nil {
			t.Fatalf("start %s: %v", brokerIDs[index], startErrors[index])
		}
		if peer.Bridge().Status().Open {
			t.Fatal("production bridge opened before authority")
		}
	}
	for _, runtime := range runtimes {
		if err := runtime.WaitForCluster(ctx, 3); err != nil {
			t.Fatal(err)
		}
	}
	// A metadata quorum can answer AccountInfo before every broker is ready
	// to host the new R3 authority stream. Require the full founding set.
	readyTicker := time.NewTicker(100 * time.Millisecond)
	defer readyTicker.Stop()
	fullClusterStatus := func() []bool {
		status := make([]bool, len(runtimes))
		for index, runtime := range runtimes {
			status[index] = runtime.FullClusterReady(3)
		}
		return status
	}
	for {
		status := fullClusterStatus()
		if !slices.Contains(status, false) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("founding R3 brokers never became fully ready: %v; full=%v", ctx.Err(), status)
		case <-readyTicker.C:
		}
	}
	controls := make([]*authority.Runtime, 3)
	gates := make([]*brokerGate, 3)
	admissionSubs := make([]*nats.Subscription, 3)
	gateCancel := make([]context.CancelFunc, 3)
	for index, id := range brokerIDs {
		broker := runtimes[index]
		control, stopAuthority, err := retryControllerOpen(ctx, "start "+id+" authority", func() bool { return broker.FullClusterReady(3) }, true,
			func(attempt context.Context) (*authority.Runtime, error) {
				return authority.Start(attempt, broker.JetStream(), authority.Config{
					Scope: "gru", CandidateID: entityid.Derive("test-controller", id), Replicas: 3, LeaseDuration: 12 * time.Second, RenewInterval: 2 * time.Second,
					ClockCheck: func() error { _, err := clock.Measure(); return err }})
			}, func(control *authority.Runtime) { _ = control.Close() })
		if err != nil {
			t.Fatalf("start %s authority: %v; full=%v", id, err, fullClusterStatus())
		}
		controls[index] = control
		t.Cleanup(func() { stopAuthority(); _ = control.Close() })
		var gateCtx context.Context
		gateCtx, gateCancel[index] = context.WithCancel(ctx)
		gates[index], err = startBrokerGate(gateCtx, Config{NATS: configs[index]}, runtimes[index], controls[index], entityid.Derive("test-controller", id), ticketPrivate, ticketPub, clock)
		if err != nil {
			t.Fatalf("start %s gate: %v", id, err)
		}
		policy, err := buildSignerPolicy(Config{NATS: configs[index], Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
		if err != nil {
			t.Fatal(err)
		}
		sub, err := serveBrokerClaimAdmission(gateCtx, runtimes[index].Conn(), "gru", policy, gates[index])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
		admissionSubs[index] = sub
	}
	operatorPub, operatorCreds := testBrokerJWTUser(t, root, "claim-operator.creds", cellKey, cellID,
		[]string(natscell.BrokerOperatorPublishPermissions("gru")), nil)
	operatorClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, operatorCreds))
	if err != nil {
		t.Fatal(err)
	}
	operatorClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + operatorPub + ".>"}
	operatorCreds = testBrokerJWTUserWithClaim(t, root, "claim-operator.creds", cellKey, operatorClaim)
	operatorConfig := Config{NATS: natscell.Config{Cell: "gru", Instance: "claim-operator", Replicas: 3, URL: configs[0].URL,
		CredentialsFile: operatorCreds, TLS: tlsFiles},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "claim-operator.key"), BrokerTicketPublicKeyFile: ticketPubFile}}
	// The embedded broker client URL is the external mTLS bridge address.
	operatorConfig.NATS.URL = fmt.Sprintf("tls://127.0.0.1:%d", clientPorts[0])
	operatorConfigPath := testJSONFile(t, root, "claim-operator.json", operatorConfig)
	waitBrokerGateStatus(t, ctx, runtimes, func(status natscell.BridgeStatus) bool { return status.Open && status.ClaimSequence > 0 })
	_, hostCreds := testBrokerJWTUser(t, root, "host.creds", cellKey, cellID, nil, nil)
	_, hostID, err := brokerJWTUser(hostCreds)
	if err != nil {
		t.Fatal(err)
	}
	hosts := make([]*natscell.Runtime, 3)
	for index, runtime := range runtimes {
		hosts[index], err = natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: fmt.Sprintf("host-%d", index), Replicas: 3,
			ClientRole: "host", URL: runtime.URL(), CredentialsFile: hostCreds, TLS: tlsFiles})
		if err != nil {
			t.Fatalf("host real caller through %s: %v", brokerIDs[index], err)
		}
		host := hosts[index]
		t.Cleanup(func() { _ = host.Close() })
	}
	leader := -1
	for index, control := range controls {
		if control.Current().CanMutate() {
			leader = index
			break
		}
	}
	if leader < 0 {
		t.Fatal("no regional authority leader")
	}
	currentClaim := runtimes[leader].Bridge().Status()
	follower := (leader + 1) % len(runtimes)
	for _, forged := range []fenceRequest{
		{Cell: "gru", Account: cellID, Sequence: currentClaim.ClaimSequence, Hash: "wrong-hash"},
		{Cell: "gru", Account: cellID, Sequence: ^uint64(0), Hash: "wrong-hash"},
	} {
		wire, err := json.Marshal(forged)
		if err != nil {
			t.Fatal(err)
		}
		requestCtx, stop := context.WithTimeout(ctx, 250*time.Millisecond)
		_, err = runtimes[follower].Conn().RequestWithContext(requestCtx,
			brokerRPCSubject("gru", "fence", brokerIDs[leader]), wire)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, nats.ErrTimeout) {
			t.Fatalf("forged fence got a response or unexpected error: %v", err)
		}
		probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
		waitBrokerGateStatus(t, probeCtx, runtimes, func(status natscell.BridgeStatus) bool {
			return status.Open && status.ClaimSequence == currentClaim.ClaimSequence
		})
		probeCancel()
	}
	time.Sleep(time.Until(time.Unix(cell.IssuedAt+1, 0)))
	cell.Revoke(hostID)
	revokedRaw, err := cell.Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	revokedFile := write("revoked.jwt", revokedRaw)
	if err := admissionSubs[leader].Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	rogueConfig := configs[follower]
	rogueConfig.Instance = "rogue-controller"
	rogueConfig.URL = runtimes[follower].URL()
	rogueConfig.Embedded = nil
	rogueRuntime, err := natscell.Start(ctx, rogueConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer rogueRuntime.Close()
	var forgedMode atomic.Int32
	var forgedReplies atomic.Int32
	rogue, err := rogueRuntime.Conn().Subscribe(brokerClaimApplySubject("gru"), func(message *nats.Msg) {
		var wire []byte
		switch forgedMode.Load() {
		case 1:
			wire = []byte(`{"status":"fenced","sequence":1,"hash":"0000000000RPYNQGXVXJSC20CX"}`)
		case 2:
			wire = []byte(`{"error":"control log compare-and-set conflict"}`)
		case 3, 4, 5:
			digest := sha256.Sum256([]byte(revokedRaw))
			requestDigest := sha256.Sum256(message.Data)
			payload, err := json.Marshal(brokerClaimApplyResponse{Cell: "gru", Account: cellID,
				RequestHash: hex.EncodeToString(requestDigest[:]), ExpectedSequence: currentClaim.ClaimSequence,
				Status: "fenced", Sequence: currentClaim.ClaimSequence + 1, Hash: hex.EncodeToString(digest[:])})
			if err != nil {
				return
			}
			kind, operationID := "broker.claim.other", brokerClaimOperationID(revokedRaw)
			if forgedMode.Load() == 4 {
				kind, operationID = "broker.claim.receipt", brokerClaimOperationID(cellRaw)
			} else if forgedMode.Load() == 5 {
				kind = "broker.claim.receipt"
			}
			now := time.Now().UTC()
			proof, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
				Region: "gru", Kind: kind, Actor: "broker-controller", OperationID: operationID,
				Generation: currentClaim.ClaimSequence + 1, Epoch: controls[leader].Current().Epoch,
			}, now, now.Add(time.Minute), ticketPrivate)
			if err != nil {
				return
			}
			wire, err = json.Marshal(brokerClaimApplyReply{Proof: &proof})
			if err != nil {
				return
			}
		}
		if err := message.Respond(wire); err == nil {
			forgedReplies.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rogueRuntime.Conn().FlushTimeout(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct {
		mode  int32
		name  string
		cause string
	}{{1, "unsigned success", "decode untrusted"}, {2, "unsigned error", "unsigned broker claim reply"},
		{3, "signed wrong scope", "scope does not match"}, {4, "replayed signed claim", "scope does not match"},
		{5, "signed uncommitted claim", "durable claim differs"}} {
		forgedMode.Store(variant.mode)
		before := forgedReplies.Load()
		var forgedOutput bytes.Buffer
		err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath, "--file", revokedFile,
			"--expected-sequence", strconv.FormatUint(currentClaim.ClaimSequence, 10)}, &forgedOutput)
		if err == nil || !strings.Contains(err.Error(), "outcome unknown") ||
			!strings.Contains(err.Error(), variant.cause) || forgedOutput.Len() != 0 || forgedReplies.Load() == before {
			t.Fatalf("%s reply was accepted: err=%v output=%q", variant.name, err, forgedOutput.String())
		}
	}
	if err := rogue.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	policy, err := buildSignerPolicy(Config{NATS: configs[leader], Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	admissionSubs[leader], err = serveBrokerClaimAdmission(ctx, runtimes[leader].Conn(), "gru", policy, gates[leader])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admissionSubs[leader].Unsubscribe() })
	var output bytes.Buffer
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath, "--file", revokedFile,
		"--expected-sequence", strconv.FormatUint(currentClaim.ClaimSequence, 10)}, &output); err != nil {
		t.Fatalf("R3 operator revocation failed: %v", err)
	}
	var receipt brokerClaimApplyResponse
	if err := json.Unmarshal(output.Bytes(), &receipt); err != nil || receipt.Status != "fenced" {
		t.Fatalf("R3 operator revocation receipt: %s, %v", output.String(), err)
	}
	claimAfter, err := gates[leader].store.Read(ctx, cellID)
	if err != nil || claimAfter.Sequence != receipt.Sequence || claimAfter.Hash != receipt.Hash {
		t.Fatalf("R3 durable claim differs from CLI receipt: %+v, %v", claimAfter, err)
	}
	result := fenceResult{Claim: claimAfter}
	for _, host := range hosts {
		for host.Conn().IsConnected() {
			if ctx.Err() != nil {
				t.Fatal("revoked host session remained connected")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitBrokerGateStatus(t, ctx, runtimes, func(status natscell.BridgeStatus) bool {
		return status.Open && status.ClaimSequence == result.Claim.Sequence && status.JWTHash == result.Claim.Hash
	})
	// A stale request for a different claim must leave the current bridge open.
	stale := write("stale.jwt", cellRaw)
	output.Reset()
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath, "--file", stale,
		"--expected-sequence", strconv.FormatUint(currentClaim.ClaimSequence, 10)}, &output); err == nil {
		t.Fatal("stale broker claim was accepted")
	}
	for _, peer := range runtimes {
		if !peer.Bridge().Status().Open {
			t.Fatal("stale broker claim closed a bridge")
		}
	}
	if deadline, ok := ctx.Deadline(); ok {
		t.Logf("offline broker phase: remaining=%s authority=%+v", time.Until(deadline), controls[leader].Current())
	}
	infoCtx, infoCancel := context.WithTimeout(ctx, 2*time.Second)
	stream, err := runtimes[leader].JetStream().Stream(infoCtx, authority.ControlStreamName)
	if err != nil {
		t.Fatalf("inspect control stream before offline broker: %v", err)
	}
	info, err := stream.Info(infoCtx)
	infoCancel()
	if err != nil || info.Cluster == nil || info.Cluster.Leader == "" {
		t.Fatalf("control stream leader unavailable before offline broker: %v", err)
	}
	t.Logf("offline broker phase control stream: leader=%s replicas=%d", info.Cluster.Leader, len(info.Cluster.Replicas))
	offline := -1
	for index, id := range brokerIDs {
		if index != leader && "gru-"+id != info.Cluster.Leader {
			offline = index
			break
		}
	}
	if offline < 0 {
		t.Fatal("no nonleader broker available for offline fence test")
	}
	gateCancel[offline]()
	_ = controls[offline].Close()
	_ = runtimes[offline].Close()
	for index, peer := range runtimes {
		if index != offline {
			if err := peer.WaitForCluster(ctx, 3); err != nil {
				t.Fatalf("remaining broker %s lost quorum: %v", brokerIDs[index], err)
			}
		}
	}
	time.Sleep(time.Until(time.Unix(cell.IssuedAt+1, 0)))
	otherUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := otherUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cell.Revoke(otherID)
	nextRaw, err := cell.Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	nextFile := write("offline-revocation.jwt", nextRaw)
	activeBroker := leader
	offlineOperator := operatorConfig
	offlineOperator.NATS.URL = fmt.Sprintf("tls://127.0.0.1:%d", clientPorts[activeBroker])
	offlineOperatorPath := testJSONFile(t, root, "offline-operator.json", offlineOperator)
	// Route quorum does not prove the live broker's authority-backed claim bridge is ready.
	waitBrokerGateStatus(t, ctx, []*natscell.Runtime{runtimes[activeBroker]}, func(status natscell.BridgeStatus) bool {
		return status.Open && status.ClaimSequence == result.Claim.Sequence && status.JWTHash == result.Claim.Hash
	})
	var pendingOutput bytes.Buffer
	err = Run(ctx, []string{"operator", "broker-claim-apply", "--config", offlineOperatorPath, "--file", nextFile,
		"--expected-sequence", strconv.FormatUint(result.Claim.Sequence, 10)}, &pendingOutput)
	if !errors.Is(err, ErrBrokerFencePending) {
		t.Fatalf("offline broker claim command did not exit pending: %v", err)
	}
	var pending brokerClaimApplyResponse
	if err := json.Unmarshal(pendingOutput.Bytes(), &pending); err != nil || pending.Status != "pending" ||
		pending.Sequence <= result.Claim.Sequence || !slices.Contains(pending.Pending, brokerIDs[offline]) {
		t.Fatalf("offline broker was counted or pending receipt invalid: %s, %v", pendingOutput.String(), err)
	}
	current, err := gates[leader].store.Read(ctx, cellID)
	if err != nil || current.Sequence != pending.Sequence || current.Hash != pending.Hash || current.JWT != nextRaw {
		t.Fatalf("offline durable claim differs from pending receipt: %+v, %v", current, err)
	}
	pendingOutput.Reset()
	err = Run(ctx, []string{"operator", "broker-claim-apply", "--config", offlineOperatorPath, "--file", nextFile,
		"--expected-sequence", strconv.FormatUint(result.Claim.Sequence, 10)}, &pendingOutput)
	if !errors.Is(err, ErrBrokerFencePending) {
		t.Fatalf("idempotent offline broker retry did not remain pending: %v", err)
	}
	var retried brokerClaimApplyResponse
	if err := json.Unmarshal(pendingOutput.Bytes(), &retried); err != nil || retried.Status != "pending" ||
		retried.Sequence != pending.Sequence || retried.Hash != pending.Hash || !slices.Contains(retried.Pending, brokerIDs[offline]) {
		t.Fatalf("idempotent pending receipt differs: %s, %v", pendingOutput.String(), err)
	}
}

func waitBrokerGateStatus(t *testing.T, ctx context.Context, runtimes []*natscell.Runtime, accept func(natscell.BridgeStatus) bool) {
	t.Helper()
	for {
		ready := true
		for _, runtime := range runtimes {
			if !accept(runtime.Bridge().Status()) {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("regional broker gate did not converge: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func testBrokerJWTUser(t *testing.T, root, name string, account nkeys.KeyPair, accountID string, publish, subscribe []string) (string, string) {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := user.PublicKey()
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	if publish != nil {
		claim.Pub.Allow = jwt.StringList(publish)
	}
	if subscribe != nil {
		claim.Sub.Allow = jwt.StringList(subscribe)
	}
	return userID, testBrokerJWTUserWithKey(t, root, name, account, user, claim)
}

func testBrokerJWTUserWithClaim(t *testing.T, root, name string, account nkeys.KeyPair, claim *jwt.UserClaims) string {
	t.Helper()
	// Preserve the seed from the file that was just written for this claim.
	path := filepath.Join(root, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.ParseDecoratedUserNKey(data)
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	return testBrokerJWTUserWithKey(t, root, name, account, user, claim)
}

func testBrokerJWTUserWithKey(t *testing.T, root, name string, account, user nkeys.KeyPair, claim *jwt.UserClaims) string {
	t.Helper()
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	data, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testDecoratedJWT(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func brokerJWTUser(path string) (*jwt.UserClaims, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		return nil, "", err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return nil, "", err
	}
	return claim, claim.Subject, nil
}
