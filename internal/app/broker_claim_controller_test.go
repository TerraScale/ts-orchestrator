package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestRunControllerOperatorBrokerClaimApply(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	tlsFiles, _ := testR3TLSMaterial(t, root)
	operatorKey, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	systemKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	cellKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, _ := operatorKey.PublicKey()
	systemID, _ := systemKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	operatorClaims := jwt.NewOperatorClaims(operatorID)
	operatorClaims.SystemAccount = systemID
	operatorJWT, err := operatorClaims.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	systemJWT, err := jwt.NewAccountClaims(systemID).Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	cellClaims := jwt.NewAccountClaims(cellID)
	cellClaims.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 128 << 20, DiskStorage: 2 << 30, Streams: 40, Consumer: 40}
	cellJWT, err := cellClaims.Encode(operatorKey)
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
	operatorFile := write("operator.jwt", operatorJWT)
	systemFile := write("system.jwt", systemJWT)
	cellFile := write("cell.jwt", cellJWT)
	ticketPublic, _ := testEd25519(t, root, "ticket.key")
	ticketFile := write("ticket.pub", base64.StdEncoding.EncodeToString(ticketPublic))
	wrongPublic, _ := testEd25519(t, root, "wrong-ticket.key")
	controllerPublic, _ := testEd25519(t, root, "response.key")
	_ = controllerPublic
	actorPublic, _ := testEd25519(t, root, "actor.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(actorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"test"}, CanRotateBrokerAccount: true}
	controllerNKey, controllerCreds := testBrokerJWTUser(t, root, "controller.creds", cellKey, cellID,
		[]string{"ts.orch.v1.gru.>", "ts.control.gru.>", "ts.broker.gru.ticket.>", "ts.broker.gru.fence.>", "$JS.API.>", "$JS.ACK.>", "$KV.>", "$O.>"}, nil)
	controllerClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, controllerCreds))
	if err != nil {
		t.Fatal(err)
	}
	controllerClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + controllerNKey + ".>",
		"ts.broker.gru.ticket.>", "ts.broker.gru.fence.broker-a", "ts.orch.v1.gru.broker.claim.apply",
		"ts.orch.v1.gru.agent.*.observation.*", "ts.orch.v1.gru.delivery.artifact.admit", "ts.orch.v1.gru.host.register", "ts.orch.v1.gru.placement.apply",
		"ts.orch.v1.gru.managed-update.prepare",
		"ts.orch.v1.gru.backup.operation",
		"ts.orch.v1.gru.terminal.>"}
	controllerClaim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	controllerCreds = testBrokerJWTUserWithClaim(t, root, "controller.creds", cellKey, controllerClaim)
	if err := natscell.ValidateBrokerControllerCredentials(controllerCreds, "gru", "broker-a"); err != nil {
		t.Fatalf("valid broker controller credentials rejected: %v", err)
	}
	boundCreds, err := os.ReadFile(controllerCreds)
	if err != nil {
		t.Fatal(err)
	}
	controllerClaim.Sub.Allow = append(controllerClaim.Sub.Allow, "ts.broker.gru.fence.>")
	testBrokerJWTUserWithClaim(t, root, "controller.creds", cellKey, controllerClaim)
	if err := natscell.ValidateBrokerControllerCredentials(controllerCreds, "gru", "broker-a"); err == nil {
		t.Fatal("wildcard fence receiver grant could impersonate another broker")
	}
	if err := os.WriteFile(controllerCreds, boundCreds, 0o600); err != nil {
		t.Fatal(err)
	}
	systemNKey, systemCreds := testBrokerJWTUser(t, root, "system.creds", systemKey, systemID,
		[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, nil)
	systemClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, systemCreds))
	if err != nil {
		t.Fatal(err)
	}
	systemClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + systemNKey + ".>"}
	systemCreds = testBrokerJWTUserWithClaim(t, root, "system.creds", systemKey, systemClaim)
	operatorNKey, operatorCreds := testBrokerJWTUser(t, root, "operator.creds", cellKey, cellID,
		[]string{"ts.orch.v1.gru.broker.claim.apply", "ts.orch.v1.gru.backup.operation", "ts.orch.v1.gru.terminal.plan", "ts.orch.v1.gru.terminal.apply",
			"ts.orch.v1.gru.terminal.status", "$JS.API.INFO", "$JS.API.STREAM.INFO.TS_CONTROL_LOG", "$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG"}, nil)
	actorClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, operatorCreds))
	if err != nil {
		t.Fatal(err)
	}
	actorClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + operatorNKey + ".>"}
	operatorCreds = testBrokerJWTUserWithClaim(t, root, "operator.creds", cellKey, actorClaim)
	clientPort := reserveControllerPort(t)
	controllerConfig := Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "gru", Instance: "broker-a", Replicas: 1,
		CredentialsFile: controllerCreds, TLS: tlsFiles, Embedded: &natscell.Embedded{
			Host: "127.0.0.1", Port: clientPort, StoreDir: filepath.Join(root, "broker"), StoreMaxBytes: 4 << 30,
			TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: operatorFile, SystemJWTFile: systemFile,
			CellJWTFile: cellFile, SystemCredentialsFile: systemCreds, TicketPublicKeyFile: ticketFile,
			BrokerIDs: []string{"broker-a"}}},
		Controller: ControllerConfig{CandidateID: "0000000000RTDFYAHDCP6Y401P", ResponseKeyFile: filepath.Join(root, "response.key"),
			BrokerTicketKeyFile: filepath.Join(root, "ticket.key"), ArtifactStoreMaxBytes: 64 << 20,
			TrustedSigners: []TrustedSignerConfig{grant}, Workloads: map[string]WorkloadProfile{
				"terrabase": {Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}},
			}}}
	controllerConfigPath := testJSONFile(t, root, "controller.json", controllerConfig)
	previousPresence := controllerBakedInputsPresent
	previousAdmission := controllerBootstrapProduction
	previousFounder := controllerFounderProduction
	previousProbe := controllerBrokerClockProbe
	previousServiceTrust := specBakedInputs
	specBakedInputs = func() (bootstrapstart.BakedInputs, error) {
		return bootstrapstart.BakedInputs{Identity: bootstrapstart.BakedIdentity{SchemaVersion: 1,
			DeploymentID: "000000000073E652YS073VHPZY", Environment: "test", Cell: "GRU"}, Genesis: testSpecRoots(t)}, nil
	}
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerBootstrapProduction = func(context.Context, Config) error { return nil }
	controllerFounderProduction = func(context.Context) error { return nil }
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	t.Cleanup(func() {
		controllerBakedInputsPresent = previousPresence
		controllerBootstrapProduction = previousAdmission
		controllerFounderProduction = previousFounder
		controllerBrokerClockProbe = previousProbe
		specBakedInputs = previousServiceTrust
	})
	if err := os.WriteFile(ticketFile, []byte(base64.StdEncoding.EncodeToString(wrongPublic)), 0o600); err != nil {
		t.Fatal(err)
	}
	var failedOutput bytes.Buffer
	if err := Run(ctx, []string{"run", "--config", controllerConfigPath}, &failedOutput); err == nil || !strings.Contains(err.Error(), "pinned broker ticket key") {
		t.Fatalf("controller accepted mismatched ticket pin: %v", err)
	}
	if err := os.WriteFile(ticketFile, []byte(base64.StdEncoding.EncodeToString(ticketPublic)), 0o600); err != nil {
		t.Fatal(err)
	}
	output := &readyWriter{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, []string{"run", "--config", controllerConfigPath}, output) }()
	select {
	case <-output.ready:
	case err := <-done:
		t.Fatalf("production controller exited before readiness: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	operatorConfig := Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "gru", Instance: "operator", Replicas: 1,
		URL: fmt.Sprintf("tls://127.0.0.1:%d", clientPort), CredentialsFile: operatorCreds, TLS: tlsFiles},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "actor.key"), BrokerTicketPublicKeyFile: ticketFile}}
	operatorConfigPath := testJSONFile(t, root, "operator.json", operatorConfig)
	var current brokerauth.Claim
	for {
		reader, err := natscell.Start(ctx, operatorConfig.NATS)
		if err == nil {
			store, openErr := brokerauth.OpenStore(ctx, reader.JetStream(), "gru", nil)
			if openErr == nil {
				current, err = store.Read(ctx, cellID)
			} else {
				err = openErr
			}
			_ = reader.Close()
		}
		if err == nil && current.Sequence > 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("initial durable broker claim unavailable: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	foreignKey, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	foreignClaim := jwt.NewAccountClaims(cellID)
	foreignClaim.Limits.JetStreamLimits = cellClaims.Limits.JetStreamLimits
	foreignJWT, err := foreignClaim.Encode(foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	foreignFile := write("foreign.jwt", foreignJWT)
	var denied bytes.Buffer
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath,
		"--file", foreignFile, "--expected-sequence", strconv.FormatUint(current.Sequence, 10)}, &denied); err == nil ||
		!strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("foreign operator-signed account JWT was accepted: %v", err)
	}
	deniedConfig := operatorConfig
	deniedConfig.Controller.TrustedSigners = []TrustedSignerConfig{{Actor: grant.Actor, PublicKey: grant.PublicKey,
		Roles: grant.Roles, Environments: grant.Environments}}
	deniedConfigPath := testJSONFile(t, root, "denied-operator.json", deniedConfig)
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", deniedConfigPath,
		"--file", cellFile, "--expected-sequence", strconv.FormatUint(current.Sequence, 10)}, &denied); err == nil ||
		!strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("default-deny operator grant was accepted: %v", err)
	}
	time.Sleep(time.Until(time.Unix(cellClaims.IssuedAt+1, 0)))
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := user.PublicKey()
	cellClaims.Revoke(userID)
	nextJWT, err := cellClaims.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	nextFile := write("next.jwt", nextJWT)
	var receiptOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath,
		"--file", nextFile, "--expected-sequence", strconv.FormatUint(current.Sequence, 10)}, &receiptOutput); err != nil {
		t.Fatalf("top-level broker claim command: %v", err)
	}
	var receipt brokerClaimApplyResponse
	if err := json.Unmarshal(receiptOutput.Bytes(), &receipt); err != nil || receipt.Status != "fenced" || receipt.Sequence <= current.Sequence {
		t.Fatalf("top-level broker claim receipt: %s, %v", receiptOutput.String(), err)
	}
	var staleOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath,
		"--file", cellFile, "--expected-sequence", strconv.FormatUint(current.Sequence, 10)}, &staleOutput); err == nil ||
		!strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("stale account claim was accepted: %v", err)
	}
	var checkOutput bytes.Buffer
	if err := Run(ctx, []string{"check", "--config", operatorConfigPath}, &checkOutput); err != nil {
		t.Fatalf("stale rejected request closed the broker bridge: %v", err)
	}
	receiptOutput.Reset()
	if err := Run(ctx, []string{"operator", "broker-claim-apply", "--config", operatorConfigPath,
		"--file", nextFile, "--expected-sequence", strconv.FormatUint(current.Sequence, 10)}, &receiptOutput); err != nil {
		t.Fatalf("idempotent exact-current claim retry: %v", err)
	}
	var retried brokerClaimApplyResponse
	if err := json.Unmarshal(receiptOutput.Bytes(), &retried); err != nil || retried.Status != "fenced" || retried.Sequence != receipt.Sequence {
		t.Fatalf("idempotent broker claim retry receipt: %s, %v", receiptOutput.String(), err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("controller shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
}
