package main

import (
	"bytes"

	"crypto/ed25519"

	"encoding/base64"
	"encoding/json/v2"

	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"

	"github.com/nats-io/jwt/v2"

	"github.com/nats-io/nkeys"
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
