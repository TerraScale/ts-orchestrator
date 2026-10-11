package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// fakeRoleIssuer signs what the controller's issuer would: a user JWT for
// the requested key and a client certificate for the CSR's key.
func fakeRoleIssuer(t *testing.T, issued *int) RoleIdentityIssuer {
	t.Helper()
	account, _ := nkeys.CreateAccount()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	return func(_ context.Context, role, node, userKey, csrPEM string) (string, []byte, error) {
		*issued++
		block, _ := pem.Decode([]byte(csrPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return "", nil, err
		}
		claim := jwt.NewUserClaims(userKey)
		claim.Name = role + "@" + node
		raw, err := claim.Encode(account)
		if err != nil {
			return "", nil, err
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(48 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
		return raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
	}
}

// A TerraBase member's file secrets and NATS identity land in its role
// directory as 0600 files of the workload user; its launch settings name
// them and never carry a secret value. A current identity is not reissued,
// and a host without an active member gets none.
func TestRoleFilesDeliverSecretsAndNATSIdentity(t *testing.T) {
	issued := 0
	c, conn, store, _, controllerKey := testControllerWithVerifier(t, nil, func(config *ControllerConfig) {
		config.RoleIdentity = fakeRoleIssuer(t, &issued)
	})
	hostKey := registerTestHost(t, c)
	hash := sha256.Sum256([]byte("member"))
	if _, err := store.PutBytes(t.Context(), "sha256-"+hex.EncodeToString(hash[:]), []byte("member")); err != nil {
		t.Fatal(err)
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase",
		Digest: hex.EncodeToString(hash[:]), Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	<-c.Ready()

	root := traversableTempDir(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("cell CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil },
		WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t),
		ManagedRuntimeRoot: root, NATSURL: "tls://10.0.0.1:4222", NATSCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"TERRABASE_BACKUP_SECRET_KEY_FILE": "s3-secret"}
	env, err := agent.prepareRoleFiles(t.Context(), desired, secrets)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "roles", "terrabase")
	if len(secrets) != 0 || env["TERRABASE_BACKUP_SECRET_KEY_FILE"] != filepath.Join(dir, "terrabase_backup_secret_key_file") ||
		env["TERRABASE_NATS_URL"] != "tls://10.0.0.1:4222" || env["TERRABASE_NATS_CREDENTIALS_FILE"] != filepath.Join(dir, "nats.creds") ||
		env["TERRABASE_NATS_CA"] != filepath.Join(dir, "nats-ca.pem") || issued != 1 {
		t.Fatalf("launch settings %v, secrets left %v, issued %d", env, secrets, issued)
	}
	for _, value := range env {
		if strings.Contains(value, "s3-secret") {
			t.Fatal("a secret value reached the environment")
		}
	}
	identity := testAgentIdentity()
	for _, name := range []string{"terrabase_backup_secret_key_file", "nats.creds", "nats.key", "nats.pem", "nats-ca.pem"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		owner := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm() != 0o600 || owner.Uid != identity.UID || owner.Gid != identity.GID {
			t.Fatalf("%s: mode %v owner %d:%d", name, info.Mode(), owner.Uid, owner.Gid)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "terrabase_backup_secret_key_file")); string(data) != "s3-secret" {
		t.Fatal("secret file content differs")
	}
	creds, _ := os.ReadFile(filepath.Join(dir, "nats.creds"))
	if _, err := jwt.ParseDecoratedJWT(creds); err != nil {
		t.Fatal(err)
	}
	if _, err := nkeys.ParseDecoratedUserNKey(creds); err != nil {
		t.Fatal(err)
	}
	if err := agent.refreshRoleFiles(t.Context(), desired); err != nil || issued != 1 {
		t.Fatalf("a current identity was renewed (%d issued): %v", issued, err)
	}

	desired.Withdrawn, desired.Digest, desired.Generation = true, "", 2
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if err := agent.ensureRoleIdentity(t.Context(), "terrabase", t.TempDir()); err == nil || issued != 1 {
		t.Fatalf("a host without an active member got an identity: %v", err)
	}
	if err := agent.ensureRoleIdentity(t.Context(), "00000000001JAWFV71SRD9EM17", t.TempDir()); err == nil {
		t.Fatal("a role without a grant got an identity")
	}
	agent.roleFilesFailures = map[string]roleFilesFailure{"terrabase": {at: time.Now(), err: errors.New("held")}}
	if err := agent.refreshRoleFiles(t.Context(), Desired{Role: "terrabase"}); err == nil || err.Error() != "held" {
		t.Fatalf("a failed renewal was retried at once: %v", err)
	}
}

// A running member renews its NATS identity past half its lifetime even while
// a staged release waits behind a restart hold: the identity is re-requested
// and replaced, and the member is not restarted (TS-803).
func TestRunningRoleIdentityRenewsWhileReleaseHeld(t *testing.T) {
	issued := 0
	c, conn, store, _, controllerKey := testControllerWithVerifier(t, nil, func(config *ControllerConfig) {
		config.RoleIdentity = fakeRoleIssuer(t, &issued)
	})
	hostKey := registerTestHost(t, c)
	running, staged := []byte("member"), []byte("staged member")
	runningDigest, stagedDigest := sha256.Sum256(running), sha256.Sum256(staged)
	for _, data := range [][]byte{running, staged} {
		hash := sha256.Sum256(data)
		if _, err := store.PutBytes(t.Context(), "sha256-"+hex.EncodeToString(hash[:]), data); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ApplyDesired(t.Context(), Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase",
		Digest: hex.EncodeToString(stagedDigest[:]), Generation: 2, AuthorityEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	<-c.Ready()

	root := traversableTempDir(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("cell CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &memoryRunner{observed: map[string]Observation{"terrabase": {Running: true, Digest: hex.EncodeToString(runningDigest[:])}}}
	stateRoot := testAgentStateRoot(t)
	agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil },
		WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		Conn: conn, Identity: hostKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		Runner: runner, InstallRoot: testAgentInstallRoot(t), StateRoot: stateRoot,
		ManagedRuntimeRoot: root, NATSURL: "tls://10.0.0.1:4222", NATSCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "terrabase"+RestartHoldSuffix), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := agent.ensureRoleDir("terrabase")
	if err != nil {
		t.Fatal(err)
	}
	// An identity 47 of its 48 hours old: past half its lifetime.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aged := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "aged"},
		NotBefore: time.Now().Add(-47 * time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, aged, aged, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	agedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "nats.pem"), agedPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := agent.reconcile(t.Context(), "terrabase"); err != nil {
		t.Fatalf("reconcile while held: %v", err)
	}
	renewed, err := os.ReadFile(filepath.Join(dir, "nats.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if issued != 1 || string(renewed) == string(agedPEM) {
		t.Fatalf("held member's identity was not renewed (%d issued)", issued)
	}
	if _, current := roleIdentityExpiry(dir); !current {
		t.Fatal("renewed identity is not current")
	}
	runner.mu.Lock()
	applied := runner.applied
	runner.mu.Unlock()
	if applied != 0 {
		t.Fatalf("held member was restarted %d times", applied)
	}
}
