package bootstrapmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// The sealed-source fixture separately exercises the public startup constructor.
// This scenario uses the actual first-boot generator and online issuer bytes.
func TestGeneratedStartupIssuerAuthenticatesFunctionToBroker(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := testConfig()
	cfg.ValidityHours = 365 * 24
	directory := filepath.Join(t.TempDir(), "material")
	record, err := Generate(directory, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLive(directory, record); err != nil {
		t.Fatal(err)
	}
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(directory, name)) }
	mustRead := func(name string) []byte {
		t.Helper()
		body, err := read(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(body) })
		return body
	}
	issuer, err := loadRecordedControllerIssuer(record, read, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Wipe)
	if !issuer.cert.NotAfter.Equal(now.Add(controllerIssuedLifetime)) || issuer.identity.lifetime != controllerIssuedLifetime {
		t.Fatal("controller issuer does not have the fixed 90-day lifetime")
	}
	for _, name := range []string{"controller-tls-issuer-cert.pem", "controller-tls-issuer-key.pem", "controller-account-signer.seed"} {
		if !slices.ContainsFunc(record.Files, func(file File) bool {
			return file.Name == name && file.Purpose == bootstrap.SecretControllerIssuer && file.Slot == ""
		}) {
			t.Fatalf("%s is not part of the baseline controller authority", name)
		}
	}
	proof := startupFunctionProof(t, entityid.Derive("tenant", t.Name()), "echo", "GRU", cfg.Environment, now, 2*time.Hour)
	credentials, identity, err := issuer.IssueFunctionCredentials(proof, string(mustRead("cell.jwt")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	verified, err := functions.VerifyWorkerCredentials(proof, record.Public.CellAccountNKey, string(mustRead("cell.jwt")), credentials)
	if err != nil || verified != identity {
		t.Fatalf("generated worker credentials failed verification: %v", err)
	}
	claimsWire, err := jwt.ParseDecoratedJWT(credentials)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeUserClaims(claimsWire)
	if err != nil || claims.Issuer != record.Public.ControllerAccountSignerNKey {
		t.Fatalf("worker was not signed by the separate controller authority: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(mustRead("ca.pem")) {
		t.Fatal("generated root is invalid")
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer.cert)
	var clientPair tls.Certificate
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		issue := issuer.IssueFunctionTLS
		if usage == x509.ExtKeyUsageClientAuth {
			issue = issuer.IssueFunctionClientTLS
		}
		cert, key, _, err := issue(proof)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(cert, key)
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: now}); err != nil {
			t.Fatalf("generated controller cannot issue function usage %d: %v", usage, err)
		}
		if usage == x509.ExtKeyUsageClientAuth {
			clientPair = pair
		}
	}
	serverCert, serverKey, err := issuer.RenewTLS(ControllerLeafIdentity("gru", "controller-a", "127.0.0.1"), now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverKey)
	serverPair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := jwt.DecodeOperatorClaims(string(mustRead("operator.jwt")))
	if err != nil {
		t.Fatal(err)
	}
	resolver := &server.MemAccResolver{}
	for key, name := range map[string]string{record.Public.SystemAccountNKey: "system.jwt", record.Public.CellAccountNKey: "cell.jwt"} {
		if err := resolver.Store(key, string(mustRead(name))); err != nil {
			t.Fatal(err)
		}
	}
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedOperators: []*jwt.OperatorClaims{operator}, AccountResolver: resolver, SystemAccount: record.Public.SystemAccountNKey,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("generated JWT/mTLS broker did not start")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.UserCredentialBytes(credentials), nats.CustomInboxPrefix(identity.InboxPrefix), nats.NoReconnect(), nats.Timeout(5*time.Second),
		nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "controller-a", Certificates: []tls.Certificate{clientPair}}))
	if err != nil {
		t.Fatalf("function could not authenticate using generated startup authority: %v", err)
	}
	t.Cleanup(connection.Close)
	if err := connection.FlushTimeout(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	t.Run("issuer expiration", func(t *testing.T) {
		expiry := issuer.cert.NotAfter
		cert, key, err := issuer.RenewTLS(ControllerLeafIdentity("gru", "controller-a", "127.0.0.1"), expiry)
		clear(key)
		if err == nil || len(cert) != 0 {
			t.Fatal("cached issuer renewed after expiry")
		}
		if expired, err := loadRecordedControllerIssuer(record, read, expiry); err == nil {
			expired.Wipe()
			t.Fatal("expired recorded issuer loaded")
		}
	})
	t.Run("tampered source bytes", func(t *testing.T) {
		tampered := func(name string) ([]byte, error) {
			body, err := read(name)
			if name == "controller-account-signer.seed" && len(body) > 0 {
				body[0] ^= 1
			}
			return body, err
		}
		if changed, err := loadRecordedControllerIssuer(record, tampered, now); err == nil {
			changed.Wipe()
			t.Fatal("altered issuer seed loaded")
		}
	})
	t.Run("independently pinned wrong signer", func(t *testing.T) {
		other, err := nkeys.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		defer other.Wipe()
		seed, err := other.Seed()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(seed)
		changed := record
		changed.Files = slices.Clone(record.Files)
		for i, file := range changed.Files {
			if file.Name == "controller-account-signer.seed" {
				changed.Files[i].SHA256, changed.Files[i].MaxBytes = digest(seed), int64(len(seed))
			}
		}
		wrongSigner := func(name string) ([]byte, error) {
			if name == "controller-account-signer.seed" {
				return bytes.Clone(seed), nil
			}
			return read(name)
		}
		if loaded, err := loadRecordedControllerIssuer(changed, wrongSigner, now); err == nil {
			loaded.Wipe()
			t.Fatal("unregistered controller signer loaded despite matching inventory digest")
		}
	})
}

func startupFunctionProof(t *testing.T, tenant, function, cell, environment string, now time.Time, validFor time.Duration) release.VerifiedFunction {
	t.Helper()
	module := []byte("\x00asm\x01\x00\x00\x00")
	digest := sha256.Sum256(module)
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: tenant, FunctionID: function, Revision: "first",
		Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)), Environment: environment, Cell: cell, Sequence: 1}
	root, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leaf)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leaf)
	if err != nil {
		t.Fatal(err)
	}
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(validFor+time.Hour), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := release.SignFunctionClaim(claim, module, delegation, roots, key, now, validFor)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, delegationWire, module, roots, release.FunctionExpectation{Environment: environment, Cell: cell,
		TenantID: tenant, FunctionID: function, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
