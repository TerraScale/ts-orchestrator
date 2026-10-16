package functions

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestWorkerBrokerJWTAndTLSIsolation(t *testing.T) {
	artifact := integrationArtifact(t, "echo")
	admitted, _, _ := signedFunctionFixture(t, artifact)
	account, signer, accountJWT, admin, connect := workerBrokerFixture(t)
	creds, identity, err := IssueWorkerCredentials(admitted, account.Subject, accountJWT, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AccountNKey != account.Subject || !identity.ExpiresAt.Equal(admitted.ExpiresAt()) || time.Until(identity.ExpiresAt) > time.Hour {
		t.Fatalf("worker public identity or proof lifetime mismatch: %+v", identity)
	}
	reissued, renewed, err := IssueWorkerCredentials(admitted, account.Subject, accountJWT, signer, creds)
	if err != nil || renewed.UserNKey != identity.UserNKey || renewed.InboxPrefix != identity.InboxPrefix {
		t.Fatalf("restart changed worker identity: %+v, %v", renewed, err)
	}
	original := bytes.Clone(reissued)
	verified, err := VerifyWorkerCredentials(admitted, account.Subject, accountJWT, reissued)
	if err != nil || verified != renewed || !bytes.Equal(original, reissued) {
		t.Fatalf("signer-free verification changed credentials or identity: %v", err)
	}
	nc, violations := connect(reissued, verified.InboxPrefix)
	worker, err := newWorker(t.Context(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close(context.Background()) })
	if err := ProvisionQueue(t.Context(), admin, admitted); err != nil {
		t.Fatal(err)
	}
	queue, err := NewQueueWorker(t.Context(), nc, worker)
	if err != nil {
		t.Fatal(err)
	}
	adminJS, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := QueueIdentity(artifact.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	observedReceipts, err := adminJS.KeyValue(t.Context(), scope.ReceiptBucket)
	if err != nil {
		t.Fatal(err)
	}
	observedConsumer, err := adminJS.Consumer(t.Context(), scope.Stream, "worker")
	if err != nil {
		t.Fatal(err)
	}
	stop := runTransportQueue(t, queue)
	payload := []byte("TLS and scoped JWT worker")
	publishTransportMessage(t, adminJS, queue.Subject(), "broker-1", payload)
	waitTransport(t, func() bool {
		entry, err := observedReceipts.Get(t.Context(), "broker-1")
		digest := sha256.Sum256(payload)
		return err == nil && bytes.Equal(entry.Value(), digest[:])
	})
	waitTransport(t, func() bool {
		info, err := observedConsumer.Info(t.Context())
		return err == nil && info.NumAckPending == 0 && info.AckFloor.Consumer == 1
	})
	stop()
	if _, err := NewQueueWorker(t.Context(), nc, worker); err != nil {
		t.Fatalf("worker cannot rebind existing resources: %v", err)
	}
	other := artifact.Manifest
	other.TenantID = entityid.New()
	otherScope, err := QueueIdentity(other)
	if err != nil {
		t.Fatal(err)
	}
	otherRevision := artifact.Manifest
	otherRevision.Revision = "v2"
	revisionScope, err := QueueIdentity(otherRevision)
	if err != nil {
		t.Fatal(err)
	}
	// The broker rejects API subjects before considering malicious config bodies.
	for _, subject := range []string{
		otherScope.Subject, revisionScope.Subject, "ts.controller.apply", "$SYS.REQ.SERVER.PING", "$JS.API.INFO",
		"$JS.API.STREAM.INFO." + otherScope.Stream,
		"$JS.API.STREAM.MSG.GET." + scope.Stream,
		"$JS.API.STREAM.CREATE." + scope.Stream,
		"$JS.API.STREAM.UPDATE." + scope.Stream,
		"$JS.API.STREAM.DELETE." + scope.Stream,
		"$JS.API.STREAM.PURGE." + scope.Stream,
		"$JS.API.CONSUMER.CREATE." + scope.Stream + ".worker." + scope.Subject,
		"$JS.API.CONSUMER.CREATE." + scope.Stream + ".worker",
		"$JS.API.CONSUMER.MSG.NEXT." + scope.Stream + ".other",
		"$JS.API.CONSUMER.MSG.NEXT." + revisionScope.Stream + ".worker",
		"$KV." + otherScope.ReceiptBucket + ".broker-1",
		"$JS.API.DIRECT.GET.KV_" + otherScope.ReceiptBucket + ".$KV." + otherScope.ReceiptBucket + ".broker-1",
		"$JS.ACK." + otherScope.Stream + ".worker.1.1.1.1.0",
		"$JS.ACK." + scope.Stream + ".other.1.1.1.1.0",
	} {
		t.Run(subject, func(t *testing.T) {
			if err := nc.Publish(subject, []byte(`{"subjects":["ts.controller.>"]}`)); err != nil {
				t.Fatal(err)
			}
			if err := nc.FlushTimeout(time.Second); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-violations:
				if !errors.Is(err, nats.ErrPermissionViolation) || !strings.Contains(err.Error(), subject) {
					t.Fatalf("unexpected denial: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("broker accepted unauthorized publication")
			}
		})
	}
	for _, subject := range []string{"ts.>", otherScope.Subject, "_INBOX.>", "_INBOX.TS_FUNCTION.other.>"} {
		if _, err := nc.SubscribeSync(subject); err != nil {
			t.Fatal(err)
		}
		if err := nc.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-violations:
			if !errors.Is(err, nats.ErrPermissionViolation) {
				t.Fatalf("unexpected subscription denial: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("broker accepted unauthorized subscription")
		}
	}
	if _, _, err := IssueWorkerCredentials(release.VerifiedFunction{}, account.Subject, accountJWT, signer, nil); !errors.Is(err, ErrScope) {
		t.Fatalf("unsigned release issued credentials: %v", err)
	}
	for _, manifest := range []Manifest{other, otherRevision} {
		otherArtifact := artifact
		otherArtifact.Manifest = manifest
		otherProof, _, _ := signedFunctionFixture(t, otherArtifact)
		if _, _, err := IssueWorkerCredentials(otherProof, account.Subject, accountJWT, signer, creds); !errors.Is(err, ErrScope) {
			t.Fatalf("reused credentials for another tenant or revision: %v", err)
		}
		if _, err := VerifyWorkerCredentials(otherProof, account.Subject, accountJWT, creds); !errors.Is(err, ErrScope) {
			t.Fatalf("verified credentials for another tenant or revision: %v", err)
		}
	}
	foreignUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer foreignUser.Wipe()
	foreignPublic, err := foreignUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*jwt.UserClaims){
		"broad publication":  func(c *jwt.UserClaims) { c.Pub.Allow.Add(">") },
		"broad subscription": func(c *jwt.UserClaims) { c.Sub.Allow.Add(">") },
		"bearer token":       func(c *jwt.UserClaims) { c.BearerToken = true },
		"another account":    func(c *jwt.UserClaims) { c.IssuerAccount = identity.UserNKey },
		"another revision":   func(c *jwt.UserClaims) { c.Name += "-other" },
		"seed mismatch":      func(c *jwt.UserClaims) { c.Subject = foreignPublic },
		"long lifetime":      func(c *jwt.UserClaims) { c.Expires = time.Now().Add(2 * time.Hour).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			altered := brokerCredentialMutation(t, creds, signer, mutate)
			original := bytes.Clone(altered)
			if _, _, err := IssueWorkerCredentials(admitted, account.Subject, accountJWT, signer, altered); !errors.Is(err, ErrScope) {
				t.Fatalf("accepted altered credentials: %v", err)
			}
			if _, err := VerifyWorkerCredentials(admitted, account.Subject, accountJWT, altered); !errors.Is(err, ErrScope) {
				t.Fatalf("verified altered credentials: %v", err)
			}
			if !bytes.Equal(altered, original) {
				t.Fatal("issuer mutated supplied credentials")
			}
		})
	}
	stranger, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Wipe()
	if _, _, err := IssueWorkerCredentials(admitted, account.Subject, accountJWT, stranger, creds); !errors.Is(err, ErrScope) {
		t.Fatalf("unregistered signer accepted: %v", err)
	}
	for name, wire := range map[string][]byte{"missing": nil, "malformed": []byte("invalid credentials")} {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(wire)
			if _, err := VerifyWorkerCredentials(admitted, account.Subject, accountJWT, wire); !errors.Is(err, ErrScope) {
				t.Fatalf("verified absent or malformed credentials: %v", err)
			}
			if !bytes.Equal(original, wire) {
				t.Fatal("verification mutated credentials")
			}
		})
	}
	for name, mutate := range map[string]func(*jwt.UserClaims){
		"past proof": func(c *jwt.UserClaims) { c.Expires = admitted.ExpiresAt().Add(time.Second).Unix() },
		"expired":    func(c *jwt.UserClaims) { c.Expires = time.Now().Add(-time.Second).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			altered := brokerCredentialMutation(t, creds, signer, mutate)
			original := bytes.Clone(altered)
			if _, err := VerifyWorkerCredentials(admitted, account.Subject, accountJWT, altered); !errors.Is(err, ErrScope) {
				t.Fatalf("verified credentials outside current authority: %v", err)
			}
			if !bytes.Equal(original, altered) {
				t.Fatal("verification mutated rejected credentials")
			}
		})
	}
	expires := time.Now().Add(2 * time.Second).Unix()
	shortLived := brokerCredentialMutation(t, creds, signer, func(c *jwt.UserClaims) { c.Expires = expires })
	if _, err := VerifyWorkerCredentials(admitted, account.Subject, accountJWT, shortLived); err != nil {
		t.Fatalf("current short-lived credentials rejected: %v", err)
	}
	time.Sleep(time.Until(time.Unix(expires, 0)))
	original = bytes.Clone(shortLived)
	if _, err := VerifyWorkerCredentials(admitted, account.Subject, accountJWT, shortLived); !errors.Is(err, ErrScope) {
		t.Fatalf("reader renewed expired credentials: %v", err)
	}
	if !bytes.Equal(original, shortLived) {
		t.Fatal("reader changed expired credentials")
	}
	if _, renewed, err := IssueWorkerCredentials(admitted, account.Subject, accountJWT, signer, shortLived); err != nil || renewed.UserNKey != identity.UserNKey {
		t.Fatalf("issuer cannot renew expired exact credentials: %v", err)
	}
}

func brokerCredentialMutation(t *testing.T, creds []byte, signer nkeys.KeyPair, mutate func(*jwt.UserClaims)) []byte {
	t.Helper()
	original, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeUserClaims(original)
	if err != nil {
		t.Fatal(err)
	}
	mutate(claims)
	raw, err := claims.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Replace(creds, []byte(original), []byte(raw), 1)
}

func workerBrokerFixture(t *testing.T) (*jwt.AccountClaims, nkeys.KeyPair, string, *nats.Conn, func([]byte, string) (*nats.Conn, <-chan error)) {
	t.Helper()
	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Wipe()
	system, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer system.Wipe()
	accountKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(accountKey.Wipe)
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Wipe)
	operatorID, _ := operator.PublicKey()
	systemID, _ := system.PublicKey()
	accountID, _ := accountKey.PublicKey()
	signerID, _ := signer.PublicKey()
	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	operatorJWT, err := operatorClaim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	operatorClaim, err = jwt.DecodeOperatorClaims(operatorJWT)
	if err != nil {
		t.Fatal(err)
	}
	account := jwt.NewAccountClaims(accountID)
	account.SigningKeys.Add(signerID)
	account.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 20, Consumer: 20}
	accountJWT, err := account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &server.MemAccResolver{}
	systemJWT, err := jwt.NewAccountClaims(systemID).Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Store(systemID, systemJWT); err != nil {
		t.Fatal(err)
	}
	if err := resolver.Store(accountID, accountJWT); err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := workerBrokerTLS(t)
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
		TLSConfig: serverTLS, TrustedOperators: []*jwt.OperatorClaims{operatorClaim}, AccountResolver: resolver, SystemAccount: systemID})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("JWT TLS broker did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	connect := func(creds []byte, inbox string) (*nats.Conn, <-chan error) {
		t.Helper()
		violations := make(chan error, 64)
		opts := []nats.Option{nats.UserCredentialBytes(creds), nats.Secure(clientTLS.Clone()), nats.NoReconnect(),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { violations <- err })}
		if inbox != "" {
			opts = append(opts, nats.CustomInboxPrefix(inbox))
		}
		nc, err := nats.Connect(srv.ClientURL(), opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(nc.Close)
		return nc, violations
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	userID, _ := user.PublicKey()
	adminClaim := jwt.NewUserClaims(userID)
	adminClaim.IssuerAccount = accountID
	adminJWT, err := adminClaim.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	adminCreds, err := jwt.FormatUserConfig(adminJWT, seed)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := connect(adminCreds, "")
	// Scoped templates cannot be used to smuggle explicit worker permissions.
	scope := jwt.NewUserScope()
	scope.Key, scope.Role = signerID, "controller"
	scope.Template.Pub.Allow = jwt.StringList{">"}
	account.SigningKeys.AddScopedSigner(scope)
	scopedJWT, err := account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, _ := signedFunctionFixture(t, integrationArtifact(t, "echo"))
	if _, _, err := IssueWorkerCredentials(proof, accountID, scopedJWT, signer, nil); !errors.Is(err, ErrScope) {
		t.Fatalf("scoped controller authority accepted: %v", err)
	}
	delete(account.SigningKeys, signerID)
	staleJWT, err := account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssueWorkerCredentials(proof, accountID, staleJWT, signer, nil); !errors.Is(err, ErrScope) {
		t.Fatalf("stale signing authority accepted: %v", err)
	}
	account.SigningKeys.Add(signerID)
	previous, _, err := IssueWorkerCredentials(proof, accountID, accountJWT, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Rotation overlap retains the user's key while both issuers remain authorized.
	rotated, rotatedIdentity, err := IssueWorkerCredentials(proof, accountID, accountJWT, accountKey, previous)
	if err != nil {
		t.Fatal(err)
	}
	previousRaw, err := jwt.ParseDecoratedJWT(previous)
	if err != nil {
		t.Fatal(err)
	}
	previousClaim, err := jwt.DecodeUserClaims(previousRaw)
	if err != nil || rotatedIdentity.UserNKey != previousClaim.Subject {
		t.Fatalf("rotation changed worker key: %v", err)
	}
	connect(rotated, rotatedIdentity.InboxPrefix)
	delete(account.SigningKeys, signerID)
	retiredJWT, err := account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssueWorkerCredentials(proof, accountID, retiredJWT, accountKey, previous); !errors.Is(err, ErrScope) {
		t.Fatalf("retired signer credentials renewed: %v", err)
	}
	if _, err := VerifyWorkerCredentials(proof, accountID, retiredJWT, previous); !errors.Is(err, ErrScope) {
		t.Fatalf("retired signer credentials verified: %v", err)
	}
	account.SigningKeys.Add(signerID)
	account.SigningKeys.AddScopedSigner(scope)
	scopedJWT, err = account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWorkerCredentials(proof, accountID, scopedJWT, previous); !errors.Is(err, ErrScope) {
		t.Fatalf("scoped issuer credentials verified: %v", err)
	}
	account.SigningKeys.Add(signerID)
	account.Expires = proof.ExpiresAt().Add(-time.Second).Unix()
	shortAccountJWT, err := account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWorkerCredentials(proof, accountID, shortAccountJWT, previous); !errors.Is(err, ErrScope) {
		t.Fatalf("credentials beyond account expiry verified: %v", err)
	}
	account.Expires = 0
	account.Revoke(previousClaim.Subject)
	revokedJWT, err := account.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWorkerCredentials(proof, accountID, revokedJWT, previous); !errors.Is(err, ErrScope) {
		t.Fatalf("revoked credentials verified: %v", err)
	}
	account.Revocations = nil
	return account, signer, accountJWT, admin, connect
}

func workerBrokerTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "function broker integration"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	leaf := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert},
		&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf}, RootCAs: roots}
}
