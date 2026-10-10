package hostenroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
)

// A TerraBase member's own user, issued by the controller and checked by a
// real broker, reaches its lease bucket and nothing else: no other bucket,
// no stream create, no controller subject.
func TestRoleUserReachesOnlyItsBuckets(t *testing.T) {
	now := time.Now()
	year := now.AddDate(1, 0, 0)
	root, rootPEM, _ := generationtest.Certificate(t, generationtest.CA("cell CA", now, year), nil)
	_, certPEM, keyPEM := generationtest.Certificate(t, generationtest.HostIssuer(now, year), &root)
	tlsKey, tlsCert, _, err := hostenroll.ParseTLSIssuer(keyPEM, certPEM, []*x509.Certificate{root.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	operator, _ := nkeys.CreateOperator()
	system, _ := nkeys.CreateAccount()
	cell, _ := nkeys.CreateAccount()
	hostIssuer, _ := nkeys.CreateAccount()
	operatorID, _ := operator.PublicKey()
	systemID, _ := system.PublicKey()
	cellID, _ := cell.PublicKey()
	issuer := &hostenroll.Issuer{CellAccount: cellID, Cell: "gru", NATSKey: hostIssuer, TLSKey: tlsKey,
		TLSCert: tlsCert, TLSCertPEM: certPEM, Root: root.Certificate}

	signer, err := roleidentity.Signer(hostIssuer)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := roleidentity.Signer(hostIssuer)
	signerID, _ := signer.PublicKey()
	againID, _ := again.PublicKey()
	hostID, _ := hostIssuer.PublicKey()
	if signerID != againID || signerID == hostID {
		t.Fatal("the role signer must be derived deterministically and differ from the host issuer")
	}

	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	operatorJWT, _ := operatorClaim.Encode(operator)
	decodedOperator, _ := jwt.DecodeOperatorClaims(operatorJWT)
	systemJWT, _ := jwt.NewAccountClaims(systemID).Encode(operator)
	cellClaim := jwt.NewAccountClaims(cellID)
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit,
		Streams: jwt.NoLimit, Consumer: jwt.NoLimit}
	withoutRole, _ := cellClaim.Encode(operator)
	if err := issuer.ValidateRoleScope(withoutRole); err == nil {
		t.Fatal("a cell account without the role signer was accepted")
	}
	cellClaim.SigningKeys.AddScopedSigner(roleidentity.Scope(signerID))
	cellJWT, _ := cellClaim.Encode(operator)
	if err := issuer.ValidateRoleScope(cellJWT); err != nil {
		t.Fatal(err)
	}

	resolver := &server.MemAccResolver{}
	_ = resolver.Store(systemID, systemJWT)
	_ = resolver.Store(cellID, cellJWT)
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
		TrustedOperators: []*jwt.OperatorClaims{decodedOperator}, SystemAccount: systemID, AccountResolver: resolver,
		NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	t.Cleanup(broker.Shutdown)
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}

	user := func(t *testing.T, claim *jwt.UserClaims, sign nkeys.KeyPair, seed []byte, errs chan<- error) *nats.Conn {
		raw, err := claim.Encode(sign)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := nats.Connect(broker.ClientURL(), nats.UserJWTAndSeed(raw, string(seed)),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(conn.Close)
		return conn
	}
	adminKey, _ := nkeys.CreateUser()
	adminID, _ := adminKey.PublicKey()
	adminSeed, _ := adminKey.Seed()
	admin := user(t, jwt.NewUserClaims(adminID), cell, adminSeed, make(chan error, 8))
	adminJS, _ := jetstream.New(admin)
	ctx := t.Context()
	for _, bucket := range []string{"terrabase_backup_leases", "other_bucket", "TS_HOST_STATE"} {
		if _, err := adminJS.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.MemoryStorage}); err != nil {
			t.Fatal(err)
		}
	}

	memberKey, _ := nkeys.CreateUser()
	memberID, _ := memberKey.PublicKey()
	memberSeed, _ := memberKey.Seed()
	tlsPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, tlsPrivate)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if _, _, _, err := issuer.IssueRole("ts-auth", "gru-1-ctl-1", memberID, csrPEM, now); err == nil {
		t.Fatal("a role without a grant got credentials")
	}
	rawJWT, chain, expires, err := issuer.IssueRole("terrabase", "gru-1-db-1", memberID, csrPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeUserClaims(rawJWT)
	if err != nil || claim.Issuer != signerID || claim.IssuerAccount != cellID || claim.Subject != memberID ||
		!claim.HasEmptyPermissions() || !claim.Tags.Contains("kv:terrabase_backup_leases") || claim.Expires != expires.Unix() ||
		!claim.Tags.Contains("query:terrabase-wan") || !claim.Tags.Contains("query:terrabase-stats") || !claim.Tags.Contains("cell:gru") {
		t.Fatalf("role JWT: %+v %v", claim, err)
	}
	leafBlock, rest := pem.Decode(chain)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil || string(rest) != string(certPEM) || !leaf.NotAfter.Equal(expires) {
		t.Fatalf("role certificate chain: %v", err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	intermediates.AppendCertsFromPEM(certPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 8)
	member, err := nats.Connect(broker.ClientURL(), nats.UserJWTAndSeed(rawJWT, string(memberSeed)),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(member.Close)
	js, _ := jetstream.New(member)
	leases, err := js.KeyValue(ctx, "terrabase_backup_leases")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := leases.Create(ctx, "auth.db", []byte("gru-1-db-1/a"))
	if err != nil {
		t.Fatal(err)
	}
	if revision, err = leases.Update(ctx, "auth.db", []byte("gru-1-db-1/a"), revision); err != nil {
		t.Fatal(err)
	}
	if entry, err := leases.Get(ctx, "auth.db"); err != nil || entry.Revision() != revision {
		t.Fatalf("get own lease: %v", err)
	}
	if err := leases.Delete(ctx, "auth.db", jetstream.LastRevision(revision)); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for _, bucket := range []string{"other_bucket", "TS_HOST_STATE"} {
		if _, err := js.KeyValue(short, bucket); err == nil {
			t.Fatalf("role user bound %s", bucket)
		}
	}
	if _, err := js.CreateKeyValue(short, jetstream.KeyValueConfig{Bucket: "terrabase_other"}); err == nil {
		t.Fatal("role user created a bucket")
	}
	// TS-643's cross-region queries (TS-668): the member answers its own
	// cell's terrabase-wan queries once each and asks another cell's, and
	// nothing else of the query family.
	answer, err := member.Subscribe("ts.orch.v1.gru.query.terrabase-wan.heads", func(m *nats.Msg) { _ = m.Respond([]byte("heads")) })
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Unsubscribe()
	peer, err := admin.Subscribe("ts.orch.v1.sfo.query.terrabase-wan.member.ts-sfo-1", func(m *nats.Msg) { _ = m.Respond([]byte("pull")) })
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Unsubscribe()
	_ = member.Flush()
	_ = admin.Flush()
	if reply, err := admin.Request("ts.orch.v1.gru.query.terrabase-wan.heads", nil, 2*time.Second); err != nil || string(reply.Data) != "heads" {
		t.Fatalf("member did not answer its cell's query: %v", err)
	}
	if reply, err := member.Request("ts.orch.v1.sfo.query.terrabase-wan.member.ts-sfo-1", nil, 2*time.Second); err != nil || string(reply.Data) != "pull" {
		t.Fatalf("member could not query another cell: %v", err)
	}
	refused := func(subject string, do func() error) {
		t.Helper()
		if err := do(); err != nil {
			t.Fatal(err)
		}
		_ = member.Flush()
		for {
			select {
			case err := <-errs:
				if errors.Is(err, nats.ErrPermissionViolation) && strings.Contains(err.Error(), subject) {
					return
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s was not refused", subject)
			}
		}
	}
	refused("ts.orch.v1.sfo.query.terrabase-wan.>", func() error {
		_, err := member.SubscribeSync("ts.orch.v1.sfo.query.terrabase-wan.>")
		return err
	})
	refused("ts.orch.v1.gru.query.machine.list", func() error { return member.Publish("ts.orch.v1.gru.query.machine.list", nil) })
	refused("ts.orch.v1.gru.placement.apply", func() error { return member.Publish("ts.orch.v1.gru.placement.apply", nil) })
}
