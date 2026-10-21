package natscell

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func writeExpiringUserCredentials(t *testing.T, path string, account nkeys.KeyPair, accountID string,
	user nkeys.KeyPair, expires time.Time,
) {
	t.Helper()
	userID, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	claim.Expires = expires.Unix()
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClientMaterialSourceRejectsAnotherUserKey(t *testing.T) {
	root := t.TempDir()
	account, _ := nkeys.CreateAccount()
	accountID, _ := account.PublicKey()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	other, _ := nkeys.CreateUser()
	startup := filepath.Join(root, "startup.creds")
	renewed := filepath.Join(root, "renewed.creds")
	foreign := filepath.Join(root, "foreign.creds")
	later := time.Now().Add(time.Hour)
	writeExpiringUserCredentials(t, startup, account, accountID, user, later)
	writeExpiringUserCredentials(t, renewed, account, accountID, user, later)
	writeExpiringUserCredentials(t, foreign, account, accountID, other, later)
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	next := renewed
	source := newClientMaterialSource(Config{CredentialsFile: startup, TLS: tlsFiles,
		ReloadClientMaterial: func() (ClientMaterial, error) {
			return ClientMaterial{CredentialsFile: next, TLS: tlsFiles}, nil
		}}, userID)
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("renewed credentials for the same key were not used: %s", got)
	}
	next = foreign
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("credentials for a different NATS user were accepted: %s", got)
	}
	next = filepath.Join(root, "missing.creds")
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("missing reloaded credentials did not fall back: %s", got)
	}
	if _, err := source.tlsConfig(); err != nil {
		t.Fatal(err)
	}
	static := newClientMaterialSource(Config{CredentialsFile: startup, TLS: tlsFiles}, userID)
	if got := static.current().CredentialsFile; got != startup {
		t.Fatal(got)
	}
}

// A renewed host JWT must be picked up on the reconnect the broker forces at
// the old credential's expiry, without restarting the client process.
func TestHostClientPresentsRenewedCredentialsAfterExpiry(t *testing.T) {
	root := t.TempDir()
	operatorKey, _ := nkeys.CreateOperator()
	systemKey, _ := nkeys.CreateAccount()
	cellKey, _ := nkeys.CreateAccount()
	operatorID, _ := operatorKey.PublicKey()
	systemID, _ := systemKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	op := jwt.NewOperatorClaims(operatorID)
	op.SystemAccount = systemID
	opRaw, err := op.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	sysRaw, err := jwt.NewAccountClaims(systemID).Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	cell := jwt.NewAccountClaims(cellID)
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 10, Consumer: 10}
	cellRaw, err := cell.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	ticketPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	controllerCredentials := testJWTUserCredentials(t, root, "controller.creds", cellKey, cellID, nil, nil)
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	systemCredentials := testJWTUserCredentialsWithKey(t, root, "system.creds", systemKey, systemID, systemUser,
		[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, []string{inboxPrefix("gru", systemUserID) + ".>"})
	tlsFiles := testBridgeTLS(t, root)
	cfg := Config{Cell: "gru", Instance: "broker-a", Replicas: 1, CredentialsFile: controllerCredentials, TLS: tlsFiles,
		Embedded: &Embedded{Host: "127.0.0.1", Port: freeClientPort(t), StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: write("operator.jwt", opRaw),
			SystemJWTFile: write("system.jwt", sysRaw), CellJWTFile: write("cell.jwt", cellRaw),
			SystemCredentialsFile: systemCredentials}}
	cfg.Embedded.TicketPublicKeyFile = write("ticket.pub", base64.StdEncoding.EncodeToString(ticketPublic))
	cfg.Embedded.BrokerIDs = []string{"broker-a"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	r, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.ApplyCellClaim(ctx, 1, cellRaw); err != nil {
		t.Fatal(err)
	}
	if err := r.Bridge().OpenUntil(1, cellRaw, time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	hostUser, _ := nkeys.CreateUser()
	startup := filepath.Join(root, "host-startup.creds")
	renewed := filepath.Join(root, "host-renewed.creds")
	writeExpiringUserCredentials(t, startup, cellKey, cellID, hostUser, time.Now().Add(3*time.Second))
	var renewedReady atomic.Bool
	hostConfig := Config{Cell: "gru", Instance: "host-a", Replicas: 1, ClientRole: "host",
		URL: r.URL(), CredentialsFile: startup, TLS: tlsFiles,
		ReloadClientMaterial: func() (ClientMaterial, error) {
			if !renewedReady.Load() {
				return ClientMaterial{CredentialsFile: startup, TLS: tlsFiles}, nil
			}
			return ClientMaterial{CredentialsFile: renewed, TLS: tlsFiles}, nil
		}}
	client, err := Start(ctx, hostConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reconnected := make(chan struct{}, 4)
	client.Conn().SetReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} })
	writeExpiringUserCredentials(t, renewed, cellKey, cellID, hostUser, time.Now().Add(time.Hour))
	renewedReady.Store(true)
	select {
	case <-reconnected:
	case <-ctx.Done():
		t.Fatal("host client did not reconnect after its startup credential expired")
	}
	time.Sleep(500 * time.Millisecond)
	if !client.Conn().IsConnected() {
		t.Fatalf("host client is not connected with renewed credentials: %v", client.Conn().Status())
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	materialCtx, stopMaterial := context.WithTimeout(t.Context(), 60*time.Second)
	defer stopMaterial()
	deadline, _ := materialCtx.Deadline()
	if err := r.Bridge().OpenUntil(1, cellRaw, deadline); err != nil {
		t.Fatal(err)
	}
	bridge := r.Bridge()
	drainBridge := func(t *testing.T) {
		t.Helper()
		waitUntil(t, materialCtx, "previous material client drained", func() bool {
			bridge.mu.Lock()
			defer bridge.mu.Unlock()
			return len(bridge.pairs) == 0
		})
	}
	drainBridge(t)

	renewedTLS := testBridgeTLS(t, filepath.Join(root, "renewed-tls"))
	startupCA, err := os.ReadFile(tlsFiles.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	renewedCA, err := os.ReadFile(renewedTLS.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	replace(t, tlsFiles.CAFile, append(startupCA, renewedCA...))
	renewedTLS.CAFile = tlsFiles.CAFile
	startupCertificate, err := tls.LoadX509KeyPair(tlsFiles.CertFile, tlsFiles.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	renewedCertificate, err := tls.LoadX509KeyPair(renewedTLS.CertFile, renewedTLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	startupFingerprint := sha256.Sum256(startupCertificate.Certificate[0])
	renewedFingerprint := sha256.Sum256(renewedCertificate.Certificate[0])
	if startupFingerprint == renewedFingerprint {
		t.Fatal("startup and renewed TLS certificates are indistinguishable")
	}
	probeSubject := "ts.orch.v1.gru.clientmaterial.probe"
	probe, err := r.Conn().Subscribe(probeSubject, func(message *nats.Msg) {
		_ = message.Respond(message.Data)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Unsubscribe()
	if err := r.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	assertMaterial := func(t *testing.T, conn *nats.Conn, wantJWT, wantUser string, wantFingerprint [sha256.Size]byte,
		previousCID uint64, previousPair *bridgePair,
	) (uint64, *bridgePair) {
		t.Helper()
		var acceptedCID uint64
		var acceptedPair *bridgePair
		waitUntil(t, materialCtx, "fresh material JWT and authenticated peer certificate", func() bool {
			cid, err := conn.GetClientID()
			if err != nil || !conn.IsConnected() || cid == previousCID {
				return false
			}
			bridge.mu.Lock()
			var pair *bridgePair
			if len(bridge.pairs) == 1 {
				for candidate := range bridge.pairs {
					pair = candidate
				}
			}
			bridge.mu.Unlock()
			if pair == nil || pair == previousPair {
				return false
			}
			external, ok := pair.external.(*tls.Conn)
			if !ok {
				return false
			}
			state := external.ConnectionState()
			if !state.HandshakeComplete || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 ||
				sha256.Sum256(state.PeerCertificates[0].Raw) != wantFingerprint {
				return false
			}
			connections, err := r.server.Connz(&server.ConnzOptions{CID: cid, Username: true})
			if err != nil || len(connections.Conns) != 1 {
				return false
			}
			authenticated := connections.Conns[0]
			if authenticated.JWT != wantJWT || authenticated.AuthorizedUser != wantUser || authenticated.Account != cellID {
				return false
			}
			requestCtx, stopRequest := context.WithTimeout(materialCtx, 250*time.Millisecond)
			reply, err := conn.RequestWithContext(requestCtx, probeSubject, []byte("material"))
			stopRequest()
			if err != nil || string(reply.Data) != "material" {
				return false
			}
			currentCID, err := conn.GetClientID()
			if err != nil || currentCID != cid || !conn.IsConnected() {
				return false
			}
			// ConnectionState survives closure; accept only the same live bridge pair.
			bridge.mu.Lock()
			_, retained := bridge.pairs[pair]
			stable := retained && len(bridge.pairs) == 1
			bridge.mu.Unlock()
			if !stable {
				return false
			}
			acceptedCID, acceptedPair = cid, pair
			return true
		})
		return acceptedCID, acceptedPair
	}
	credentialJWT := func(path string) string {
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
	userID, err := hostUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	foreignUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	foreignID, err := foreignUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	materialStartup := filepath.Join(root, "material-startup.creds")
	materialRenewed := filepath.Join(root, "material-renewed.creds")
	foreign := filepath.Join(root, "material-foreign.creds")
	writeExpiringUserCredentials(t, materialStartup, cellKey, cellID, hostUser, time.Now().Add(time.Hour))
	writeExpiringUserCredentials(t, materialRenewed, cellKey, cellID, hostUser, time.Now().Add(48*time.Hour))
	writeExpiringUserCredentials(t, foreign, cellKey, cellID, foreignUser, time.Now().Add(2*time.Hour))
	startupJWT, renewedJWT, foreignJWT := credentialJWT(materialStartup), credentialJWT(materialRenewed), credentialJWT(foreign)
	if startupJWT == renewedJWT {
		t.Fatal("startup and renewed JWTs are indistinguishable")
	}
	type materialOffer struct {
		material ClientMaterial
		err      error
	}
	var offered atomic.Pointer[materialOffer]
	offered.Store(&materialOffer{material: ClientMaterial{CredentialsFile: materialStartup, TLS: tlsFiles}})
	materialConfig := Config{Cell: "gru", Instance: "material-client", Replicas: 1, ClientRole: "host",
		URL: r.URL(), CredentialsFile: materialStartup, TLS: tlsFiles,
		ReloadClientMaterial: func() (ClientMaterial, error) {
			next := offered.Load()
			return next.material, next.err
		}}
	materialClient, err := Start(materialCtx, materialConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer materialClient.Close()
	cid, pair := assertMaterial(t, materialClient.Conn(), startupJWT, userID, startupFingerprint, 0, nil)
	for _, transition := range []struct {
		name     string
		material ClientMaterial
		err      error
	}{
		{"same-user renewal", ClientMaterial{CredentialsFile: materialRenewed, TLS: renewedTLS}, nil},
		{"another valid user", ClientMaterial{CredentialsFile: foreign, TLS: renewedTLS}, nil},
		{"failed configuration read", ClientMaterial{}, errors.New("host.json is being rewritten")},
		{"missing offered credentials", ClientMaterial{CredentialsFile: filepath.Join(root, "missing.creds"), TLS: renewedTLS}, nil},
	} {
		if !t.Run(transition.name, func(t *testing.T) {
			offered.Store(&materialOffer{material: transition.material, err: transition.err})
			if err := materialClient.Conn().ForceReconnect(); err != nil {
				t.Fatal(err)
			}
			cid, pair = assertMaterial(t, materialClient.Conn(), renewedJWT, userID, renewedFingerprint, cid, pair)
		}) {
			return
		}
	}
	if err := os.Remove(materialRenewed); err != nil {
		t.Fatal(err)
	}
	if err := materialClient.Conn().ForceReconnect(); err != nil {
		t.Fatal(err)
	}
	assertMaterial(t, materialClient.Conn(), startupJWT, userID, startupFingerprint, cid, pair)
	if err := materialClient.Close(); err != nil {
		t.Fatal(err)
	}
	drainBridge(t)

	// The foreign credential must be admissible, so broker denial cannot mask selection.
	for _, control := range []struct {
		name, credentials, jwt, user string
	}{
		{"foreign positive control", foreign, foreignJWT, foreignID},
		{"static startup credentials", materialStartup, startupJWT, userID},
	} {
		if !t.Run(control.name, func(t *testing.T) {
			cfg := materialConfig
			cfg.CredentialsFile, cfg.ReloadClientMaterial = control.credentials, nil
			controlClient, err := Start(materialCtx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer controlClient.Close()
			assertMaterial(t, controlClient.Conn(), control.jwt, control.user, startupFingerprint, 0, nil)
			if err := controlClient.Close(); err != nil {
				t.Fatal(err)
			}
			drainBridge(t)
		}) {
			return
		}
	}
}
