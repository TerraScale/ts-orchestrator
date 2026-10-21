package natscell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// TestMeshHubRecoveryPreservesLocalServing exercises production JWT accounts,
// mTLS leaves and disk stores; loopback endpoints stand in for the overlay.
func TestMeshHubRecoveryPreservesLocalServing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"gru", "sjc", "fra"}
	regions := map[string]*testRegion{}
	runtimes := map[string]*Runtime{}
	for _, name := range names {
		region := newLinkRegion(t, filepath.Join(root, name), name, signerID)
		region.cfg.CredentialsFile = linkControllerCredentials(t, root, name+"-controller.creds", region)
		regions[name] = region
	}
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf-tls"))
	useLinkListener(t, freeClientPort(t))
	regions["gru"].cfg.Embedded.Link = &Link{TLS: leafTLS}
	for _, name := range names[1:] {
		regions[name].cfg.Embedded.Link = &Link{TLS: leafTLS,
			CredentialsFile: linkUserCredentials(t, root, name+"-leaf.creds", signer, regions["gru"].cellID, name)}
	}
	t.Cleanup(func() {
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	})
	start := func(name string) {
		t.Helper()
		runtime, err := Start(ctx, regions[name].cfg)
		if err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		runtimes[name] = runtime
		_, err = runtime.Conn().Subscribe(protocol.InterRegionObservabilitySubject(name, protocol.ObservabilityRegionLeaf),
			func(msg *nats.Msg) { _ = msg.Respond([]byte(name)) })
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Conn().Flush(); err != nil {
			t.Fatal(err)
		}
	}
	probe := func(from, to string) {
		t.Helper()
		subject := protocol.InterRegionObservabilitySubject(to, protocol.ObservabilityRegionLeaf)
		if reply := requestUntil(ctx, t, runtimes[from].Conn(), subject); string(reply.Data) != to {
			t.Fatalf("%s -> %s replied %q", from, to, reply.Data)
		}
	}
	allDirections := func(phase string) {
		t.Helper()
		for _, from := range names {
			for _, to := range names {
				if from != to {
					probe(from, to)
					t.Logf("%s: %s -> %s authenticated reply identifies %s", phase, from, to, to)
				}
			}
		}
	}
	identity := func(name string) string {
		t.Helper()
		var identity string
		for _, file := range []string{storeIdentityFile, nodeIdentityFile} {
			data, err := os.ReadFile(filepath.Join(regions[name].cfg.Embedded.StoreDir, file))
			if err != nil {
				t.Fatal(err)
			}
			identity += string(data)
		}
		return identity
	}
	for _, name := range names {
		start(name)
		_, err := runtimes[name].JetStream().CreateStream(ctx, jetstream.StreamConfig{
			Name: "LOCAL", Subjects: []string{protocol.Regional(name, "local")}, Storage: jetstream.FileStorage,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtimes[name].JetStream().Publish(ctx, protocol.Regional(name, "local"), []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	waitLeafCount(ctx, t, runtimes["gru"], 2)
	allDirections("before hub loss")
	initial := runtimes["gru"].InitialCellJWT()
	// NATS compares issued-at at second precision; make every replacement newer.
	time.Sleep(1100 * time.Millisecond)
	replacement := func(mutate func(*jwt.AccountClaims)) string {
		t.Helper()
		claim, err := jwt.DecodeAccountClaims(initial)
		if err != nil {
			t.Fatal(err)
		}
		claim.IssuedAt = time.Now().Unix()
		mutate(claim)
		raw, err := claim.Encode(regions["gru"].operator)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, mutate := range map[string]func(*jwt.AccountClaims){
		"wildcard publish": func(claim *jwt.AccountClaims) {
			claim.SigningKeys[signerID].(*jwt.UserScope).Template.Pub.Allow.Add(">")
		},
		"unlimited leaves": func(claim *jwt.AccountClaims) { claim.Limits.LeafNodeConn = -1 },
		"query remapped to command": func(claim *jwt.AccountClaims) {
			claim.Mappings = jwt.Mapping{jwt.Subject(protocol.Regional("gru", "query", "status")): {
				{Subject: jwt.Subject(protocol.HostRegisterSubject("gru")), Weight: 100},
			}}
		},
		"cross-account import": func(claim *jwt.AccountClaims) {
			claim.Imports.Add(&jwt.Import{Account: regions["sjc"].cellID, Subject: jwt.Subject(protocol.HostRegisterSubject("sjc")), Type: jwt.Service})
		},
		"cross-account export": func(claim *jwt.AccountClaims) {
			claim.Exports.Add(&jwt.Export{Subject: jwt.Subject(protocol.HostRegisterSubject("gru")), Type: jwt.Service})
		},
	} {
		if err := runtimes["gru"].ApplyCellClaim(ctx, 1, replacement(mutate)); err == nil {
			t.Fatalf("operator-signed %s replacement widened live link admission", name)
		}
		current, err := runtimes["gru"].server.Accountz(&server.AccountzOptions{Account: regions["gru"].cellID})
		if err != nil || current.Account == nil || current.Account.Jwt != initial || runtimes["gru"].InitialCellJWT() != initial {
			t.Fatalf("rejected %s replacement changed broker/resolver claim: %+v, %v", name, current, err)
		}
		allDirections("after rejected " + name)
	}
	valid := replacement(func(claim *jwt.AccountClaims) { claim.Limits.JetStreamLimits.Streams = 19 })
	if err := runtimes["gru"].ApplyCellClaim(ctx, 1, valid); err != nil {
		t.Fatalf("link-preserving account renewal rejected: %v", err)
	}
	allDirections("after valid account renewal")
	identities := map[string]string{}
	serverIDs := map[string]string{}
	for _, name := range names {
		identities[name], serverIDs[name] = identity(name), runtimes[name].server.ID()
	}

	cut := time.Now()
	if err := runtimes["gru"].Close(); err != nil {
		t.Fatal(err)
	}
	if runtimes["gru"].Ready() {
		t.Fatal("stopped hub reports ready")
	}
	for _, name := range names[1:] {
		runtime := runtimes[name]
		waitLeafCount(ctx, t, runtime, 0)
		if !runtime.Ready() || !runtime.FullClusterReady(1) {
			t.Fatalf("%s lost local readiness with the hub stopped", name)
		}
		probe(name, name)
		if _, err := runtime.JetStream().Publish(ctx, protocol.Regional(name, "local"), []byte("hub unavailable")); err != nil {
			t.Fatalf("%s local publish while hub stopped: %v", name, err)
		}
		for _, to := range names {
			if name == to {
				continue
			}
			requestCtx, stop := context.WithTimeout(ctx, 300*time.Millisecond)
			_, err := runtime.Conn().RequestWithContext(requestCtx,
				protocol.InterRegionObservabilitySubject(to, protocol.ObservabilityRegionLeaf), []byte("probe"))
			stop()
			if !errors.Is(err, nats.ErrNoResponders) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s -> %s with hub stopped: got %v, want unavailable request", name, to, err)
			}
			t.Logf("hub stopped: %s -> %s reports %v; local serving remains ready", name, to, err)
		}
	}

	start("gru")
	waitLeafCount(ctx, t, runtimes["gru"], 2)
	allDirections("after hub restart")
	for _, name := range names {
		runtime := runtimes[name]
		if got := identity(name); got != identities[name] || runtime.CellAccount() != regions[name].cellID {
			t.Fatalf("%s changed persistent node/store/account identity", name)
		}
		if name != "gru" && (runtime.server.ID() != serverIDs[name] || runtime.Conn().Stats().Reconnects != 0) {
			t.Fatalf("%s restarted its regional broker/client during global recovery", name)
		}
		stream, err := runtime.JetStream().Stream(ctx, "LOCAL")
		if err != nil {
			t.Fatal(err)
		}
		message, err := stream.GetMsg(ctx, 1)
		if err != nil || string(message.Data) != name {
			t.Fatalf("%s lost its original local message: %+v, %v", name, message, err)
		}
		if name != "gru" {
			message, err := stream.GetMsg(ctx, 2)
			if err != nil || string(message.Data) != "hub unavailable" {
				t.Fatalf("%s lost its partition-time write: %+v, %v", name, message, err)
			}
		}
		info, err := runtime.JetStream().AccountInfo(ctx)
		if err != nil || info.Domain != name {
			t.Fatalf("%s JetStream domain: %+v, %v", name, info, err)
		}
	}
	t.Logf("hub loss and automatic recovery completed in %s", time.Since(cut).Round(time.Millisecond))
}

func TestMeshStartupRejectsInvalidLinkAdmission(t *testing.T) {
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	useLinkListener(t, freeClientPort(t))
	for _, name := range []string{
		"both link contracts", "missing spoke credentials", "another region", "expired user",
		"future user", "permission-carrying user", "wrong user seed", "home credentials",
		"home missing signer", "home widened template", "home unlimited leaves", "missing mutual TLS",
		"uppercase region", "invalid home account",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			home := newLinkRegion(t, filepath.Join(root, "gru"), "gru", signerID)
			region := newLinkRegion(t, filepath.Join(root, "sjc"), "sjc", signerID)
			leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf-tls"))
			if name == "home credentials" || name == "home missing signer" || name == "home widened template" || name == "home unlimited leaves" {
				region = home
			}
			region.cfg.CredentialsFile = linkControllerCredentials(t, root, "controller.creds", region)
			region.cfg.Embedded.Link = &Link{TLS: leafTLS}
			if region != home {
				region.cfg.Embedded.Link.CredentialsFile = linkUserCredentials(t, root, "leaf.creds", signer, home.cellID, "sjc")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			working, err := Start(ctx, region.cfg)
			if err != nil {
				t.Fatalf("valid production startup before invalid replacement: %v", err)
			}
			_, probeErr := working.JetStream().AccountInfo(ctx)
			_ = working.Close()
			if probeErr != nil {
				t.Fatalf("valid production JetStream request before invalid replacement: %v", probeErr)
			}
			if name == "home credentials" {
				region.cfg.Embedded.Link.CredentialsFile = linkUserCredentials(t, root, "leaf.creds", signer, home.cellID, "sjc")
			}
			mutateUser := func(mutate func(*jwt.UserClaims)) {
				t.Helper()
				data, err := os.ReadFile(region.cfg.Embedded.Link.CredentialsFile)
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
				mutate(claim)
				raw, err = claim.Encode(signer)
				if err != nil {
					t.Fatal(err)
				}
				if name == "wrong user seed" {
					key, err = nkeys.CreateUser()
					if err != nil {
						t.Fatal(err)
					}
					defer key.Wipe()
				}
				seed, err := key.Seed()
				if err != nil {
					t.Fatal(err)
				}
				creds, err := jwt.DecorateJWT(raw)
				if err != nil {
					t.Fatal(err)
				}
				seedBlock, err := jwt.DecorateSeed(seed)
				if err != nil {
					t.Fatal(err)
				}
				creds = append(creds, seedBlock...)
				if err := os.WriteFile(region.cfg.Embedded.Link.CredentialsFile, creds, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "both link contracts":
				region.cfg.Embedded.InterRegion = &InterRegion{AccountJWTFile: "unused"}
			case "missing spoke credentials":
				region.cfg.Embedded.Link.CredentialsFile = ""
			case "another region":
				mutateUser(func(claim *jwt.UserClaims) { claim.Tags = jwt.TagList{"cell:fra"} })
			case "expired user":
				mutateUser(func(claim *jwt.UserClaims) { claim.Expires = time.Now().Add(-time.Minute).Unix() })
			case "future user":
				mutateUser(func(claim *jwt.UserClaims) { claim.NotBefore = time.Now().Add(time.Minute).Unix() })
			case "permission-carrying user":
				mutateUser(func(claim *jwt.UserClaims) { claim.Pub.Allow.Add(">") })
			case "wrong user seed":
				mutateUser(func(*jwt.UserClaims) {})
			case "uppercase region":
				region.cfg.Cell = "SJC"
			case "invalid home account":
				mutateUser(func(claim *jwt.UserClaims) { claim.IssuerAccount = home.cellID + "x" })
			case "home missing signer", "home widened template", "home unlimited leaves":
				raw, err := os.ReadFile(region.cfg.Embedded.CellJWTFile)
				if err != nil {
					t.Fatal(err)
				}
				claim, err := jwt.DecodeAccountClaims(string(raw))
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "home missing signer":
					delete(claim.SigningKeys, signerID)
				case "home widened template":
					claim.SigningKeys[signerID].(*jwt.UserScope).Template.Sub.Allow.Add(">")
				case "home unlimited leaves":
					claim.Limits.LeafNodeConn = -1
				}
				encoded, err := claim.Encode(region.operator)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(region.cfg.Embedded.CellJWTFile, []byte(encoded), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing mutual TLS":
				region.cfg.Embedded.Link.TLS = TLSFiles{}
			}
			runtime, err := Start(ctx, region.cfg)
			if runtime != nil {
				_ = runtime.Close()
			}
			if err == nil {
				t.Fatalf("invalid %s admission started a production broker", name)
			}
			t.Logf("production startup refused %s: %v", name, err)
		})
	}
}
