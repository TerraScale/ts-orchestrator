package bootstrapmaterial_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestControllerObservabilityCredentialsAcrossMTLSLeaf(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	type linkedRegion struct {
		material, directory string
		record              bootstrapmaterial.InterRegionRecord
	}
	gruFixture, sfoFixture, link := bootstrapmaterial.ObservabilityLinkFixture(t)
	gru := linkedRegion{gruFixture.Material, gruFixture.Directory, gruFixture.Record}
	sfo := linkedRegion{sfoFixture.Material, sfoFixture.Directory, sfoFixture.Record}
	read := func(directory, name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	freePort := func() int {
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
	type region struct {
		linkedRegion
		broker     *natscell.Runtime
		clients    []*nats.Conn
		errors     []chan error
		journal    *decisionlog.Journal
		aggregator *observability.Aggregator
	}
	regions := []region{{linkedRegion: gru}, {linkedRegion: sfo}}
	leafPort := freePort()
	for index := range regions {
		r := &regions[index]
		var parent *bootstrapmaterial.ParentLink
		if index == 1 {
			parent = link
			if err := os.WriteFile(filepath.Join(r.directory, "leaf-gru.creds"), read(gru.directory, "leaf-sfo.creds"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		interregion, err := bootstrapmaterial.RenderInterRegion(r.record, "controller-a", r.directory, parent, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if interregion.Listen != nil {
			// Production requires the wildcard bind; all test dials stay on loopback.
			interregion.Listen.Port = leafPort
		} else {
			interregion.Remotes[0].URLs = []string{fmt.Sprintf("nats-leaf://127.0.0.1:%d", leafPort)}
		}
		path := func(name string) string { return filepath.Join(r.material, name) }
		tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("controller-a-tls-cert.pem"),
			KeyFile: path("controller-a-tls-key.pem")}
		r.broker, err = natscell.Start(ctx, natscell.Config{Cell: r.record.Cell, Instance: "controller-a",
			Replicas: 1, ClientRole: "controller", CredentialsFile: path("controller-a.creds"), TLS: tlsFiles,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: freePort(), StoreDir: filepath.Join(t.TempDir(), "store"),
				TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: path("operator.jwt"),
				SystemJWTFile: filepath.Join(r.directory, "system-interregion.jwt"),
				CellJWTFile:   filepath.Join(r.directory, "cell-interregion.jwt"), SystemCredentialsFile: path("system.creds"),
				TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: []string{"controller-a"}, InterRegion: &interregion}})
		if err != nil {
			t.Fatalf("start %s: %v", r.record.Cell, err)
		}
		t.Cleanup(func() { _ = r.broker.Close() })
		if err := r.broker.Bridge().OpenUntil(1, r.broker.InitialCellJWT(), time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		r.journal = decisionlog.NewJournal(decisionlog.JournalConfig{Region: r.record.Cell})
		r.journal.Record(ctx, decisionlog.Decision{Kind: decisionlog.KindScaleUp})
	}
	connect := func(r *region, slot string, credentials []byte) (*nats.Conn, chan error) {
		t.Helper()
		pair, err := tls.LoadX509KeyPair(filepath.Join(r.material, slot+"-tls-cert.pem"), filepath.Join(r.material, slot+"-tls-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(read(r.material, "ca.pem")) {
			t.Fatal("invalid regional CA")
		}
		raw, err := jwt.ParseDecoratedJWT(credentials)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(claim.Pub.Allow) == 0 || len(claim.Sub.Allow) == 0 {
			t.Fatal("integration test requires restricted production credentials")
		}
		failures := make(chan error, 32)
		// The production bridge terminates TLS before the embedded server's plaintext INFO.
		conn, err := nats.Connect(r.broker.URL(), nats.UserCredentialBytes(credentials),
			nats.CustomInboxPrefix(protocol.InboxPrefix(r.record.Cell, claim.Subject)), nats.NoReconnect(),
			nats.SetCustomDialer(&tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second},
				Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: "controller-a"}}),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { failures <- err }))
		if err != nil {
			t.Fatalf("connect %s/%s: %v", r.record.Cell, slot, err)
		}
		t.Cleanup(conn.Close)
		return conn, failures
	}
	flush := func(conn *nats.Conn) {
		t.Helper()
		if err := conn.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
	}
	permissionDenied := func(conn *nats.Conn, failures <-chan error, subject string) {
		t.Helper()
		flush(conn)
		select {
		case err := <-failures:
			if !errors.Is(err, nats.ErrPermissionViolation) || !strings.Contains(err.Error(), subject) {
				t.Fatalf("%s: expected permission violation, got %v", subject, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s: no asynchronous permission violation", subject)
		}
	}
	requestDenied := func(conn *nats.Conn, failures <-chan error, subject string) {
		t.Helper()
		if msg, err := conn.Request(subject, []byte(`{"version":1}`), 100*time.Millisecond); err == nil {
			t.Fatalf("forbidden request %s answered: %q", subject, msg.Data)
		}
		permissionDenied(conn, failures, subject)
	}
	names := []string{"controller-a", "controller-b", "controller-c"}
	for index := range regions {
		r := &regions[index]
		old := read(r.material, "controller-a.creds")
		raw, err := jwt.ParseDecoratedJWT(old)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		// Model deficient installed credentials; founding material always grants telemetry.
		claim.Sub.Allow.Remove(protocol.ObservabilityGrant(r.record.Cell))
		signer, err := nkeys.FromSeed(bytes.TrimSpace(read(r.material, "issuer-cell.seed")))
		if err != nil {
			t.Fatal(err)
		}
		defer signer.Wipe()
		user, err := jwt.ParseDecoratedUserNKey(old)
		if err != nil {
			t.Fatal(err)
		}
		defer user.Wipe()
		old, err = bootstrapmaterial.CredentialsForTest(claim, signer, user)
		if err != nil {
			t.Fatal(err)
		}
		conn, failures := connect(r, "controller-a", old)
		collector, err := observability.NewCollector(observability.CollectorConfig{Cell: r.record.Cell, Member: names[0], Role: "controller",
			System: func() (observability.SystemView, error) { return observability.SystemView{}, nil }})
		if err != nil {
			t.Fatal(err)
		}
		// Subscribe succeeds locally even when the server rejects it asynchronously.
		responders := []struct {
			leaf  string
			serve func() (*nats.Subscription, error)
		}{
			{observability.SnapshotLeaf, func() (*nats.Subscription, error) {
				return observability.ServeSnapshots(ctx, conn, r.record.Cell, collector)
			}},
			{regionview.SummaryLeaf, func() (*nats.Subscription, error) {
				return regionview.Serve(ctx, conn, r.record.Cell, &regionview.Provider{Cell: r.record.Cell})
			}},
			{decisionlog.QueryLeaf, func() (*nats.Subscription, error) {
				return decisionlog.ServeQueries(ctx, conn, r.record.Cell, r.journal)
			}},
		}
		for _, responder := range responders {
			sub, err := responder.serve()
			if err != nil {
				t.Fatal(err)
			}
			permissionDenied(conn, failures, protocol.InterRegionObservabilitySubject(r.record.Cell, responder.leaf))
			_ = sub.Unsubscribe()
		}
		conn.Close()
		for _, slot := range names {
			conn, failures := connect(r, slot, read(r.material, slot+".creds"))
			r.clients, r.errors = append(r.clients, conn), append(r.errors, failures)
			collector, err := observability.NewCollector(observability.CollectorConfig{Cell: r.record.Cell, Member: slot, Role: "controller",
				System: func() (observability.SystemView, error) { return observability.SystemView{}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := observability.ServeSnapshots(ctx, conn, r.record.Cell, collector); err != nil {
				t.Fatal(err)
			}
			if _, err := decisionlog.ServeQueries(ctx, conn, r.record.Cell, r.journal); err != nil {
				t.Fatal(err)
			}
			flush(conn)
		}
		r.aggregator, err = observability.NewAggregator(r.clients[0], r.record.Cell, names, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for _, conn := range r.clients {
			if _, err := regionview.Serve(ctx, conn, r.record.Cell, &regionview.Provider{Cell: r.record.Cell, Cluster: r.aggregator}); err != nil {
				t.Fatal(err)
			}
			flush(conn)
		}
	}
	for index := range regions {
		r, peer := &regions[index], regions[1-index].record.Cell
		cluster, err := r.aggregator.Cluster(ctx, false)
		if err != nil || len(cluster.Members) != 3 || len(cluster.Missing) != 0 {
			t.Fatalf("%s local snapshots: %+v, %v", r.record.Cell, cluster, err)
		}
		for _, member := range cluster.Members {
			if member.Version != 1 || member.Cell != r.record.Cell {
				t.Fatalf("invalid local snapshot: %+v", member)
			}
		}
		for clientIndex, conn := range r.clients {
			for _, leaf := range protocol.InterRegionObservabilityLeaves() {
				subject := protocol.InterRegionObservabilitySubject(peer, leaf)
				var msg *nats.Msg
				for {
					msg, err = conn.Request(subject, []byte(`{"version":1}`), time.Second)
					if err == nil {
						break
					}
					if ctx.Err() != nil || !(errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrTimeout)) {
						t.Fatalf("%s -> %s: %v", r.record.Cell, subject, err)
					}
					time.Sleep(20 * time.Millisecond)
				}
				if leaf == regionview.SummaryLeaf {
					var summary regionview.Summary
					if err := json.Unmarshal(msg.Data, &summary); err != nil || summary.Version != 1 || summary.Region != peer || summary.Quorum.Answering != 3 {
						t.Fatalf("%s summary: %+v, %v", subject, summary, err)
					}
				} else {
					var reply struct {
						Version int                 `json:"version"`
						Region  string              `json:"region"`
						Result  *decisionlog.Result `json:"result"`
						Error   string              `json:"error"`
					}
					if err := json.Unmarshal(msg.Data, &reply); err != nil || reply.Version != 1 || reply.Region != peer || reply.Error != "" ||
						reply.Result == nil || len(reply.Result.Decisions) != 1 || reply.Result.Decisions[0].Region != peer {
						t.Fatalf("%s decisions: %+v, %v", subject, reply, err)
					}
				}
			}
			links, err := regionlink.New(r.record.Cell, conn, []string{peer}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err := links.Link(peer, conn); err != nil {
				t.Fatal(err)
			}
			provider := &regionview.Provider{Cell: r.record.Cell, Links: links}
			if probe := provider.Probe(ctx, peer); probe.Reach != decisionlog.RegionOK || probe.Region != peer || len(probe.Members) != 3 {
				t.Fatalf("%s controller %d authenticated probe: %+v", r.record.Cell, clientIndex, probe)
			}
			for _, subject := range []string{
				protocol.InterRegionObservabilitySubject(peer, observability.SnapshotLeaf),
				protocol.InterRegionObservabilitySubject(peer, decisionlog.JournalLeaf),
				protocol.PlacementApplySubject(peer),
			} {
				requestDenied(conn, r.errors[clientIndex], subject)
				sub, err := conn.SubscribeSync(subject)
				if err != nil {
					t.Fatal(err)
				}
				permissionDenied(conn, r.errors[clientIndex], subject)
				_ = sub.Unsubscribe()
			}
			flush(conn)
			select {
			case err := <-r.errors[clientIndex]:
				t.Fatalf("%s unexpected asynchronous error: %v", r.record.Cell, err)
			default:
			}
		}
	}
}
