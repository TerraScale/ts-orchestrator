package natscell

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

// subscribe registers leaf interest; a wildcard is never permission-checked
// by the hub at LS+ time.
func (l *rawLeaf) subscribe(t *testing.T, subject string) {
	t.Helper()
	if _, err := fmt.Fprintf(l.conn, "LS+ %s\r\nPING\r\n", subject); err != nil {
		t.Fatal(err)
	}
}

// awaitMessage reads until an LMSG on a subject with prefix arrives, the
// link closes, or the timeout passes. It answers PINGs.
func (l *rawLeaf) awaitMessage(t *testing.T, prefix string, timeout time.Duration) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = l.conn.SetReadDeadline(deadline)
		line, err := l.reader.ReadString('\n')
		if err != nil {
			return "", false
		}
		if strings.HasPrefix(line, "PING") {
			_, _ = io.WriteString(l.conn, "PONG\r\n")
			continue
		}
		if !strings.HasPrefix(line, "LMSG ") && !strings.HasPrefix(line, "HMSG ") {
			continue
		}
		fields := strings.Fields(line)
		size, _ := strconv.Atoi(fields[len(fields)-1])
		payload := make([]byte, size+2)
		if _, err := io.ReadFull(l.reader, payload); err != nil {
			return "", false
		}
		if strings.HasPrefix(fields[1], prefix) {
			return fields[1], true
		}
	}
	return "", false
}

// startHubWithChild starts GRU (the hub and global home) with SJC and FRA as
// children; only SJC is actually started. It returns the hub, the SJC spoke,
// the hub's leaf address and the leaf TLS files.
func startHubWithChild(ctx context.Context, t *testing.T) (*testRegion, *Runtime, *Runtime, string, TLSFiles) {
	t.Helper()
	root := t.TempDir()
	topology := HubAndSpoke("gru", []string{"fra", "sjc"})
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf-tls"))
	gru := newTestRegion(t, filepath.Join(root, "gru"), "gru", topology)
	sjc := newTestRegion(t, filepath.Join(root, "sjc"), "sjc", topology)
	leafPort := freeClientPort(t)
	gru.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "0.0.0.0", Port: leafPort, TLS: leafTLS}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(leafPort))
	sjc.cfg.Embedded.InterRegion.Remotes = []LeafRemote{{
		Peer: "gru", URLs: []string{"nats-leaf://" + addr}, ServerName: testLeafServerName,
		CredentialsFile: gru.childLeafCredentials(t, "sjc-leaf.creds", "sjc"), PeerAccount: gru.interregionID, TLS: leafTLS,
	}}
	gruRuntime, err := Start(ctx, gru.cfg)
	if err != nil {
		t.Fatalf("start gru: %v", err)
	}
	t.Cleanup(func() { _ = gruRuntime.Close() })
	sjcRuntime, err := Start(ctx, sjc.cfg)
	if err != nil {
		t.Fatalf("start sjc: %v", err)
	}
	t.Cleanup(func() { _ = sjcRuntime.Close() })
	waitLeafCount(ctx, t, gruRuntime, 1)
	return gru, gruRuntime, sjcRuntime, addr, leafTLS
}

// TestSiblingLeafCannotInterceptAnotherChild: FRA's leaf user, bound by its
// scoped signing key to FRA's subtree, subscribes with wildcards to SJC's
// query service and SJC's mirror feed. GRU's requests to SJC must still be
// answered by SJC alone and nothing addressed to SJC may reach FRA.
func TestSiblingLeafCannotInterceptAnotherChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	gru, gruRuntime, sjcRuntime, addr, leafTLS := startHubWithChild(ctx, t)

	sjcQuery, err := sjcRuntime.Conn().Subscribe(protocol.Regional("sjc", "query", "status"), func(msg *nats.Msg) {
		_ = msg.Respond([]byte("sjc-ok"))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sjcQuery.Unsubscribe()
	if err := sjcRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	if reply := requestUntil(ctx, t, gruRuntime.Conn(), protocol.Regional("sjc", "query", "status")); string(reply.Data) != "sjc-ok" {
		t.Fatalf("baseline query = %q", reply.Data)
	}
	assertObservabilityCrossesNarrowly(ctx, t, gruRuntime, sjcRuntime)

	sibling := dialRawLeaf(ctx, t, addr, leafTLS, gru.childLeafCredentials(t, "fra-leaf.creds", "fra"))
	defer sibling.close()
	for _, wildcard := range []string{"ts.orch.v1.sjc.>", "ts.orch.v1.*.query.>", "ts.interregion.v1.>", ">"} {
		sibling.subscribe(t, wildcard)
	}
	time.Sleep(300 * time.Millisecond)
	for range 5 {
		reply := requestUntil(ctx, t, gruRuntime.Conn(), protocol.Regional("sjc", "query", "status"))
		if string(reply.Data) != "sjc-ok" {
			t.Fatalf("query to SJC answered by someone else: %q", reply.Data)
		}
	}
	// SJC's mirror feed and its observability requests are SJC's alone too.
	for range 5 {
		if err := gruRuntime.Conn().Publish(protocol.InterRegionGlobalDeliverSubject("sjc"), []byte("feed")); err != nil {
			t.Fatal(err)
		}
		for _, leaf := range protocol.InterRegionObservabilityLeaves() {
			requestCtx, requestCancel := context.WithTimeout(ctx, 200*time.Millisecond)
			_, _ = gruRuntime.Conn().RequestWithContext(requestCtx, protocol.InterRegionObservabilitySubject("sjc", leaf),
				[]byte(`{"version":1}`))
			requestCancel()
		}
	}
	if err := gruRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	if subject, got := sibling.awaitMessage(t, "ts.", 500*time.Millisecond); got {
		t.Fatalf("FRA's leaf intercepted %q addressed to SJC", subject)
	}

	// FRA cannot speak for SJC either: its health is refused and the link closes.
	impostor := dialRawLeaf(ctx, t, addr, leafTLS, gru.childLeafCredentials(t, "fra-impostor.creds", "fra"))
	impostor.publish(t, protocol.RegionHealthSubject("sjc"), "", []byte("forged"))
	if reason := impostor.awaitClose(t); !strings.Contains(reason, "Permissions Violation for Publish") {
		t.Fatalf("FRA published SJC's health; link closed with %q", reason)
	}
	resetter := dialRawLeaf(ctx, t, addr, leafTLS, gru.childLeafCredentials(t, "fra-reset.creds", "fra"))
	resetter.publish(t, protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix("gru"), protocol.GlobalControlStream,
		protocol.GlobalMirrorConsumer("sjc")), "", []byte(`{"seq":99}`))
	if reason := resetter.awaitClose(t); !strings.Contains(reason, "Permissions Violation for Publish") {
		t.Fatalf("FRA reset SJC's mirror consumer; link closed with %q", reason)
	}
	// A user signed by the interregion account identity key rather than a
	// child's scoped key gets the deny-all defaults, even for FRA's subjects.
	identity := dialRawLeaf(ctx, t, addr, leafTLS, gru.leafCredentials(t, "identity.creds"))
	identity.publish(t, protocol.RegionHealthSubject("fra"), "", []byte("unscoped"))
	if reason := identity.awaitClose(t); !strings.Contains(reason, "Permissions Violation for Publish") {
		t.Fatalf("unscoped leaf user published; link closed with %q", reason)
	}
	// Its own region's subjects still cross.
	own := dialRawLeaf(ctx, t, addr, leafTLS, gru.childLeafCredentials(t, "fra-own.creds", "fra"))
	defer own.close()
	health := make(chan *nats.Msg, 4)
	healthSub, err := gruRuntime.Conn().ChanSubscribe(protocol.RegionHealthSubject("fra"), health)
	if err != nil {
		t.Fatal(err)
	}
	defer healthSub.Unsubscribe()
	if err := gruRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		own.publish(t, protocol.RegionHealthSubject("fra"), "", []byte("fra-health"))
		select {
		case msg := <-health:
			if string(msg.Data) == "fra-health" {
				return
			}
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("FRA's own health did not cross")
		}
	}
}
