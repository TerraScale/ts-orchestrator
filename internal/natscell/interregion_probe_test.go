package natscell

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// steeringRequest is the review probe: a consumer-create request whose
// delivery subject is a hub-local controller command subject. Before the fix
// GRU accepted it through the linked API prefix and delivered global records
// onto its own placement.apply subscriber.
func steeringRequest(t *testing.T, name string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"stream_name": protocol.GlobalControlStream,
		"config": map[string]any{
			"name": name, "durable_name": name, "deliver_policy": "all", "ack_policy": "none",
			"deliver_subject": protocol.PlacementApplySubject("gru"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// steeringSubjects are every JetStream API spelling a peer could try to reach
// the home stream with: the linked prefix, the domain prefix, and the verbs
// beside the one the contract carries.
func steeringSubjects() []string {
	linked := protocol.JSDomainAPIPrefix("gru")
	stream := protocol.GlobalControlStream
	return []string{
		linked + ".CONSUMER.CREATE." + stream,
		linked + ".CONSUMER.CREATE." + stream + ".evil",
		linked + ".CONSUMER.CREATE." + stream + ".evil." + protocol.GlobalStateStreamSubject(),
		linked + ".CONSUMER.DURABLE.CREATE." + stream + ".evil",
		linked + ".CONSUMER.DELETE." + stream + "." + protocol.GlobalMirrorConsumer("sfo"),
		linked + ".STREAM.PURGE." + stream,
		linked + ".STREAM.INFO." + stream,
		linked + ".INFO",
		"$JS.gru.API.CONSUMER.CREATE." + stream,
		"$JS.gru.API.CONSUMER.CREATE." + stream + ".evil",
		"$JS.gru.API.STREAM.INFO." + stream,
	}
}

// assertPeerCannotSteerHomeDelivery replays the review probe from a peer's
// cell account and requires that nothing answers, nothing lands on GRU's
// placement subject, and the home stream keeps exactly its contract consumer.
func assertPeerCannotSteerHomeDelivery(ctx context.Context, t *testing.T, peer *nats.Conn, home jetstream.Stream,
	gruCommands <-chan *nats.Msg,
) {
	t.Helper()
	for _, subject := range steeringSubjects() {
		requestCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		msg, err := peer.RequestWithContext(requestCtx, subject, steeringRequest(t, "evil"))
		cancel()
		if err == nil {
			t.Fatalf("peer reached the home JetStream API through %q: %s", subject, msg.Data)
		}
	}
	select {
	case msg := <-gruCommands:
		t.Fatalf("peer steered home delivery onto %q: %s", msg.Subject, msg.Data)
	case <-time.After(time.Second):
	}
	assertOnlyContractConsumer(ctx, t, home)
}

func assertOnlyContractConsumer(ctx context.Context, t *testing.T, home jetstream.Stream) {
	t.Helper()
	var names []string
	lister := home.ConsumerNames(ctx)
	for name := range lister.Name() {
		names = append(names, name)
	}
	if err := lister.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{protocol.GlobalMirrorConsumer("sfo")}) {
		t.Fatalf("home stream consumers = %v, want only the contract mirror consumer", names)
	}
	consumer, err := home.PushConsumer(ctx, protocol.GlobalMirrorConsumer("sfo"))
	if err != nil {
		t.Fatal(err)
	}
	if got := consumer.CachedInfo().Config.DeliverSubject; got != protocol.InterRegionGlobalDeliverSubject("sfo") {
		t.Fatalf("home mirror consumer delivers to %q", got)
	}
}

// assertRawLeafPeerIsDenyByDefault speaks the leafnode protocol directly with
// a valid GRU interregion leaf credential, so no well-behaved peer server
// filters anything first. GRU itself must refuse every subject outside the
// contract (closing the link) while still accepting contract subjects.
func assertRawLeafPeerIsDenyByDefault(ctx context.Context, t *testing.T, gru *testRegion, gruConn, sfoConn *nats.Conn,
	home jetstream.Stream, addr string, leafTLS TLSFiles, gruCommands <-chan *nats.Msg,
) {
	t.Helper()
	creds := gru.childLeafCredentials(t, "raw-leaf.creds", "sfo")

	// A forged record on SFO's mirror feed must never reach SFO: deny-by-
	// default stops one peer from relaying onto another peer's subjects.
	forgedFeed := make(chan *nats.Msg, 16)
	feed, err := sfoConn.ChanSubscribe(protocol.InterRegionGlobalDeliverSubject("sfo"), forgedFeed)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Unsubscribe()
	if err := sfoConn.Flush(); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"forged peer mirror feed": protocol.InterRegionGlobalDeliverSubject("sfo"),
		"hub placement command":   protocol.PlacementApplySubject("gru"),
		"hub control log":         protocol.Control("gru", "lease"),
		"raw JetStream API":       "$JS.API.CONSUMER.CREATE." + protocol.GlobalControlStream,
		"linked consumer create":  protocol.JSDomainAPIPrefix("gru") + ".CONSUMER.CREATE." + protocol.GlobalControlStream,
		"arbitrary peer relay":    "peer.relay",
	}
	for name, subject := range refused {
		leaf := dialRawLeaf(ctx, t, addr, leafTLS, creds)
		leaf.publish(t, subject, protocol.JSDomainAPIPrefix("sfo")+".reply", steeringRequest(t, "raw"))
		if reason := leaf.awaitClose(t); !strings.Contains(reason, "Permissions Violation for Publish") {
			t.Errorf("%s: hub did not refuse %q, closed with %q", name, subject, reason)
		}
	}
	select {
	case msg := <-gruCommands:
		t.Fatalf("raw leaf reached hub placement subject: %s", msg.Data)
	case msg := <-forgedFeed:
		if strings.Contains(string(msg.Data), "raw") {
			t.Fatalf("raw leaf forged SFO's mirror feed: %s", msg.Data)
		}
	case <-time.After(500 * time.Millisecond):
	}
	assertOnlyContractConsumer(ctx, t, home)

	// Contract subjects still cross from the same credential: the link is
	// narrowed, not broken.
	health := make(chan *nats.Msg, 16)
	healthSub, err := gruConn.ChanSubscribe(protocol.RegionHealthSubject("sfo"), health)
	if err != nil {
		t.Fatal(err)
	}
	defer healthSub.Unsubscribe()
	if err := gruConn.Flush(); err != nil {
		t.Fatal(err)
	}
	leaf := dialRawLeaf(ctx, t, addr, leafTLS, creds)
	defer leaf.close()
	for {
		leaf.publish(t, protocol.RegionHealthSubject("sfo"), "", []byte("raw-contract"))
		select {
		case msg := <-health:
			if string(msg.Data) == "raw-contract" {
				return
			}
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("raw leaf contract subject did not cross")
		}
	}
}

type rawLeaf struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialRawLeaf(ctx context.Context, t *testing.T, addr string, files TLSFiles, credsPath string) *rawLeaf {
	t.Helper()
	data, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatal(err)
	}
	userJWT, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		t.Fatal(err)
	}
	user, err := jwt.ParseDecoratedNKey(data)
	if err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	plain, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(plain).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("leaf INFO = %q, %v", line, err)
	}
	var info struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "INFO ")), &info); err != nil || info.Nonce == "" {
		t.Fatalf("leaf INFO nonce: %v", err)
	}
	config, err := loadTLS(files, false)
	if err != nil {
		t.Fatal(err)
	}
	config.ServerName = "127.0.0.1"
	secure := tls.Client(plain, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	signature, err := user.Sign([]byte(info.Nonce))
	if err != nil {
		t.Fatal(err)
	}
	connect, err := json.Marshal(map[string]any{
		"version": "2.15.0", "jwt": userJWT, "sig": base64.RawURLEncoding.EncodeToString(signature),
		"name": "raw-leaf", "headers": true, "compress_mode": "off", "protocol": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := &rawLeaf{conn: secure, reader: bufio.NewReader(secure)}
	if _, err := fmt.Fprintf(secure, "CONNECT %s\r\nPING\r\n", connect); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := leaf.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("raw leaf handshake: %v", err)
		}
		switch {
		case strings.HasPrefix(line, "PONG"):
			_ = secure.SetDeadline(time.Time{})
			return leaf
		case strings.HasPrefix(line, "-ERR"):
			t.Fatalf("hub refused the raw leaf credential: %s", line)
		case strings.HasPrefix(line, "PING"):
			_, _ = io.WriteString(secure, "PONG\r\n")
		}
	}
}

func (l *rawLeaf) publish(t *testing.T, subject, reply string, payload []byte) {
	t.Helper()
	header := "LMSG " + subject
	if reply != "" {
		header += " " + reply
	}
	if _, err := fmt.Fprintf(l.conn, "%s %d\r\n%s\r\nPING\r\n", header, len(payload), payload); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

// awaitClose reads until the hub closes the link and returns its last -ERR.
func (l *rawLeaf) awaitClose(t *testing.T) string {
	t.Helper()
	defer l.close()
	_ = l.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reason := ""
	for {
		line, err := l.reader.ReadString('\n')
		if strings.HasPrefix(line, "-ERR") {
			reason = strings.TrimSpace(line)
		}
		if strings.HasPrefix(line, "PING") {
			_, _ = io.WriteString(l.conn, "PONG\r\n")
		}
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				return "link stayed open; last error " + reason
			}
			return reason
		}
	}
}

func (l *rawLeaf) close() { _ = l.conn.Close() }

// assertForwardResetFailsMirrorClosed: the reset verb of a mirror consumer is
// a contract subject its own region's leaf users may send (a sibling's scoped
// leaf users may not; see TestSiblingLeafCannotInterceptAnotherChild), and
// NATS accepts a reset to any sequence, including one ahead of what the
// mirror stored. The mirror then skips those home records for good. A
// compromised or buggy SFO leaf credential can still do that, so the mirror
// reader must notice the gap and fail closed instead of serving a record that
// a skipped one may have superseded.
func assertForwardResetFailsMirrorClosed(ctx context.Context, t *testing.T, gru *testRegion, gruJS jetstream.JetStream,
	mirror jetstream.Stream, reader *globalcontrol.Reader, addr string, leafTLS TLSFiles,
) {
	t.Helper()
	if _, _, err := reader.Roster(ctx); errors.Is(err, globalcontrol.ErrMirrorGap) {
		t.Fatalf("gap-free mirror reported a gap: %v", err)
	}
	info, err := mirror.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := info.State.LastSeq
	leaf := dialRawLeaf(ctx, t, addr, leafTLS, gru.childLeafCredentials(t, "compromised-leaf.creds", "sfo"))
	defer leaf.close()
	reset := protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix("gru"), protocol.GlobalControlStream,
		protocol.GlobalMirrorConsumer("sfo"))
	leaf.publish(t, reset, "_R_.sibling", fmt.Appendf(nil, `{"seq":%d}`, stored+4))
	time.Sleep(500 * time.Millisecond)
	for index := range 6 {
		if _, err := gruJS.Publish(ctx, protocol.GlobalState("roster", fmt.Sprintf("skip%d", index)), []byte("r")); err != nil {
			t.Fatal(err)
		}
	}
	for {
		info, err := mirror.Info(ctx)
		if err == nil && info.State.LastSeq == stored+6 {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("mirror never caught up after the forward reset: %+v, %v", info, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, _, err := reader.Roster(ctx); !errors.Is(err, globalcontrol.ErrMirrorGap) {
		t.Fatalf("mirror with skipped home records served a read: %v", err)
	}
}
