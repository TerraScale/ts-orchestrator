package logs

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type logPipeline struct {
	ctx          context.Context
	conn         *nats.Conn
	js           jetstream.JetStream
	stream       *Stream
	key          string
	view         *View
	http         *httptest.Server
	barriers     *Counter
	stop         context.CancelFunc
	done         chan struct{}
	barrierCount int
}

func newLogPipeline(t *testing.T) *logPipeline {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	conn := startNATS(t)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := OpenStream(ctx, js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	p := &logPipeline{ctx: ctx, conn: conn, js: js, stream: stream, key: publicUserKey(t), barriers: NewCounter("gru", "barrier")}
	p.follow(t, NewView("gru"))
	return p
}

func (p *logPipeline) follow(t *testing.T, view *View) {
	t.Helper()
	p.view = view
	ctx, cancel := context.WithCancel(p.ctx)
	p.stop = cancel
	done := make(chan struct{})
	p.done = done
	go func() {
		defer close(done)
		p.stream.Follow(ctx, view, func(_ context.Context, node, key string) bool {
			return key == p.key && (strings.HasPrefix(node, "node-") || node == "barrier")
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("log follower did not stop")
		}
	})
	p.http = httptest.NewServer(Handler(view))
	p.http.Client().Timeout = 2 * time.Second
	t.Cleanup(p.http.Close)
}

func (p *logPipeline) publish(t *testing.T, key string, window Window) Window {
	t.Helper()
	data, err := json.Marshal(window)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := p.js.Publish(p.ctx, protocol.AgentObservation("gru", key, "logs"), data)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := p.stream.stream.GetMsg(p.ctx, ack.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	var observed Window
	if err := json.Unmarshal(stored.Data, &observed); err != nil {
		t.Fatal(err)
	}
	return observed
}

func (p *logPipeline) get(t *testing.T, query string) Reply {
	t.Helper()
	req, err := http.NewRequestWithContext(p.ctx, http.MethodGet, p.http.URL+"/v1/logs?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := p.http.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("log HTTP status %d: %s", response.StatusCode, data)
	}
	if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("log response headers: %v", response.Header)
	}
	var reply Reply
	if err := json.Unmarshal(data, &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

// A streamed barrier proves earlier messages were processed before HTTP assertions.
func (p *logPipeline) sync(t *testing.T) {
	t.Helper()
	p.barriers.Add(Record{Service: "barrier", Level: LevelDebug, Message: "observed"})
	p.publish(t, p.key, p.barriers.Flush(time.Now().UTC().Truncate(time.Minute)))
	p.barrierCount++
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		reply := p.get(t, "service=barrier")
		if len(reply.Classes) == 1 && reply.Classes[0].Count == p.barrierCount {
			return
		}
		select {
		case <-p.ctx.Done():
			t.Fatalf("log stream barrier: %v; reply=%+v", p.ctx.Err(), reply)
		case <-tick.C:
		}
	}
}

func (p *logPipeline) query(t *testing.T, query string) Reply {
	t.Helper()
	p.sync(t)
	reply := p.get(t, query)
	reply.Classes = slices.DeleteFunc(reply.Classes, func(c ReplyClass) bool { return c.Service == "barrier" })
	reply.Totals = slices.DeleteFunc(reply.Totals, func(c Total) bool { return c.Service == "barrier" })
	return reply
}

// Read real journal bytes before publishing the parser/counter output to JetStream.
func journalRecords(t *testing.T, entries ...Entry) []Record {
	t.Helper()
	p := newLogPipeline(t)
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		line, err := json.Marshal(map[string]string{"_SYSTEMD_UNIT": e.Unit, "_COMM": e.Comm, "_PID": e.PID, "PRIORITY": e.Priority, "__REALTIME_TIMESTAMP": fmt.Sprint(e.At.UnixMicro()), "MESSAGE": e.Message})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(file, string(line)); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{`[104,105]`, `--`, ``, `{"_COMM":"invalid","MESSAGE":[104,105]}`} {
		if _, err := fmt.Fprintln(file, invalid); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	counter := NewCounter("gru", "node-a")
	var parser Parser
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		entry, ok := DecodeJournal(scanner.Bytes())
		if line >= len(entries) {
			if ok {
				t.Fatalf("invalid journal line %q was accepted", scanner.Text())
			}
		} else {
			want := entries[line]
			if !ok || !entry.At.Equal(want.At.Truncate(time.Microsecond)) {
				t.Fatalf("journal entry %d timestamp = %v, decoded = %v", line, entry.At, ok)
			}
			entryFields, wantFields := entry, want
			entryFields.At, wantFields.At = time.Time{}, time.Time{}
			if entryFields != wantFields {
				t.Fatalf("journal entry %d = %+v, want %+v", line, entry, want)
			}
			if record, ok := parser.Parse(entry); ok {
				counter.Add(record)
			}
		}
		line++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for _, record := range parser.Flush() {
		counter.Add(record)
	}
	p.publish(t, p.key, counter.Flush(time.Now().UTC().Truncate(time.Minute)))
	reply := p.query(t, "limit=500")
	var records []Record
	for _, c := range reply.Classes {
		for range c.Count {
			records = append(records, Record{Service: c.Service, Level: c.Level, Component: c.Component, Message: c.Message, Example: c.Example})
		}
	}
	return records
}

func compareRecords(a, b Record) int {
	return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
}

func persistedWindow(t *testing.T, window Window) Window {
	t.Helper()
	p := newLogPipeline(t)
	return p.publish(t, p.key, window)
}

func testClass(service, level, message string, count int) Class {
	return Class{Service: service, Level: level, Component: "core", Message: message, Count: count, Example: message + " example"}
}

func testWindow(node, boot string, seq uint64, minute time.Time, classes ...Class) Window {
	return Window{Version: 1, Region: "gru", Node: node, Minute: minute, Boot: boot, Seq: seq, Classes: classes}
}
