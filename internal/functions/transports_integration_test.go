package functions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func transportWorker(t *testing.T, kind string) *Worker {
	t.Helper()
	w, err := newWorker(t.Context(), integrationArtifact(t, kind))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(context.Background()) })
	return w
}

func TestHTTPRealWorkerAuthenticationScopeAndLimits(t *testing.T) {
	worker := transportWorker(t, "echo")
	if _, err := NewHTTPHandler(worker, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing authorizer: %v", err)
	}
	otherTenant := entityid.New()
	handler, err := NewHTTPHandler(worker, func(r *http.Request) (string, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer valid":
			return worker.Manifest().TenantID, nil
		case "Bearer other":
			return otherTenant, nil
		default:
			return "", errors.New("private authentication diagnostic")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		name, method, auth, id, payload string
		status                          int
	}{
		{"success", "POST", "Bearer valid", "http-1", `{"tenant_id":"forged","payload":"raw input"}`, 200},
		{"authentication", "POST", "Bearer invalid", "http-2", "secret payload", 401},
		{"tenant", "POST", "Bearer other", "http-3", "secret payload", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, srv.URL+"/invoke?private=host-secret", strings.NewReader(tc.payload))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", tc.auth)
			req.Header.Set("Idempotency-Key", tc.id)
			req.Header.Set("X-Tenant-ID", otherTenant)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != tc.status {
				t.Fatalf("response %d, %v: %s", resp.StatusCode, err, body)
			}
			if tc.status != 200 {
				if bytes.Contains(body, []byte("secret")) || bytes.Contains(body, []byte("diagnostic")) {
					t.Fatalf("private request or diagnostic leaked: %s", body)
				}
				return
			}
			var guest Invocation
			if err := json.Unmarshal(body, &guest); err != nil {
				t.Fatal(err)
			}
			if guest.TenantID != worker.Manifest().TenantID || guest.FunctionID != worker.Manifest().FunctionID ||
				guest.Revision != worker.Manifest().Revision || guest.ID != tc.id || guest.Trigger != "http" || string(guest.Payload) != tc.payload {
				t.Fatalf("guest input: %+v", guest)
			}
			if bytes.Contains(body, []byte(tc.auth)) || bytes.Contains(body, []byte("host-secret")) {
				t.Fatal("HTTP metadata reached guest")
			}
		})
	}
}

func transportBroker(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	brokers := functionBrokerCluster(t, &server.Options{MaxPayload: 4 << 20})
	nc, err := nats.Connect(brokers[0].ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return nc, js
}

func runTransportQueue(t *testing.T, queue *QueueWorker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		err := queue.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("queue run: %v", err)
		}
		done <- err
	}()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("queue stopped: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("queue did not stop")
		}
	}
	return stop
}

func publishTransportMessage(t *testing.T, js jetstream.JetStream, subject, id string, payload []byte) {
	t.Helper()
	msg := &nats.Msg{Subject: subject, Header: nats.Header{}, Data: payload}
	msg.Header.Set(nats.MsgIdHdr, id)
	if _, err := js.PublishMsg(t.Context(), msg); err != nil {
		t.Fatal(err)
	}
}

func waitTransport(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transport condition did not complete within 8 seconds")
}

func TestQueueRealWorkerReceiptsReplayPoisonAndScope(t *testing.T) {
	nc, js := transportBroker(t)
	worker := transportWorker(t, "echo")
	if err := provisionQueue(t.Context(), nc, worker.Manifest()); err != nil {
		t.Fatal(err)
	}
	queue, err := NewQueueWorker(t.Context(), nc, worker)
	if err != nil {
		t.Fatal(err)
	}
	manifest := worker.Manifest()
	scope, err := QueueIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wantSubject := "ts.functions." + manifest.TenantID + "." + manifest.FunctionID + "." + manifest.Revision
	wantIdentity := fmt.Sprintf("%x", sha256.Sum256([]byte(wantSubject)))
	wantScope := QueueScope{Subject: wantSubject, Stream: "TS_FUNCTION_" + wantIdentity, ReceiptBucket: "TS_FUNCTION_RECEIPTS_" + wantIdentity}
	if scope != wantScope || queue.Subject() != wantSubject {
		t.Fatalf("queue wire identity: scope=%+v subject=%q, want %+v", scope, queue.Subject(), wantScope)
	}
	receipts, err := js.KeyValue(t.Context(), scope.ReceiptBucket)
	if err != nil {
		t.Fatal(err)
	}
	stop := runTransportQueue(t, queue)
	payload := []byte(`{"tenant_id":"forged","revision":"forged"}`)
	publishTransportMessage(t, js, queue.Subject(), "queue-1", payload)
	var receipt jetstream.KeyValueEntry
	waitTransport(t, func() bool {
		receipt, err = receipts.Get(t.Context(), "queue-1")
		return err == nil
	})
	digest := sha256.Sum256(payload)
	if !bytes.Equal(receipt.Value(), digest[:]) {
		t.Fatalf("receipt does not bind raw payload: %x", receipt.Value())
	}
	info, err := queue.consumer.Info(t.Context())
	if err != nil || info.Config.MaxAckPending != 1 || info.Config.MaxRequestBatch != 1 {
		t.Fatalf("consumer limits: %+v, %v", info, err)
	}
	if info.Stream != wantScope.Stream || info.Config.FilterSubject != wantSubject {
		t.Fatalf("broker queue identity: %+v, want %+v", info, wantScope)
	}
	stop()
	if err := worker.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	queue, err = NewQueueWorker(t.Context(), nc, worker)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(t.Context(), info.Stream)
	if err != nil {
		t.Fatal(err)
	}
	streamInfo, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate replay outside broker deduplication without waiting two minutes.
	streamInfo.Config.Duplicates = 100 * time.Millisecond
	if _, err := js.UpdateStream(t.Context(), streamInfo.Config); err != nil {
		t.Fatal(err)
	}
	stop = runTransportQueue(t, queue)
	defer stop()
	publishTransportMessage(t, js, queue.Subject(), "queue-1", payload)
	time.Sleep(110 * time.Millisecond)
	publishTransportMessage(t, js, queue.Subject(), "queue-1", []byte("conflicting payload"))
	publishTransportMessage(t, js, queue.Subject(), "", []byte("missing ID"))
	publishTransportMessage(t, js, queue.Subject(), "oversized", bytes.Repeat([]byte("x"), MaxPayloadBytes+1))
	waitTransport(t, func() bool {
		info, err := stream.Info(t.Context())
		return err == nil && info.State.Msgs == 0
	})
	replayed, err := receipts.Get(t.Context(), "queue-1")
	if err != nil || replayed.Revision() != receipt.Revision() {
		t.Fatalf("replay changed durable result: %v", err)
	}
	otherSubject := strings.Replace(queue.Subject(), worker.Manifest().TenantID, entityid.New(), 1)
	if _, err := js.Publish(t.Context(), otherSubject, []byte("wrong tenant")); !errors.Is(err, jetstream.ErrNoStreamResponse) {
		t.Fatalf("cross-tenant publication: %v", err)
	}
}
