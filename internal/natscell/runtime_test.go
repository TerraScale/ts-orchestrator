package natscell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestEmbeddedSingleNodeDurableRestart(t *testing.T) {
	cfg := productionTestConfig(t, "lab", "one")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	r, err := openTestBroker(t, ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := r.JetStream().CreateStream(ctx, jetstream.StreamConfig{
		Name: "LAB_EVENTS", Subjects: []string{"lab.events"}, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.JetStream().Publish(ctx, "lab.events", []byte("persisted")); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("second close:", err)
	}
	r, err = openTestBroker(t, ctx, cfg)
	if err != nil {
		t.Fatal("restart:", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	stream, err = r.JetStream().Stream(ctx, stream.CachedInfo().Config.Name)
	if err != nil {
		t.Fatal(err)
	}
	message, err := stream.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Data) != "persisted" {
		t.Fatalf("durable message = %q", message.Data)
	}
}

func TestHostNKeyCannotCrossNodeOrUseJetStream(t *testing.T) {
	region := productionTestRegion(t, "lab", "one")
	hostConfig, hostPublic := productionTestUser(t, region, "host-one", "host", false)
	_, otherPublic := productionTestUser(t, region, "host-two", "host", false)
	serverConfig := region.cfg
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	controller, err := openTestBroker(t, ctx, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	hostConfig.URL = controller.URL()
	host, err := Start(ctx, hostConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	observations, err := controller.Conn().SubscribeSync("ts.orch.v1.lab.agent.*.observation.*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observations.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	allowed := "ts.orch.v1.lab.agent." + hostPublic + ".observation.report"
	if err := host.Conn().Publish(allowed, []byte("own")); err != nil {
		t.Fatal(err)
	}
	if err := host.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	message, err := observations.NextMsg(time.Second)
	if err != nil || string(message.Data) != "own" {
		t.Fatalf("own observation was not delivered: %v %v", message, err)
	}
	forbidden := "ts.orch.v1.lab.agent." + otherPublic + ".observation.report"
	_ = host.Conn().Publish(forbidden, []byte("spoof"))
	_ = host.Conn().FlushTimeout(time.Second)
	if _, err := observations.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("host published another node's observation: %v", err)
	}
	otherInbox, err := host.Conn().SubscribeSync(inboxPrefix("lab", otherPublic) + ".probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherInbox.Unsubscribe() })
	if err := host.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := controller.Conn().Publish(inboxPrefix("lab", otherPublic)+".probe", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := otherInbox.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("host subscribed to another node's replies: %v", err)
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer probeCancel()
	if _, err := host.JetStream().AccountInfo(probeCtx); err == nil {
		t.Fatal("host accessed JetStream account API")
	}
}

func TestOperatorNKeyCanUseClientAPIsButCannotWriteControllerState(t *testing.T) {
	region := productionTestRegion(t, "lab", "one")
	operatorConfig, operatorPublic := productionTestUser(t, region, "operator", "operator", false)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	controller, err := openTestBroker(t, ctx, region.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	for _, bucket := range []string{"TS_DELIVERY_ADMISSIONS", "TS_DELIVERY_OPERATIONS", "TS_HOST_STATE"} {
		store, err := controller.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, Replicas: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PutString(ctx, "probe", "trusted"); err != nil {
			t.Fatal(err)
		}
	}
	objects, err := controller.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "TS_ARTIFACTS", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.JetStream().CreateStream(ctx, jetstream.StreamConfig{Name: "TS_CONTROL_LOG", Subjects: []string{"ts.control.lab.>"}, Replicas: 1, AllowDirect: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.JetStream().Publish(ctx, "ts.control.lab.lease", []byte("test")); err != nil {
		t.Fatal(err)
	}
	operatorConfig.URL = controller.URL()
	operator, err := Start(ctx, operatorConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = operator.Close() })
	for _, bucket := range []string{"TS_DELIVERY_ADMISSIONS", "TS_DELIVERY_OPERATIONS", "TS_HOST_STATE"} {
		store, err := operator.JetStream().KeyValue(ctx, bucket)
		if err != nil {
			t.Fatalf("bind %s: %v", bucket, err)
		}
		entry, err := store.Get(ctx, "probe")
		if err != nil || string(entry.Value()) != "trusted" {
			t.Fatalf("read %s: %v", bucket, err)
		}
		deniedCtx, deniedCancel := context.WithTimeout(ctx, 250*time.Millisecond)
		_, err = store.PutString(deniedCtx, "probe", "0000000000RPYNQGXVXJSC20CX")
		deniedCancel()
		if err == nil {
			t.Fatalf("operator wrote controller-owned %s", bucket)
		}
	}
	clientObjects, err := operator.JetStream().ObjectStore(ctx, "TS_ARTIFACTS")
	if err != nil {
		t.Fatal(err)
	}
	artifactInfo, err := clientObjects.Put(ctx, jetstream.ObjectMeta{Name: "artifact"}, bytes.NewReader([]byte("content")))
	if err != nil {
		t.Fatalf("operator artifact upload: %v", err)
	}
	artifactStream, err := operator.JetStream().Stream(ctx, "OBJ_TS_ARTIFACTS")
	if err != nil {
		t.Fatalf("bind artifact chunk stream: %v", err)
	}
	chunk, err := artifactStream.GetMsg(ctx, 1, jetstream.WithGetMsgSubject("$O.TS_ARTIFACTS.C."+artifactInfo.NUID))
	if err != nil || chunk == nil || string(chunk.Data) != "content" {
		t.Fatalf("operator direct artifact chunk read: %v, chunk=%v", err, chunk)
	}
	if _, err := objects.GetInfo(ctx, "artifact"); err != nil {
		t.Fatal(err)
	}
	readback, err := clientObjects.Get(ctx, "artifact")
	if err != nil {
		t.Fatalf("operator artifact readback: %v", err)
	}
	contents, err := io.ReadAll(readback)
	readback.Close()
	if err != nil || string(contents) != "content" {
		t.Fatalf("operator artifact readback bytes: %q, %v", contents, err)
	}
	log, err := operator.JetStream().Stream(ctx, "TS_CONTROL_LOG")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.GetLastMsgForSubject(ctx, "ts.control.lab.lease"); err != nil {
		t.Fatalf("operator observe lease: %v", err)
	}
	deniedCtx, deniedCancel := context.WithTimeout(ctx, 250*time.Millisecond)
	_, err = operator.JetStream().Publish(deniedCtx, "ts.control.lab.lease", []byte("forged"))
	deniedCancel()
	if err == nil {
		t.Fatal("operator forged an authority lease")
	}
	requests, err := controller.Conn().SubscribeSync("ts.orch.v1.lab.delivery.artifact.admit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requests.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := operator.Conn().Publish("ts.orch.v1.lab.delivery.artifact.admit", []byte("signed")); err != nil {
		t.Fatal(err)
	}
	if _, err := requests.NextMsg(time.Second); err != nil {
		t.Fatalf("operator artifact claim publish: %v", err)
	}
	backupRequests, err := controller.Conn().Subscribe("ts.orch.v1.lab.backup.operation", func(message *nats.Msg) {
		_ = message.Respond([]byte("accepted"))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backupRequests.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	backupReply, err := operator.Conn().RequestWithContext(ctx, "ts.orch.v1.lab.backup.operation", []byte("signed"))
	if err != nil {
		t.Fatalf("operator backup operation request: %v", err)
	}
	if string(backupReply.Data) != "accepted" ||
		!strings.HasPrefix(backupReply.Subject, inboxPrefix("lab", operatorPublic)+".") {
		t.Fatalf("backup operation response did not use the operator's private inbox: subject=%s body=%q",
			backupReply.Subject, backupReply.Data)
	}
}
