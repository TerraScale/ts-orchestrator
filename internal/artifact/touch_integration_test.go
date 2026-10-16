package artifact_test

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// A deletion is a compare-and-set on the metadata it read: a touch since
// refuses it, and a touch after it finds the object gone. A deletion purges
// the object's chunks.
func TestTouchAndDeleteIfUnchangedIntegration(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := conn.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	store, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "ARTIFACTS"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := store.PutBytes(t.Context(), "object", []byte("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	subject := "$O.ARTIFACTS.M." + base64.URLEncoding.EncodeToString([]byte("object"))
	read := func() *nats.RawStreamMsg {
		t.Helper()
		meta, err := legacy.GetLastMsg("OBJ_ARTIFACTS", subject)
		if err != nil {
			t.Fatal(err)
		}
		return meta
	}
	chosen := read()
	if err := artifact.Touch(t.Context(), legacy, "ARTIFACTS", "object"); err != nil {
		t.Fatal(err)
	}
	if err := artifact.DeleteIfUnchanged(t.Context(), legacy, "ARTIFACTS", chosen); !errors.Is(err, artifact.ErrChanged) {
		t.Fatalf("delete with metadata older than a touch = %v, want artifact.ErrChanged", err)
	}
	if err := artifact.DeleteIfUnchanged(t.Context(), legacy, "ARTIFACTS", read()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetInfo(t.Context(), "object"); !errors.Is(err, jetstream.ErrObjectNotFound) {
		t.Fatalf("object after deletion: %v", err)
	}
	if err := artifact.Touch(t.Context(), legacy, "ARTIFACTS", "object"); !errors.Is(err, jetstream.ErrObjectNotFound) {
		t.Fatalf("touch after deletion = %v, want ErrObjectNotFound", err)
	}
	stream, err := js.Stream(t.Context(), "OBJ_ARTIFACTS")
	if err != nil {
		t.Fatal(err)
	}
	state, err := stream.Info(t.Context(), jetstream.WithSubjectFilter("$O.ARTIFACTS.C."+info.NUID))
	if err != nil || len(state.State.Subjects) != 0 {
		t.Fatalf("chunks after deletion: %v, %v", state.State.Subjects, err)
	}
}
