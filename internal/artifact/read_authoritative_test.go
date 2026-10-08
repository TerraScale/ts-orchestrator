package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestReadVerifiedAuthoritativeRequiresOnlyLeaderReadGrant(t *testing.T) {
	const bucket = "ARTIFACTS"
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: t.TempDir(), Users: []*server.User{
			{Username: "admin", Password: "admin-secret"},
			{Username: "reader", Password: "reader-secret", Permissions: &server.Permissions{
				Publish:   &server.SubjectPermission{Allow: []string{"$JS.API.STREAM.MSG.GET.OBJ_" + bucket}},
				Subscribe: &server.SubjectPermission{Allow: []string{"_INBOX.>"}},
			}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	admin, err := nats.Connect(srv.ClientURL(), nats.UserInfo("admin", "admin-secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	adminJS, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	store, err := adminJS.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: bucket})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutBytes(t.Context(), "unrelated", []byte("skip these chunk and metadata sequences")); err != nil {
		t.Fatal(err)
	}
	body := []byte("multiple pinned chunks")
	digest := sha256.Sum256(body)
	const name = "pinned"
	info, err := store.Put(t.Context(), jetstream.ObjectMeta{Name: name, Opts: &jetstream.ObjectMetaOptions{ChunkSize: 3}}, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := nats.Connect(srv.ClientURL(), nats.UserInfo("reader", "reader-secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	readerJS, err := jetstream.New(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := ReadVerifiedAuthoritative(ctx, readerJS, info, bucket, name, hex.EncodeToString(digest[:]),
		int64(len(body)), 100, &output); err != nil || !bytes.Equal(output.Bytes(), body) {
		t.Fatalf("leader-only verification: bytes=%q error=%v", output.Bytes(), err)
	}
	invalid := *info
	invalid.Bucket = "UNRELATED"
	if err := ReadVerifiedAuthoritative(ctx, readerJS, &invalid, bucket, name, hex.EncodeToString(digest[:]),
		int64(len(body)), 100, &bytes.Buffer{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid captured metadata was accepted: %v", err)
	}
	canceled, cancelRead := context.WithCancel(t.Context())
	cancelRead()
	if err := ReadVerifiedAuthoritative(canceled, readerJS, info, bucket, name, hex.EncodeToString(digest[:]),
		int64(len(body)), 100, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled leader verification: %v", err)
	}
}
