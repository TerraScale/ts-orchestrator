package artifact_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestReadVerifiedObjectStoreToFileIntegration(t *testing.T) {
	for _, scenario := range []string{
		"interleaved chunks", "zero-byte object", "missing chunk", "oversize chunk",
		"signed digest mismatch", "object digest mismatch", "extra chunk", "closed destination",
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			go srv.Start()
			t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
			if !srv.ReadyForConnections(5 * time.Second) {
				t.Fatal("NATS did not start")
			}
			conn, err := nats.Connect(srv.ClientURL())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(conn.Close)
			js, err := jetstream.New(conn)
			if err != nil {
				t.Fatal(err)
			}
			const bucket = "ARTIFACTS"
			const name = "pinned"
			store, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: bucket, Storage: jetstream.FileStorage})
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("firstmiddlelast")
			sum := sha256.Sum256(body)
			digest := hex.EncodeToString(sum[:])
			info, err := store.Put(ctx, jetstream.ObjectMeta{Name: name, Opts: &jetstream.ObjectMetaOptions{ChunkSize: 5}}, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			stream, err := js.Stream(ctx, "OBJ_"+bucket)
			if err != nil {
				t.Fatal(err)
			}
			subject := "$O." + bucket + ".C." + info.NUID
			first, err := stream.GetMsg(ctx, 1, jetstream.WithGetMsgSubject(subject))
			if err != nil {
				t.Fatal(err)
			}
			wantError := artifact.ErrInvalid
			switch scenario {
			case "interleaved chunks":
				var chunks [][]byte
				for sequence := uint64(1); ; {
					message, err := stream.GetMsg(ctx, sequence, jetstream.WithGetMsgSubject(subject))
					if errors.Is(err, jetstream.ErrMsgNotFound) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					chunks = append(chunks, message.Data)
					if err := stream.DeleteMsg(ctx, message.Sequence); err != nil {
						t.Fatal(err)
					}
					sequence = message.Sequence + 1
				}
				for _, chunk := range chunks {
					if _, err := js.Publish(ctx, subject, chunk); err != nil {
						t.Fatal(err)
					}
					if _, err := store.PutBytes(ctx, "unrelated", []byte("other object")); err != nil {
						t.Fatal(err)
					}
				}
				wantError = nil
			case "zero-byte object":
				if _, err := store.PutBytes(ctx, name, nil); err != nil {
					t.Fatal(err)
				}
			case "missing chunk":
				if err := stream.DeleteMsg(ctx, first.Sequence); err != nil {
					t.Fatal(err)
				}
				wantError = jetstream.ErrObjectNotFound
			case "oversize chunk":
				if _, err := js.Publish(ctx, subject, bytes.Repeat([]byte("x"), len(body)+1)); err != nil {
					t.Fatal(err)
				}
				if err := stream.DeleteMsg(ctx, first.Sequence); err != nil {
					t.Fatal(err)
				}
			case "signed digest mismatch":
				digest = strings.Repeat("0", 64)
			case "object digest mismatch":
				legacy, err := conn.JetStream()
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := legacy.GetLastMsg("OBJ_"+bucket, "$O."+bucket+".M.>", nats.Context(ctx))
				if err != nil {
					t.Fatal(err)
				}
				info.Digest = "SHA-256=bad"
				data, err := json.Marshal(info)
				if err != nil {
					t.Fatal(err)
				}
				message := nats.NewMsg(metadata.Subject)
				message.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
				message.Data = data
				if _, err := js.PublishMsg(ctx, message); err != nil {
					t.Fatal(err)
				}
			case "extra chunk":
				if _, err := js.Publish(ctx, subject, []byte("extra")); err != nil {
					t.Fatal(err)
				}
			case "closed destination":
				wantError = os.ErrClosed
			}
			path := filepath.Join(t.TempDir(), "artifact")
			output, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = output.Close() })
			if scenario == "closed destination" {
				if err := output.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = artifact.ReadVerified(ctx, js, store, bucket, name, digest, int64(len(body)), 100, output)
			if !errors.Is(err, wantError) {
				t.Fatalf("read stored artifact: %v, want %v", err, wantError)
			}
			if err == nil {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatalf("artifact on disk = %q, error %v; want %q", actual, err, body)
				}
			}
		})
	}
}
