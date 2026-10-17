package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNetBirdPublicSourceReplicatedScanCursor(t *testing.T) {
	for _, trailing := range []int{0, 1, 3} {
		t.Run(fmt.Sprintf("trailing_%d", trailing), func(t *testing.T) {
			js, managerJS, denied := newNetBirdSourceR3(t)
			ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
			defer cancel()
			runtime, err := Start(ctx, js, Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 3})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = runtime.Close() })
			var buckets [2]jetstream.KeyValue
			for index, name := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS"} {
				buckets[index], err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: name, History: 4, Replicas: 3, Storage: jetstream.FileStorage})
				if err != nil {
					t.Fatal(err)
				}
				key := []string{"current", "chain"}[index]
				if _, err := buckets[index].Put(ctx, key, []byte("public")); err != nil {
					t.Fatal(err)
				}
				for private := range trailing {
					if _, err := buckets[index].Put(ctx, fmt.Sprintf("private-%d", private), []byte("private-never-delivered")); err != nil {
						t.Fatal(err)
					}
				}
			}
			nonce := entityid.New()
			if err := runtime.OpenNetBirdSourceRead(ctx, nonce); err != nil {
				t.Fatal(err)
			}
			reader, err := ConnectNetBirdSourceRead(ctx, managerJS, nonce)
			if err != nil {
				t.Fatal(err)
			}
			spec, roots, err := reader.Read(ctx)
			if err != nil || spec.Revision != 1 || roots.Revision != 1 || !bytes.Equal(spec.Wire, []byte("public")) || !bytes.Equal(roots.Wire, []byte("public")) {
				t.Fatalf("public-only scan = %+v %+v %v", spec, roots, err)
			}
			if _, err := ConnectNetBirdSourceRead(ctx, managerJS, nonce); err == nil {
				t.Fatal("consumed nonce admitted another reader")
			}
			for _, source := range netBirdPublicSources {
				consumer, err := js.Consumer(ctx, source.stream, source.consumer)
				if err != nil {
					t.Fatal(err)
				}
				info, err := consumer.Info(ctx)
				if err != nil || info.Delivered.Consumer != 1 || info.Delivered.Stream != uint64(trailing+1) || info.AckFloor.Stream != uint64(trailing+1) {
					t.Fatalf("persisted scan cursor = %+v %v", info, err)
				}
				leader := info.Cluster.Leader
				response, err := js.Conn().RequestWithContext(ctx, "$JS.API.CONSUMER.LEADER.STEPDOWN."+source.stream+"."+source.consumer, nil)
				if err != nil {
					t.Fatal(err)
				}
				var result struct {
					Success bool `json:"success"`
				}
				if err := json.Unmarshal(response.Data, &result); err != nil || !result.Success {
					t.Fatalf("consumer leader stepdown = %s %v", response.Data, err)
				}
				for {
					info, err = consumer.Info(ctx)
					if err == nil && info.Cluster != nil && info.Cluster.Leader != "" && info.Cluster.Leader != leader && len(info.Cluster.Replicas) == 2 && info.Cluster.Replicas[0].Current && info.Cluster.Replicas[1].Current {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("replicated cursor leader did not become current: ", ctx.Err())
					case <-time.After(20 * time.Millisecond):
					}
				}
				if info.Delivered.Consumer != 1 || info.Delivered.Stream != uint64(trailing+1) || info.AckFloor.Stream != uint64(trailing+1) {
					t.Fatalf("new leader lost replicated scan cursor: %+v", info)
				}
				for _, subject := range []string{"$JS.API.STREAM.MSG.GET." + source.stream, "$JS.API.DIRECT.GET." + source.stream,
					"$JS.API.CONSUMER.CREATE." + source.stream + "." + source.consumer, "$JS.API.CONSUMER.DELETE." + source.stream + "." + source.consumer,
					"$JS.ACK." + source.stream + "." + source.consumer + ".1.1.1.1.0"} {
					if err := managerJS.Conn().Publish(subject, []byte(`{}`)); err != nil {
						t.Fatal(err)
					}
					if err := managerJS.Conn().FlushWithContext(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case <-denied:
					case <-ctx.Done():
						t.Fatal("manager escalation was not denied: ", subject)
					}
				}
			}
			if _, _, err := reader.Read(ctx); err != nil {
				t.Fatal("leader change replayed or lost the public cursor: ", err)
			}
			switch trailing {
			case 0:
				err = buckets[0].Delete(ctx, "current")
			case 1:
				err = buckets[0].Purge(ctx, "current")
			case 3:
				stream, getErr := js.Stream(ctx, netBirdPublicSources[0].stream)
				if getErr != nil {
					t.Fatal(getErr)
				}
				info, getErr := stream.Info(ctx)
				if getErr != nil {
					t.Fatal(getErr)
				}
				config := info.Config
				config.MaxMsgsPerSubject = 2
				_, err = js.UpdateStream(ctx, config)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := reader.Read(ctx); err == nil {
				t.Fatal("deleted, purged or history-changed source remained authorized")
			}
		})
	}
}
