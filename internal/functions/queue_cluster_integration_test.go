package functions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func functionBrokerCluster(t *testing.T, options *server.Options) []*server.Server {
	t.Helper()
	var brokers []*server.Server
	for index := range 3 {
		options := options.Clone()
		options.ServerName = fmt.Sprintf("function-r3-%d", index)
		options.Host, options.Port = "127.0.0.1", -1
		options.JetStream, options.StoreDir = true, t.TempDir()
		options.Cluster = server.ClusterOpts{Name: "function-r3", Host: "127.0.0.1", Port: -1}
		if index == 0 {
			route, err := url.Parse("nats-route://127.0.0.1:1")
			if err != nil {
				t.Fatal(err)
			}
			options.Routes = []*url.URL{route}
		}
		for _, peer := range brokers {
			route, err := url.Parse("nats-route://" + peer.ClusterAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			options.Routes = append(options.Routes, route)
		}
		broker, err := server.NewServer(options)
		if err != nil {
			t.Fatal(err)
		}
		go broker.Start()
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("function R3 broker did not start")
		}
		brokers = append(brokers, broker)
		t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		ready := false
		for _, broker := range brokers {
			ready = ready || (broker.JetStreamIsLeader() && len(broker.JetStreamClusterPeers()) == 3)
		}
		for _, broker := range brokers {
			ready = ready && broker.JetStreamIsCurrent()
		}
		if ready {
			return brokers
		}
		select {
		case <-ctx.Done():
			t.Fatal("function R3 metadata unavailable: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestQueueRejectsUnreplicatedResources(t *testing.T) {
	nc, js := transportBroker(t)
	worker := transportWorker(t, "echo")
	if err := provisionQueue(t.Context(), nc, worker.Manifest()); err != nil {
		t.Fatal(err)
	}
	scope, err := QueueIdentity(worker.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"queue", "receipts"} {
		t.Run(resource, func(t *testing.T) {
			name := scope.Stream
			if resource == "receipts" {
				name = "KV_" + scope.ReceiptBucket
			}
			stream, err := js.Stream(t.Context(), name)
			if err != nil {
				t.Fatal(err)
			}
			config := stream.CachedInfo().Config
			config.Replicas = 1
			if _, err := js.UpdateStream(t.Context(), config); err != nil {
				t.Fatal(err)
			}
			if resource == "queue" {
				// WorkQueue consumers must match their parent's replication.
				consumer, err := js.Consumer(t.Context(), scope.Stream, "worker")
				if err != nil {
					t.Fatal(err)
				}
				config := consumer.CachedInfo().Config
				config.Replicas = 1
				if _, err := js.UpdateConsumer(t.Context(), scope.Stream, config); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewQueueWorker(t.Context(), nc, worker); !errors.Is(err, ErrScope) {
				t.Fatalf("worker accepted R1 %s: %v", resource, err)
			}
			if err := provisionQueue(t.Context(), nc, worker.Manifest()); err != nil {
				t.Fatal(err)
			}
			if _, err := NewQueueWorker(t.Context(), nc, worker); err != nil {
				t.Fatalf("worker cannot bind repaired R3 resources: %v", err)
			}
		})
	}
}

func TestQueuePendingAndReceiptsSurviveOwningBrokerLoss(t *testing.T) {
	for _, lostResource := range []string{"queue", "receipts"} {
		t.Run(lostResource, func(t *testing.T) {
			brokers := functionBrokerCluster(t, &server.Options{})
			nc, err := nats.Connect(brokers[0].ClientURL())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(nc.Close)
			js, err := jetstream.New(nc)
			if err != nil {
				t.Fatal(err)
			}
			worker := transportWorker(t, "echo")
			if err := provisionQueue(t.Context(), nc, worker.Manifest()); err != nil {
				t.Fatal(err)
			}
			scope, err := QueueIdentity(worker.Manifest())
			if err != nil {
				t.Fatal(err)
			}
			queue, err := NewQueueWorker(t.Context(), nc, worker)
			if err != nil {
				t.Fatal(err)
			}
			receipts, err := js.KeyValue(t.Context(), scope.ReceiptBucket)
			if err != nil {
				t.Fatal(err)
			}
			// Set the window before messages create deduplication timers on followers.
			stream, err := js.Stream(t.Context(), scope.Stream)
			if err != nil {
				t.Fatal(err)
			}
			config := stream.CachedInfo().Config
			config.Duplicates = 100 * time.Millisecond
			if _, err := js.UpdateStream(t.Context(), config); err != nil {
				t.Fatal(err)
			}
			waitTransport(t, func() bool {
				for _, broker := range brokers {
					account, err := broker.JszAccount(&server.JSzOptions{Account: server.DEFAULT_GLOBAL_ACCOUNT, Streams: true, Config: true})
					if err != nil {
						return false
					}
					configured := false
					for _, detail := range account.Streams {
						if detail.Name == scope.Stream {
							configured = detail.Config != nil && detail.Config.Duplicates == config.Duplicates && detail.Config.Replicas == 3 && detail.State.LastSeq == 0
							break
						}
					}
					if !configured {
						return false
					}
				}
				return true
			})
			payload := []byte("completed before owning broker loss")
			stop := runTransportQueue(t, queue)
			publishTransportMessage(t, js, scope.Subject, "completed", payload)
			var before jetstream.KeyValueEntry
			waitTransport(t, func() bool {
				before, err = receipts.Get(t.Context(), "completed")
				info, infoErr := queue.consumer.Info(t.Context())
				return err == nil && infoErr == nil && info.NumAckPending == 0 && info.AckFloor.Consumer == 1
			})
			stop()
			publishTransportMessage(t, js, scope.Subject, "pending", []byte("accepted before owning broker loss"))
			ownerStream := scope.Stream
			if lostResource == "receipts" {
				ownerStream = "KV_" + scope.ReceiptBucket
			}
			var leader string
			waitTransport(t, func() bool {
				for _, name := range []string{scope.Stream, "KV_" + scope.ReceiptBucket} {
					s, err := js.Stream(t.Context(), name)
					if err != nil {
						return false
					}
					info, err := s.Info(t.Context())
					if err != nil || info.Config.Replicas != 3 || info.Cluster == nil || info.Cluster.Leader == "" || len(info.Cluster.Replicas) != 2 {
						return false
					}
					for _, replica := range info.Cluster.Replicas {
						if !replica.Current {
							return false
						}
					}
					if name == ownerStream {
						leader = info.Cluster.Leader
					}
				}
				return true
			})
			var owner *server.Server
			for _, broker := range brokers {
				if broker.Name() == leader {
					owner = broker
				}
			}
			if owner == nil {
				t.Fatalf("unknown %s leader %q", lostResource, leader)
			}
			lossConn, err := nats.Connect(owner.ClientURL(), nats.ReconnectWait(20*time.Millisecond), nats.MaxReconnects(-1))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(lossConn.Close)
			waitTransport(t, func() bool { return len(lossConn.Servers()) == 3 })
			owner.Shutdown()
			owner.WaitForShutdown()
			waitTransport(t, func() bool { return lossConn.IsConnected() && lossConn.ConnectedUrl() != owner.ClientURL() })
			survivingJS, err := jetstream.New(lossConn)
			if err != nil {
				t.Fatal(err)
			}
			waitTransport(t, func() bool {
				queue, err = NewQueueWorker(t.Context(), lossConn, worker)
				return err == nil
			})
			retained, err := survivingJS.KeyValue(t.Context(), scope.ReceiptBucket)
			if err != nil {
				t.Fatal(err)
			}
			after, err := retained.Get(t.Context(), "completed")
			digest := sha256.Sum256(payload)
			if err != nil || after.Revision() != before.Revision() || !bytes.Equal(after.Value(), digest[:]) {
				t.Fatalf("receipt did not survive owning broker loss: %v", err)
			}
			stop = runTransportQueue(t, queue)
			defer stop()
			waitTransport(t, func() bool {
				_, err := retained.Get(t.Context(), "pending")
				return err == nil && worker.Snapshot().Succeeded == 2
			})
			time.Sleep(110 * time.Millisecond)
			msg := nats.NewMsg(scope.Subject)
			msg.Header.Set(nats.MsgIdHdr, "completed")
			msg.Data = payload
			ack, err := survivingJS.PublishMsg(t.Context(), msg)
			if err != nil || ack.Duplicate {
				t.Fatalf("replay was not accepted outside broker deduplication: %+v, %v", ack, err)
			}
			waitTransport(t, func() bool {
				info, err := queue.consumer.Info(t.Context())
				return err == nil && info.AckFloor.Consumer == 3 && info.NumAckPending == 0
			})
			after, err = retained.Get(t.Context(), "completed")
			if err != nil || after.Revision() != before.Revision() || !bytes.Equal(after.Value(), digest[:]) || worker.Snapshot().Succeeded != 2 {
				t.Fatalf("reconnected replay changed receipt or repeated execution: %v", err)
			}
		})
	}
}
