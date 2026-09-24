//go:build ignore

// natsdiag reads only regional JetStream metadata during a Firecracker lab run.
// It never prints the NKey seed or raw control-log payloads.
package main

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	seed := flag.String("seed", "", "private controller NKey seed file")
	operatorSeed := flag.String("operator-seed", "", "private operator NKey seed file")
	urls := flag.String("urls", "", "comma-separated direct controller URLs")
	flag.Parse()
	if *seed == "" || *urls == "" {
		fmt.Fprintln(os.Stderr, "usage: go run natsdiag.go --seed FILE --urls URL,URL,URL")
		os.Exit(2)
	}
	option, err := nats.NkeyOptionFromSeed(*seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load controller identity:", err)
		os.Exit(1)
	}
	var output sync.Mutex
	var workers sync.WaitGroup
	for _, url := range strings.Split(*urls, ",") {
		workers.Go(func() { probe(url, "controller", option, &output) })
	}
	if *operatorSeed != "" {
		operatorOption, err := nats.NkeyOptionFromSeed(*operatorSeed)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load operator identity:", err)
			os.Exit(1)
		}
		workers.Go(func() { probe(*urls, "operator", operatorOption, &output) })
	}
	workers.Wait()
}

func probe(url, role string, identity nats.Option, output *sync.Mutex) {
	result := map[string]any{"requested_url": url, "role": role, "time": time.Now().UTC()}
	defer func() {
		encoded, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encode diagnostic:", err)
			return
		}
		output.Lock()
		fmt.Println(string(encoded))
		output.Unlock()
	}()
	conn, err := nats.Connect(url, identity, nats.Timeout(2*time.Second), nats.NoReconnect())
	if err != nil {
		result["connect_error"] = err.Error()
		return
	}
	defer conn.Close()
	result["connected_url"] = conn.ConnectedUrl()
	result["servers"] = conn.Servers()
	result["discovered_servers"] = conn.DiscoveredServers()
	js, err := jetstream.New(conn)
	if err != nil {
		result["jetstream_error"] = err.Error()
		return
	}
	read := func(name string, operation func(context.Context) (any, error)) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		value, err := operation(ctx)
		if err != nil {
			result[name+"_error"] = err.Error()
		} else {
			result[name] = value
		}
	}
	read("account", func(ctx context.Context) (any, error) {
		info, err := js.AccountInfo(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"api": info.API, "tiers": info.Tiers}, nil
	})
	for _, name := range []string{authority.ControlStreamName, delivery.IntentStream, "KV_TS_HOST_STATE"} {
		read("stream_"+name, func(ctx context.Context) (any, error) {
			stream, err := js.Stream(ctx, name)
			if err != nil {
				return nil, err
			}
			info, err := stream.Info(ctx)
			if err != nil {
				return nil, err
			}
			return map[string]any{"messages": info.State.Msgs, "first_seq": info.State.FirstSeq,
				"last_seq": info.State.LastSeq, "cluster": info.Cluster}, nil
		})
	}
	read("delivery_consumer", func(ctx context.Context) (any, error) {
		consumer, err := js.Consumer(ctx, delivery.IntentStream, delivery.IntentConsumer)
		if err != nil {
			return nil, err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"delivered": info.Delivered, "ack_floor": info.AckFloor,
			"ack_pending": info.NumAckPending, "redelivered": info.NumRedelivered,
			"waiting": info.NumWaiting, "pending": info.NumPending, "cluster": info.Cluster}, nil
	})
	read("authority", func(ctx context.Context) (any, error) {
		snapshot, err := authority.Observe(ctx, js, "lab")
		if err != nil {
			return nil, err
		}
		return map[string]any{"candidate": snapshot.CandidateID, "epoch": snapshot.Epoch,
			"revision": snapshot.Revision, "expires_at": snapshot.ExpiresAt,
			"ready": snapshot.Ready, "reason": snapshot.Reason}, nil
	})
}
