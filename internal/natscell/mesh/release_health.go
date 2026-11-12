package mesh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
)

func (n *Node) ReleaseHealth(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if status := n.server.Healthz(&server.HealthzOptions{}); status.StatusCode != http.StatusOK {
		return fmt.Errorf("jetstream: %s", status.Error)
	}
	if n.fabric == nil {
		return errors.New("jetstream: fabric not started")
	}
	js, err := jetstream.New(n.fabric)
	if err != nil {
		return err
	}
	it := js.ListStreams(ctx)
	for stream := range it.Info() {
		if stream.Cluster == nil || stream.Cluster.Leader == "" {
			return fmt.Errorf("stream %s: no leader", stream.Config.Name)
		}
		if 1+len(stream.Cluster.Replicas) != stream.Config.Replicas {
			return fmt.Errorf("stream %s: got %d replicas, want %d", stream.Config.Name, 1+len(stream.Cluster.Replicas), stream.Config.Replicas)
		}
		for _, replica := range stream.Cluster.Replicas {
			if !replica.Current || replica.Offline {
				return fmt.Errorf("stream %s: replica %s not current", stream.Config.Name, replica.Name)
			}
		}
	}
	return it.Err()
}
