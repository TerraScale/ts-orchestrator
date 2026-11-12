package mesh

import (
	"context"
	"encoding/json"
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
	for offset := 0; ; {
		payload, err := json.Marshal(struct {
			Offset int `json:"offset"`
		}{Offset: offset})
		if err != nil {
			return err
		}
		message, err := n.fabric.RequestWithContext(ctx, "$JS.API.STREAM.LIST", payload)
		if err != nil {
			return err
		}
		var page struct {
			Total   int                     `json:"total"`
			Streams []*jetstream.StreamInfo `json:"streams"`
			Missing []string                `json:"missing"`
			Error   *jetstream.APIError     `json:"error"`
		}
		if err := json.Unmarshal(message.Data, &page); err != nil {
			return err
		}
		if page.Error != nil {
			return page.Error
		}
		if len(page.Missing) != 0 {
			return fmt.Errorf("stream %s: no leader answered", page.Missing[0])
		}
		for _, stream := range page.Streams {
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
		offset += len(page.Streams)
		if offset >= page.Total {
			return nil
		}
		if len(page.Streams) == 0 {
			return errors.New("jetstream: empty stream list page")
		}
	}
}
