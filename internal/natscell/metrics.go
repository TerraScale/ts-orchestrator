package natscell

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats-server/v2/server"
)

// maxObservedStreams and maxObservedConsumers bound the per-stream and
// per-consumer views; the regional control plane owns a small fixed set of
// streams. A view cut at either bound sets NATSView.Truncated, so a missing
// row is never read as an absent stream or consumer.
const (
	maxObservedStreams   = 128
	maxObservedConsumers = 128
)

// Observe reads embedded broker and JetStream health in process through the
// server monitoring API. It deliberately does not enable the NATS HTTP
// monitor port, which would be another listener on the broker address.
// Callers cache the result: Jsz walks every hosted stream and consumer.
func (r *Runtime) Observe(ctx context.Context) (observability.NATSView, error) {
	if r == nil || r.server == nil {
		return observability.NATSView{}, errors.New("embedded NATS server is not running")
	}
	if err := ctx.Err(); err != nil {
		return observability.NATSView{}, err
	}
	varz, err := r.server.Varz(nil)
	if err != nil {
		return observability.NATSView{}, err
	}
	view := observability.NATSView{
		ServerName: varz.Name, Connections: varz.Connections, Routes: varz.Routes,
		ClusterPeers: r.peerCount(), SlowConsumers: varz.SlowConsumers,
		InMsgs: varz.InMsgs, OutMsgs: varz.OutMsgs, InBytes: varz.InBytes, OutBytes: varz.OutBytes,
	}
	if varz.JetStream.Config != nil {
		view.StoreLimitBytes = varz.JetStream.Config.MaxStore
	}
	jsz, err := r.server.Jsz(&server.JSzOptions{Accounts: true, Streams: true, Consumer: true, Config: true})
	if err != nil {
		return observability.NATSView{}, err
	}
	if jsz.Disabled {
		return observability.NATSView{}, ErrJetStreamDisabled
	}
	view.StoreUsedBytes = jsz.Store
	if jsz.Config.MaxStore > 0 {
		view.StoreLimitBytes = jsz.Config.MaxStore
	}
	if meta := jsz.Meta; meta != nil {
		view.MetaLeader, view.MetaClusterSize = meta.Leader, meta.Size
		view.IsMetaLeader = meta.Leader != "" && meta.Leader == view.ServerName
		for _, peer := range meta.Replicas {
			if peer != nil {
				view.MetaPeers = append(view.MetaPeers, observability.PeerView{Name: peer.Name,
					Current: peer.Current, Offline: peer.Offline, Lag: peer.Lag, Active: peer.Active})
			}
		}
	} else if r.conn != nil {
		// A single-replica cell has no metadata group; it leads itself.
		view.IsMetaLeader, view.MetaLeader, view.MetaClusterSize = true, view.ServerName, 1
	}
	for _, account := range jsz.AccountDetails {
		if account == nil {
			continue
		}
		for _, stream := range account.Streams {
			if len(view.Streams) >= maxObservedStreams {
				view.Truncated = true
				break
			}
			view.Streams = append(view.Streams, streamView(stream))
			for _, consumer := range stream.Consumer {
				if consumer == nil {
					continue
				}
				if len(view.Consumers) >= maxObservedConsumers {
					view.Truncated = true
					break
				}
				view.Consumers = append(view.Consumers, observability.ConsumerView{
					Stream: consumer.Stream, Name: consumer.Name, NumPending: consumer.NumPending,
					NumAckPending: consumer.NumAckPending, NumRedelivered: consumer.NumRedelivered,
					NumWaiting: consumer.NumWaiting})
			}
		}
	}
	slices.SortFunc(view.Streams, func(a, b observability.StreamView) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(view.Consumers, func(a, b observability.ConsumerView) int {
		if order := cmp.Compare(a.Stream, b.Stream); order != 0 {
			return order
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return view, nil
}

func streamView(stream server.StreamDetail) observability.StreamView {
	view := observability.StreamView{Name: stream.Name, Messages: stream.State.Msgs, Bytes: stream.State.Bytes, Replicas: 1}
	configured := stream.Config != nil && stream.Config.Replicas > 0
	if configured {
		view.Replicas = stream.Config.Replicas
	}
	if cluster := stream.Cluster; cluster != nil {
		view.Leader = cluster.Leader
		// Without a configured factor, count peers from the cluster info.
		// It omits the leader from Replicas, but a leaderless group lists
		// every peer, this server included.
		peers := len(cluster.Replicas)
		if cluster.Leader != "" {
			peers++
		}
		if !configured && peers > view.Replicas {
			view.Replicas = peers
		}
		for _, replica := range cluster.Replicas {
			if replica == nil {
				continue
			}
			view.MaxReplicaLag = max(view.MaxReplicaLag, replica.Lag)
			if replica.Offline {
				view.OfflinePeers++
			}
		}
	}
	return view
}
