package natscell

import (
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const (
	closeDrainTimeout   = 5 * time.Second
	closeHandoffTimeout = 5 * time.Second
	// Lame-duck mode closes any remaining clients over this window after a
	// short grace period. Both stay far below the unit's TimeoutStopSec=60s.
	lameDuckDuration    = 3 * time.Second
	lameDuckGracePeriod = 500 * time.Millisecond
)

// drainConnection lets in-flight publishes and acknowledgements finish.
// nats.go drains asynchronously, so an immediate Close would cancel the drain.
func drainConnection(conn *nats.Conn, timeout time.Duration) {
	if conn.IsClosed() {
		return
	}
	if err := conn.Drain(); err == nil {
		deadline := time.Now().Add(timeout)
		for !conn.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	conn.Close()
}

// stopServer hands off leadership before the embedded server stops. A broker
// that already died skips straight to Shutdown, which is idempotent.
func (r *Runtime) stopServer() {
	if r.server.Running() && r.server.JetStreamIsClustered() {
		r.handOffLeadership(closeHandoffTimeout)
		// Lame-duck mode transfers every remaining Raft leadership, including
		// the metadata leader, and waits for the transfer before stopping
		// JetStream. NATS skips it when the server has no client listener
		// (production DontListen); Shutdown below still steps every Raft
		// leader down first, only without waiting for the transfer.
		r.server.LameDuckShutdown()
	}
	r.server.Shutdown()
	r.server.WaitForShutdown()
}

// handOffLeadership steps down every replicated stream and consumer Raft
// group this broker leads so a peer takes over now rather than after an
// election timeout. It waits only while a group still names this broker as
// leader, and returns immediately when this broker leads nothing.
func (r *Runtime) handOffLeadership(timeout time.Duration) {
	led := r.ledGroups()
	if len(led) == 0 {
		return
	}
	for _, group := range led {
		if group.consumer == "" {
			_ = r.server.JetStreamStepdownStream(group.account, group.stream)
		} else {
			_ = r.server.JetStreamStepdownConsumer(group.account, group.stream, group.consumer)
		}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) && len(r.ledGroups()) != 0 {
		time.Sleep(50 * time.Millisecond)
	}
}

type ledGroup struct{ account, stream, consumer string }

// ledGroups lists groups led by this broker that have a current, online
// follower. Other groups cannot hand off and are left to Shutdown.
func (r *Runtime) ledGroups() []ledGroup {
	info, err := r.server.Jsz(&server.JSzOptions{Accounts: true, Streams: true, Consumer: true})
	if err != nil || info == nil {
		return nil
	}
	name := r.server.Name()
	var led []ledGroup
	for _, account := range info.AccountDetails {
		if account == nil {
			continue
		}
		for _, stream := range account.Streams {
			if stream.Cluster != nil && stream.Cluster.Leader == name && hasCurrentPeer(stream.Cluster.Replicas) {
				led = append(led, ledGroup{account: account.Id, stream: stream.Name})
			}
			for _, consumer := range stream.Consumer {
				if consumer != nil && consumer.Cluster != nil && consumer.Cluster.Leader == name &&
					hasCurrentPeer(consumer.Cluster.Replicas) {
					led = append(led, ledGroup{account: account.Id, stream: stream.Name, consumer: consumer.Name})
				}
			}
		}
	}
	return led
}

func hasCurrentPeer(peers []*server.PeerInfo) bool {
	for _, peer := range peers {
		if peer != nil && peer.Current && !peer.Offline {
			return true
		}
	}
	return false
}
