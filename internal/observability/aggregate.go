package observability

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	// SnapshotLeaf is the observability subject leaf every controller of a
	// cell answers with its MemberSnapshot.
	SnapshotLeaf = "snapshot"
	// DefaultAggregationTimeout bounds one scatter-gather. Members that have
	// not answered by then are reported missing.
	DefaultAggregationTimeout = time.Second

	maxSnapshotRequestBytes = 256
	maxClusterMembers       = 16
	snapshotAnswerTimeout   = 2 * time.Second
)

type snapshotRequest struct {
	Version        int  `json:"version"`
	IncludeMetrics bool `json:"include_metrics,omitzero"`
}

// ServeSnapshots answers cell-wide snapshot requests from source until the
// subscription is closed or ctx ends. Requests reach it only from callers
// holding a publish grant on the cell's controller subjects; replies carry
// read-only telemetry and no signed state.
func ServeSnapshots(ctx context.Context, conn *nats.Conn, cell string, source SnapshotSource) (*nats.Subscription, error) {
	if conn == nil || source == nil {
		return nil, errors.New("snapshot responder requires a connection and a source")
	}
	subject, err := protocol.ObservabilitySubject(cell, SnapshotLeaf)
	if err != nil {
		return nil, err
	}
	subscription, err := conn.Subscribe(subject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) > maxSnapshotRequestBytes {
			return
		}
		var request snapshotRequest
		if err := json.Unmarshal(message.Data, &request); err != nil || request.Version != SnapshotVersion {
			return
		}
		answerCtx, cancel := context.WithTimeout(ctx, snapshotAnswerTimeout)
		defer cancel()
		snapshot, err := source.Snapshot(answerCtx, request.IncludeMetrics)
		if err != nil {
			return
		}
		data, err := json.Marshal(snapshot)
		if err == nil && int64(len(data)) > conn.MaxPayload() {
			// Drop the exposition rather than the whole answer.
			snapshot.Metrics, snapshot.MetricsTruncated = "", true
			data, err = json.Marshal(snapshot)
		}
		if err != nil || int64(len(data)) > conn.MaxPayload() {
			return
		}
		_ = message.Respond(data)
	})
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = subscription.Unsubscribe() })
	return subscription, nil
}

// Aggregator scatter-gathers MemberSnapshot values from every controller of
// one cell. It implements ClusterSource.
type Aggregator struct {
	conn     *nats.Conn
	cell     string
	subject  string
	expected []string
	timeout  time.Duration
}

// NewAggregator binds a cell and its expected member names. With expected
// members known, a gather ends as soon as all of them answer.
func NewAggregator(conn *nats.Conn, cell string, expected []string, timeout time.Duration) (*Aggregator, error) {
	if conn == nil {
		return nil, errors.New("snapshot aggregator requires a connection")
	}
	subject, err := protocol.ObservabilitySubject(cell, SnapshotLeaf)
	if err != nil {
		return nil, err
	}
	if len(expected) > maxClusterMembers {
		return nil, errors.New("snapshot aggregator expects too many members")
	}
	if timeout <= 0 {
		timeout = DefaultAggregationTimeout
	}
	expected = slices.Clone(expected)
	slices.Sort(expected)
	return &Aggregator{conn: conn, cell: cell, subject: subject, expected: slices.Compact(expected), timeout: timeout}, nil
}

// Cluster gathers one snapshot per answering member. A reply for another
// cell, an unknown member when the roster is known, or a duplicate member is
// ignored. Missing members are listed rather than failing the call.
func (aggregator *Aggregator) Cluster(ctx context.Context, includeMetrics bool) (ClusterSnapshot, error) {
	request, err := json.Marshal(snapshotRequest{Version: SnapshotVersion, IncludeMetrics: includeMetrics})
	if err != nil {
		return ClusterSnapshot{}, err
	}
	inbox := aggregator.conn.NewInbox()
	replies := make(chan *nats.Msg, maxClusterMembers*2)
	subscription, err := aggregator.conn.ChanSubscribe(inbox, replies)
	if err != nil {
		return ClusterSnapshot{}, err
	}
	defer subscription.Unsubscribe()
	if err := aggregator.conn.PublishRequest(aggregator.subject, inbox, request); err != nil {
		return ClusterSnapshot{}, err
	}
	timer := time.NewTimer(aggregator.timeout)
	defer timer.Stop()
	members := map[string]MemberSnapshot{}
	cluster := ClusterSnapshot{Cell: aggregator.cell, Expected: aggregator.expected}
gather:
	for len(aggregator.expected) == 0 || len(members) < len(aggregator.expected) {
		select {
		case <-ctx.Done():
			return ClusterSnapshot{}, ctx.Err()
		case <-timer.C:
			break gather
		case message := <-replies:
			var snapshot MemberSnapshot
			if err := json.Unmarshal(message.Data, &snapshot); err != nil || snapshot.Version < 1 ||
				snapshot.Cell != aggregator.cell || snapshot.Member == "" {
				continue
			}
			if len(aggregator.expected) > 0 {
				if _, known := slices.BinarySearch(aggregator.expected, snapshot.Member); !known {
					continue
				}
			}
			if _, duplicate := members[snapshot.Member]; duplicate || len(members) >= maxClusterMembers {
				continue
			}
			members[snapshot.Member] = snapshot
		}
	}
	for _, member := range slices.Sorted(maps.Keys(members)) {
		cluster.Members = append(cluster.Members, members[member])
	}
	for _, member := range aggregator.expected {
		if _, answered := members[member]; !answered {
			cluster.Missing = append(cluster.Missing, member)
		}
	}
	cluster.ObservedAt = time.Now().UTC()
	return cluster, nil
}
