package observability

import (
	"io"
	"slices"
)

// maxLabeledDatabases bounds per-database series. Larger fleets still appear
// in the JSON view; the stage totals keep their aggregate counts.
const maxLabeledDatabases = 64

// WriteAuthorityMetrics renders the local authority lease observation.
func WriteAuthorityMetrics(w io.Writer, view AuthorityView) {
	WriteGauge(w, MetricPrefix+"authority_leader", Bool(view.Leader))
	WriteGauge(w, MetricPrefix+"authority_ready", Bool(view.Ready))
	WriteGauge(w, MetricPrefix+"authority_can_mutate", Bool(view.CanMutate))
	WriteGauge(w, MetricPrefix+"authority_epoch", float64(view.Epoch))
	WriteGauge(w, MetricPrefix+"authority_revision", float64(view.Revision))
	if !view.ExpiresAt.IsZero() {
		WriteGauge(w, MetricPrefix+"authority_lease_expiry_timestamp_seconds", float64(view.ExpiresAt.Unix()))
	}
}

// WriteNATSMetrics renders embedded broker and JetStream health.
func WriteNATSMetrics(w io.Writer, view NATSView) {
	WriteGauge(w, MetricPrefix+"nats_connections", float64(view.Connections))
	WriteGauge(w, MetricPrefix+"nats_routes", float64(view.Routes))
	WriteGauge(w, MetricPrefix+"nats_cluster_peers", float64(view.ClusterPeers))
	WriteCounter(w, MetricPrefix+"nats_slow_consumers_total", float64(view.SlowConsumers))
	WriteCounter(w, MetricPrefix+"nats_in_msgs_total", float64(view.InMsgs))
	WriteCounter(w, MetricPrefix+"nats_out_msgs_total", float64(view.OutMsgs))
	WriteCounter(w, MetricPrefix+"nats_in_bytes_total", float64(view.InBytes))
	WriteCounter(w, MetricPrefix+"nats_out_bytes_total", float64(view.OutBytes))
	WriteGauge(w, MetricPrefix+"js_meta_leader", Bool(view.IsMetaLeader))
	WriteGauge(w, MetricPrefix+"js_meta_cluster_size", float64(view.MetaClusterSize))
	WriteGauge(w, MetricPrefix+"nats_view_truncated", Bool(view.Truncated))
	WriteGauge(w, Series(MetricPrefix+"nats_route_rtts_truncated", "server", view.ServerName), Bool(view.RouteRTTsTruncated))
	for _, route := range view.RouteRTTs {
		labels := []string{"server", view.ServerName, "peer", route.RemoteName}
		WriteGauge(w, Series(MetricPrefix+"nats_route_connections", labels...), float64(route.Connections))
		WriteGauge(w, Series(MetricPrefix+"nats_route_measured_connections", labels...), float64(route.MeasuredConnections))
		if route.RTTSeconds != nil {
			WriteGauge(w, Series(MetricPrefix+"nats_route_rtt_seconds", labels...), *route.RTTSeconds)
		}
	}
	offline := 0
	for _, peer := range view.MetaPeers {
		if peer.Offline {
			offline++
		}
		WriteGauge(w, Series(MetricPrefix+"js_meta_peer_lag", "peer", peer.Name), float64(peer.Lag))
	}
	WriteGauge(w, MetricPrefix+"js_meta_peers_offline", float64(offline))
	WriteGauge(w, MetricPrefix+"js_store_used_bytes", float64(view.StoreUsedBytes))
	WriteGauge(w, MetricPrefix+"js_store_limit_bytes", float64(view.StoreLimitBytes))
	for _, stream := range view.Streams {
		WriteGauge(w, Series(MetricPrefix+"js_stream_messages", "stream", stream.Name), float64(stream.Messages))
		WriteGauge(w, Series(MetricPrefix+"js_stream_bytes", "stream", stream.Name), float64(stream.Bytes))
		WriteGauge(w, Series(MetricPrefix+"js_stream_replicas", "stream", stream.Name), float64(stream.Replicas))
		WriteGauge(w, Series(MetricPrefix+"js_stream_replica_lag_max", "stream", stream.Name), float64(stream.MaxReplicaLag))
		WriteGauge(w, Series(MetricPrefix+"js_stream_offline_peers", "stream", stream.Name), float64(stream.OfflinePeers))
		WriteGauge(w, Series(MetricPrefix+"js_stream_leader_local", "stream", stream.Name),
			Bool(stream.Leader != "" && stream.Leader == view.ServerName))
	}
	for _, consumer := range view.Consumers {
		WriteGauge(w, Series(MetricPrefix+"js_consumer_num_pending", "stream", consumer.Stream, "consumer", consumer.Name),
			float64(consumer.NumPending))
		WriteGauge(w, Series(MetricPrefix+"js_consumer_num_ack_pending", "stream", consumer.Stream, "consumer", consumer.Name),
			float64(consumer.NumAckPending))
		WriteGauge(w, Series(MetricPrefix+"js_consumer_num_redelivered", "stream", consumer.Stream, "consumer", consumer.Name),
			float64(consumer.NumRedelivered))
	}
}

// WritePlacementMetrics renders TerraBase member stages and rollout progress.
func WritePlacementMetrics(w io.Writer, view PlacementView) {
	stages := make([]string, 0, len(view.StageCounts))
	for stage := range view.StageCounts {
		stages = append(stages, stage)
	}
	slices.Sort(stages)
	for _, stage := range stages {
		WriteGauge(w, Series(MetricPrefix+"terrabase_members", "stage", stage), float64(view.StageCounts[stage]))
	}
	WriteGauge(w, MetricPrefix+"terrabase_partitions", float64(len(view.Databases)))
	// The partition count and per-database series are bounded; say so on
	// /metrics rather than only in the JSON snapshot.
	WriteGauge(w, MetricPrefix+"terrabase_view_truncated",
		Bool(view.Truncated || len(view.Databases) > maxLabeledDatabases))
	for index, database := range view.Databases {
		if index >= maxLabeledDatabases {
			break
		}
		labels := []string{"database", database.DatabaseID, "partition", database.PartitionID}
		WriteGauge(w, Series(MetricPrefix+"terrabase_replicas", slices.Concat(labels, []string{"state", "desired"})...),
			float64(database.DesiredSeats))
		WriteGauge(w, Series(MetricPrefix+"terrabase_replicas", slices.Concat(labels, []string{"state", "serving"})...),
			float64(database.Serving))
		WriteGauge(w, Series(MetricPrefix+"terrabase_generation", labels...), float64(database.Generation))
		if rollout := database.Rollout; rollout != nil {
			WriteGauge(w, Series(MetricPrefix+"rollout_progress_ratio", labels...), rollout.Progress())
			WriteGauge(w, Series(MetricPrefix+"rollout_seats_completed", labels...), float64(rollout.Completed))
		}
	}
}
