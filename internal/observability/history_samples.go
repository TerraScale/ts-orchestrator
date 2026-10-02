package observability

import (
	"context"
	"strconv"
	"sync"
)

// History metric names sampled from cluster snapshots. Charts and insight
// rules address series by these names and the labels noted beside them.
const (
	HistMembersExpected  = "cluster_members_expected"
	HistMembersAnswering = "cluster_members_answering"
	HistMembersReady     = "cluster_members_ready"
	HistMemberUp         = "member_up"    // member, role
	HistMemberReady      = "member_ready" // member
	HistAuthorityEpoch   = "authority_epoch"
	HistAuthorityLeader  = "authority_leader_present"
	HistCPUUtilization   = "cpu_utilization" // member; 0..1
	HistLoad1            = "load1"           // member
	HistMemoryUsed       = "memory_used_bytes"
	HistMemoryTotal      = "memory_total_bytes"
	HistMemoryRatio      = "memory_used_ratio"
	HistFSUsed           = "filesystem_used_bytes" // member, role
	HistFSSize           = "filesystem_size_bytes" // member, role
	HistFSRatio          = "filesystem_used_ratio" // member, role
	HistNATSConnections  = "nats_connections"      // member
	HistNATSRoutes       = "nats_routes"
	HistNATSInMsgs       = "nats_in_msgs_total" // counter
	HistNATSOutMsgs      = "nats_out_msgs_total"
	HistNATSInBytes      = "nats_in_bytes_total"
	HistNATSOutBytes     = "nats_out_bytes_total"
	HistNATSSlow         = "nats_slow_consumers"
	HistJSStoreUsed      = "jetstream_store_used_bytes"
	HistJSStoreLimit     = "jetstream_store_limit_bytes"
	HistStreamMessages   = "jetstream_stream_messages"    // stream
	HistStreamBytes      = "jetstream_stream_bytes"       // stream
	HistStreamLag        = "jetstream_stream_replica_lag" // stream
	HistConsumerPending  = "jetstream_consumer_pending"   // stream, consumer
	HistConsumerAck      = "jetstream_consumer_ack_pending"
	HistOCICalls         = "oci_calls_total" // operation; counter summed over members
	HistOCIErrors        = "oci_errors_total"
	HistOCIThrottled     = "oci_throttled_total"
	HistOCISeconds       = "oci_seconds_total"
	HistDatabases        = "terrabase_databases"
	HistSeatsDesired     = "terrabase_seats_desired"
	HistSeatsServing     = "terrabase_seats_serving"
	HistStageMembers     = "terrabase_stage_members" // stage
	HistRolloutProgress  = "terrabase_rollout_progress"
	HistDeliveryAcked    = "delivery_acknowledged_total" // member; counter
	HistDeliveryDeferred = "delivery_deferred_total"
)

// SnapshotSampler turns cluster snapshots into history samples. It keeps
// the previous CPU counters per member to report utilization.
type SnapshotSampler struct {
	mu       sync.Mutex
	previous map[string]CPUSeconds
}

// Samples derives every history series from one cluster snapshot.
func (sampler *SnapshotSampler) Samples(cluster ClusterSnapshot) []Sample {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	if sampler.previous == nil {
		sampler.previous = map[string]CPUSeconds{}
	}
	var samples []Sample
	gauge := func(metric string, value float64, pairs ...string) {
		samples = append(samples, Sample{Metric: metric, Labels: L(pairs...), Value: value})
	}
	counter := func(metric string, value float64, pairs ...string) {
		samples = append(samples, Sample{Metric: metric, Labels: L(pairs...), Value: value, Counter: true})
	}
	expected := len(cluster.Expected)
	if expected == 0 {
		expected = len(cluster.Members) + len(cluster.Missing)
	}
	gauge(HistMembersExpected, float64(expected))
	gauge(HistMembersAnswering, float64(len(cluster.Members)))
	ready := 0
	leader := false
	var epoch uint64
	streams := map[string]StreamView{}
	consumers := map[[2]string]ConsumerView{}
	type ociTotals struct{ calls, errors, throttled, seconds float64 }
	oci := map[string]*ociTotals{}
	var placement *PlacementView
	for _, member := range cluster.Members {
		name := member.Member
		gauge(HistMemberUp, 1, "member", name, "role", member.Role)
		gauge(HistMemberReady, Bool(member.Ready), "member", name)
		if member.Ready {
			ready++
		}
		if member.Authority != nil {
			epoch = max(epoch, member.Authority.Epoch)
			leader = leader || member.Authority.Leader
		}
		if system := member.System; system != nil {
			if previous, ok := sampler.previous[name]; ok {
				busy := system.CPUSeconds.Busy() - previous.Busy()
				total := busy + system.CPUSeconds.Idle + system.CPUSeconds.IOWait - previous.Idle - previous.IOWait
				if total > 0 && busy >= 0 {
					gauge(HistCPUUtilization, min(busy/total, 1), "member", name)
				}
			}
			sampler.previous[name] = system.CPUSeconds
			gauge(HistLoad1, system.Load1, "member", name)
			if system.MemTotalBytes > 0 {
				used := float64(system.MemTotalBytes - min(system.MemAvailBytes, system.MemTotalBytes))
				gauge(HistMemoryUsed, used, "member", name)
				gauge(HistMemoryTotal, float64(system.MemTotalBytes), "member", name)
				gauge(HistMemoryRatio, used/float64(system.MemTotalBytes), "member", name)
			}
			for _, filesystem := range system.Filesystems {
				if filesystem.SizeBytes == 0 {
					continue
				}
				used := float64(filesystem.SizeBytes - min(filesystem.AvailBytes, filesystem.SizeBytes))
				gauge(HistFSUsed, used, "member", name, "role", filesystem.Role)
				gauge(HistFSSize, float64(filesystem.SizeBytes), "member", name, "role", filesystem.Role)
				gauge(HistFSRatio, used/float64(filesystem.SizeBytes), "member", name, "role", filesystem.Role)
			}
		}
		if nats := member.NATS; nats != nil {
			gauge(HistNATSConnections, float64(nats.Connections), "member", name)
			gauge(HistNATSRoutes, float64(nats.Routes), "member", name)
			counter(HistNATSInMsgs, float64(nats.InMsgs), "member", name)
			counter(HistNATSOutMsgs, float64(nats.OutMsgs), "member", name)
			counter(HistNATSInBytes, float64(nats.InBytes), "member", name)
			counter(HistNATSOutBytes, float64(nats.OutBytes), "member", name)
			gauge(HistNATSSlow, float64(nats.SlowConsumers), "member", name)
			gauge(HistJSStoreUsed, float64(nats.StoreUsedBytes), "member", name)
			if nats.StoreLimitBytes > 0 {
				gauge(HistJSStoreLimit, float64(nats.StoreLimitBytes), "member", name)
			}
			for _, stream := range nats.Streams {
				// Prefer the leader's report; any replica's is a fallback.
				if existing, ok := streams[stream.Name]; !ok || stream.Leader == nats.ServerName && existing.Leader != nats.ServerName {
					streams[stream.Name] = stream
				}
			}
			for _, consumer := range nats.Consumers {
				key := [2]string{consumer.Stream, consumer.Name}
				if existing, ok := consumers[key]; !ok || consumer.NumPending > existing.NumPending {
					consumers[key] = consumer
				}
			}
		}
		if view := member.OCI; view != nil {
			for _, operation := range view.Operations {
				key := operation.Service + "." + operation.Operation
				totals := oci[key]
				if totals == nil {
					totals = &ociTotals{}
					oci[key] = totals
				}
				totals.calls += float64(operation.Calls)
				totals.errors += float64(operation.Errors)
				totals.throttled += float64(operation.Throttled)
				totals.seconds += operation.TotalSeconds
			}
		}
		if member.Placement != nil && (placement == nil || len(member.Placement.Databases) > len(placement.Databases)) {
			placement = member.Placement
		}
		if delivery := member.Delivery; delivery != nil {
			counter(HistDeliveryAcked, float64(delivery.Acknowledged), "member", name)
			counter(HistDeliveryDeferred, float64(delivery.Deferred), "member", name)
		}
	}
	gauge(HistMembersReady, float64(ready))
	if epoch > 0 || leader {
		gauge(HistAuthorityEpoch, float64(epoch))
		gauge(HistAuthorityLeader, Bool(leader))
	}
	for name, stream := range streams {
		gauge(HistStreamMessages, float64(stream.Messages), "stream", name)
		gauge(HistStreamBytes, float64(stream.Bytes), "stream", name)
		gauge(HistStreamLag, float64(stream.MaxReplicaLag), "stream", name)
	}
	for key, consumer := range consumers {
		gauge(HistConsumerPending, float64(consumer.NumPending), "stream", key[0], "consumer", key[1])
		gauge(HistConsumerAck, float64(consumer.NumAckPending), "stream", key[0], "consumer", key[1])
	}
	for operation, totals := range oci {
		counter(HistOCICalls, totals.calls, "operation", operation)
		counter(HistOCIErrors, totals.errors, "operation", operation)
		counter(HistOCIThrottled, totals.throttled, "operation", operation)
		counter(HistOCISeconds, totals.seconds, "operation", operation)
	}
	if placement != nil {
		gauge(HistDatabases, float64(len(placement.Databases)))
		desired, serving := 0, 0
		for _, database := range placement.Databases {
			desired += database.DesiredSeats
			serving += database.Serving
			if rollout := database.Rollout; rollout != nil {
				gauge(HistRolloutProgress, rollout.Progress(), "operation", rollout.OperationID)
			}
		}
		gauge(HistSeatsDesired, float64(desired))
		gauge(HistSeatsServing, float64(serving))
		for stage, count := range placement.StageCounts {
			gauge(HistStageMembers, float64(count), "stage", stage)
		}
	}
	return samples
}

// ClusterCollect returns a HistorySampler.Collect function over a cluster
// source, falling back to this member's snapshot when the cell-wide view is
// unavailable or not configured.
func ClusterCollect(cluster ClusterSource, local SnapshotSource) func(context.Context) []Sample {
	sampler := &SnapshotSampler{}
	return func(ctx context.Context) []Sample {
		if cluster != nil {
			if snapshot, err := cluster.Cluster(ctx, false); err == nil {
				return sampler.Samples(snapshot)
			}
		}
		if local == nil {
			return nil
		}
		snapshot, err := local.Snapshot(ctx, false)
		if err != nil {
			return nil
		}
		return sampler.Samples(ClusterSnapshot{Cell: snapshot.Cell, ObservedAt: snapshot.ObservedAt,
			Members: []MemberSnapshot{snapshot}})
	}
}

// FormatFloat renders a value compactly for evidence text.
func FormatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', 4, 64)
}
