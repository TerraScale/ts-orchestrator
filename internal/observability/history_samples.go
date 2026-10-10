package observability

import (
	"context"
	"maps"
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
	// Per-partition seats, for the TerraBase detail pages: database, partition.
	HistPartitionDesired = "terrabase_partition_seats_desired"
	HistPartitionServing = "terrabase_partition_seats_serving"
	HistDeliveryAcked    = "delivery_acknowledged_total" // member; counter
	HistDeliveryDeferred = "delivery_deferred_total"
)

// Directed route measurements and coverage use member, server, peer labels.
const (
	HistNATSRouteRTT                 = "nats_route_rtt_seconds"
	HistNATSRouteConnections         = "nats_route_connections"
	HistNATSRouteMeasuredConnections = "nats_route_measured_connections"
	HistNATSRouteRTTsTruncated       = "nats_route_rtts_truncated" // member, server
)

// History metric names the controller's autoscaler and host load
// aggregator add on the authority leader (they are not part of cluster
// snapshots, so other members do not record them).
const (
	HistAutoscaleReplicas     = "autoscale_replicas"      // service
	HistAutoscaleGoal         = "autoscale_goal"          // service
	HistAutoscaleSignal       = "autoscale_signal"        // service, signal; per-replica value
	HistAutoscaleSignalTarget = "autoscale_signal_target" // service, signal
	HistTerraBaseConnections  = "terrabase_connections"   // member, role
	HistTerraBaseStorage      = "terrabase_storage_bytes" // member, role
	HistTerraBaseLagSeq       = "terrabase_replication_lag_seq"
	HistTerraBaseWriteQPS     = "terrabase_write_qps"
	HistHostCPUUtilization    = "host_cpu_utilization"        // member; 0..1
	HistHostMemoryRatio       = "host_memory_used_ratio"      // member; 0..1
	HistHostDiskRatio         = "host_disk_used_ratio"        // member; 0..1
	HistHostCPUCores          = "host_cpu_capacity_cores"     // member
	HistHostMemoryTotal       = "host_memory_total_bytes"     // member
	HistHostReceivedAt        = "host_report_received_at_ms"  // member; authenticated controller receive time
	HistHostFSIncomplete      = "host_filesystems_incomplete" // member; 0 or 1
	HistHostFSUsed            = "host_filesystem_used_bytes"  // member, role, path, device
	HistHostFSSize            = "host_filesystem_size_bytes"  // member, role, path, device
	HistHostFSRatio           = "host_filesystem_used_ratio"  // member, role, path, device; 0..1
	HistHostFSFiles           = "host_filesystem_files"       // member, role, path, device
	HistHostFSFilesFree       = "host_filesystem_files_free"  // member, role, path, device
	HistServiceCPUCores       = "service_cpu_cores"           // member, service
	HistServiceMemoryUsed     = "service_memory_used_bytes"
)

// Incoming WAN evidence: member, node, role, receiver_region, source_region.
const (
	HistTerraBaseWANObservedAt    = "terrabase_wan_observed_at_ms"
	HistTerraBaseWANLagGroups     = "terrabase_wan_lag_groups"
	HistTerraBaseWANStaleness     = "terrabase_wan_staleness_seconds"
	HistTerraBaseWANMembers       = "terrabase_wan_members"
	HistTerraBaseWANUnregistered  = "terrabase_wan_unregistered"
	HistTerraBaseWANConflicts     = "terrabase_wan_conflicts"
	HistTerraBaseWANAheadFailures = "terrabase_wan_ahead_failures_total" // cumulative gauge; compare observations/reset
)

// Bounds on what the sampler remembers between snapshots.
const (
	maxSampledMembers    = 512
	maxSampledOperations = 256
	maxSampledStages     = 64
	// maxSampledPartitions bounds the per-partition series of one sample.
	maxSampledPartitions = 128
)

// SnapshotSampler turns cluster snapshots into history samples. It keeps
// the previous CPU counters per member to report utilization, the last OCI
// counters per member to accumulate reset-aware cluster totals, the role of
// every member seen (to record a missing one as down) and the stages seen
// (to record a cleared stage as zero).
type SnapshotSampler struct {
	mu       sync.Mutex
	previous map[string]CPUSeconds
	// ociLast is each member's last OCI counters per operation; ociTotal is
	// the cluster total accumulated from per-member deltas, so a member
	// that misses a collection or restarts does not look like a counter
	// reset or a burst.
	ociLast  map[string]map[string]ociCounters
	ociTotal map[string]*ociCounters
	// ociPresent are the members whose OCI counters the previous snapshot
	// carried. A member missing from it rejoins with a fresh baseline: its
	// counters grew across several collections, and adding that growth to
	// one sample would read as a burst.
	ociPresent map[string]bool
	roles      map[string]string
	stages     map[string]bool
	seeded     bool
}

type ociCounters struct{ calls, errors, throttled, seconds float64 }

// add accumulates current minus last, treating a decrease as a process
// restart whose counters started again from zero. A member seen for the
// first time contributes its whole count only when seed is set (the
// sampler's first snapshot); later it contributes from its first sample on,
// so a member joining or returning is not a burst.
func (total *ociCounters) add(current, last ociCounters, known, seed bool) {
	delta := func(now, before float64) float64 {
		switch {
		case !known && seed:
			return now
		case !known:
			return 0
		case now < before:
			return now
		default:
			return now - before
		}
	}
	total.calls += delta(current.calls, last.calls)
	total.errors += delta(current.errors, last.errors)
	total.throttled += delta(current.throttled, last.throttled)
	total.seconds += delta(current.seconds, last.seconds)
}

// Samples derives every history series from one cluster snapshot.
func (sampler *SnapshotSampler) Samples(cluster ClusterSnapshot) []Sample {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	if sampler.previous == nil {
		sampler.previous = map[string]CPUSeconds{}
		sampler.ociLast = map[string]map[string]ociCounters{}
		sampler.ociTotal = map[string]*ociCounters{}
		sampler.ociPresent = map[string]bool{}
		sampler.roles = map[string]string{}
		sampler.stages = map[string]bool{}
	}
	present := map[string]bool{}
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
	// fromLeader marks streams whose report came from their leader.
	fromLeader := map[string]bool{}
	consumers := map[[2]string]ConsumerView{}
	var placement *PlacementView
	for _, member := range cluster.Members {
		name := member.Member
		gauge(HistMemberUp, 1, "member", name, "role", member.Role)
		if len(sampler.roles) < maxSampledMembers || sampler.roles[name] != "" {
			sampler.roles[name] = member.Role
		}
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
			gauge(HistNATSRouteRTTsTruncated, Bool(nats.RouteRTTsTruncated), "member", name, "server", nats.ServerName)
			for _, route := range nats.RouteRTTs {
				labels := []string{"member", name, "server", nats.ServerName, "peer", route.RemoteName}
				gauge(HistNATSRouteConnections, float64(route.Connections), labels...)
				gauge(HistNATSRouteMeasuredConnections, float64(route.MeasuredConnections), labels...)
				if route.RTTSeconds != nil {
					gauge(HistNATSRouteRTT, *route.RTTSeconds, labels...)
				}
			}
			gauge(HistJSStoreUsed, float64(nats.StoreUsedBytes), "member", name)
			if nats.StoreLimitBytes > 0 {
				gauge(HistJSStoreLimit, float64(nats.StoreLimitBytes), "member", name)
			}
			for _, stream := range nats.Streams {
				// Prefer the leader's own report; any replica's is a
				// fallback. A follower's report also names the leader, so
				// track who reported, not whom the report names.
				own := stream.Leader == nats.ServerName
				if _, ok := streams[stream.Name]; !ok || own && !fromLeader[stream.Name] {
					streams[stream.Name] = stream
					fromLeader[stream.Name] = own
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
			present[name] = true
			continuous := sampler.ociPresent[name]
			last := sampler.ociLast[name]
			if last == nil && len(sampler.ociLast) < maxSampledMembers {
				last = map[string]ociCounters{}
				sampler.ociLast[name] = last
			}
			for _, operation := range view.Operations {
				key := operation.Service + "." + operation.Operation
				current := ociCounters{calls: float64(operation.Calls), errors: float64(operation.Errors),
					throttled: float64(operation.Throttled), seconds: operation.TotalSeconds}
				total := sampler.ociTotal[key]
				if total == nil {
					if len(sampler.ociTotal) >= maxSampledOperations {
						continue
					}
					total = &ociCounters{}
					sampler.ociTotal[key] = total
				}
				if last == nil {
					continue
				}
				previous, known := last[key]
				switch {
				case !sampler.seeded:
					total.add(current, previous, known, true)
				case !continuous:
					// Returning or new member: rebaseline only.
				case !known:
					// A new operation on a continuously observed member:
					// its counters were zero before, so all of it is new.
					total.add(current, ociCounters{}, true, false)
				default:
					total.add(current, previous, true, false)
				}
				last[key] = current
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
	// A member seen before that no longer answers is down: record 0 under
	// its last role so its series is updated, not left at its last 1.
	for _, name := range cluster.Missing {
		if role, seen := sampler.roles[name]; seen {
			gauge(HistMemberUp, 0, "member", name, "role", role)
		} else {
			gauge(HistMemberUp, 0, "member", name, "role", "controller")
		}
	}
	sampler.seeded = true
	sampler.ociPresent = present
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
	for operation, totals := range sampler.ociTotal {
		counter(HistOCICalls, totals.calls, "operation", operation)
		counter(HistOCIErrors, totals.errors, "operation", operation)
		counter(HistOCIThrottled, totals.throttled, "operation", operation)
		counter(HistOCISeconds, totals.seconds, "operation", operation)
	}
	if placement != nil {
		partitions := 0
		stages := maps.Clone(placement.StageCounts)
		desired, serving := 0, 0
		for index, database := range placement.Databases {
			if index < maxSampledPartitions {
				gauge(HistPartitionDesired, float64(database.DesiredSeats),
					"database", database.DatabaseID, "partition", database.PartitionID)
				gauge(HistPartitionServing, float64(database.Serving),
					"database", database.DatabaseID, "partition", database.PartitionID)
			}
			if database.Terminal {
				for stage, count := range database.Stages {
					if _, present := stages[stage]; present {
						stages[stage] -= count
					}
				}
				continue
			}
			partitions++
			desired += database.DesiredSeats
			serving += database.Serving
			if rollout := database.Rollout; rollout != nil {
				gauge(HistRolloutProgress, rollout.Progress(), "operation", rollout.OperationID)
			}
		}
		gauge(HistDatabases, float64(partitions))
		gauge(HistSeatsDesired, float64(desired))
		gauge(HistSeatsServing, float64(serving))
		for stage, count := range stages {
			gauge(HistStageMembers, float64(count), "stage", stage)
			if len(sampler.stages) < maxSampledStages {
				sampler.stages[stage] = true
			}
		}
		// A stage that emptied is absent from the active counts: record its zero.
		for stage := range sampler.stages {
			if _, present := stages[stage]; !present {
				gauge(HistStageMembers, 0, "stage", stage)
			}
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
