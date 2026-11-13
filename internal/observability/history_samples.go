package observability

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
