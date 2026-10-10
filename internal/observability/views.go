package observability

import "time"

// SnapshotVersion is the wire version of MemberSnapshot. Readers accept
// unknown fields so a rolling update can add fields without a version bump.
const SnapshotVersion = 1

// MemberSnapshot is one member's complete read-only view. It is the payload a
// controller returns on the cell's observability subject and the root model a
// dashboard renders for one member. Optional sections are nil when the member
// does not run that subsystem (a host has no authority or placement view).
type MemberSnapshot struct {
	Version      int             `json:"version"`
	Cell         string          `json:"cell"`
	Member       string          `json:"member"`
	Role         string          `json:"role"`
	BuildVersion string          `json:"build_version,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	ObservedAt   time.Time       `json:"observed_at"`
	Ready        bool            `json:"ready"`
	Checks       []CheckResult   `json:"checks,omitempty"`
	Authority    *AuthorityView  `json:"authority,omitempty"`
	NATS         *NATSView       `json:"nats,omitempty"`
	Placement    *PlacementView  `json:"placement,omitempty"`
	Delivery     *DeliveryView   `json:"delivery,omitempty"`
	OCI          *OCIView        `json:"oci,omitempty"`
	KVSnapshots  *KVSnapshotView `json:"kv_snapshots,omitempty"`
	System       *SystemView     `json:"system,omitempty"`
	// Credentials lists the expiring certificates and NATS JWTs this
	// member runs with, so a cell-wide view sees every expiry ahead.
	Credentials []CredentialView `json:"credentials,omitempty"`
	// Errors names sections that failed to collect, by section name. The
	// values are short classes, never raw upstream error text.
	Errors map[string]string `json:"errors,omitempty"`
	// Metrics is this member's Prometheus text exposition when requested.
	Metrics          string `json:"metrics,omitempty"`
	MetricsTruncated bool   `json:"metrics_truncated,omitzero"`
}

// CheckResult is one readiness check outcome.
type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// AuthorityView is the regional lease as observed by this member.
type AuthorityView struct {
	Leader     bool      `json:"leader"`
	Ready      bool      `json:"ready"`
	CanMutate  bool      `json:"can_mutate"`
	OwnerID    string    `json:"owner_id,omitempty"`
	Epoch      uint64    `json:"epoch"`
	Revision   uint64    `json:"revision"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
	Reason     string    `json:"reason,omitempty"`
}

// NATSView is the embedded broker and JetStream health of one member.
type NATSView struct {
	ServerName      string         `json:"server_name"`
	RaftNodeID      string         `json:"raft_node_id,omitempty"`
	Connections     int            `json:"connections"`
	Routes          int            `json:"routes"`
	ClusterPeers    int            `json:"cluster_peers"`
	SlowConsumers   int64          `json:"slow_consumers"`
	InMsgs          int64          `json:"in_msgs"`
	OutMsgs         int64          `json:"out_msgs"`
	InBytes         int64          `json:"in_bytes"`
	OutBytes        int64          `json:"out_bytes"`
	MetaLeader      string         `json:"meta_leader,omitempty"`
	IsMetaLeader    bool           `json:"is_meta_leader"`
	MetaClusterSize int            `json:"meta_cluster_size"`
	MetaPeers       []PeerView     `json:"meta_peers,omitempty"`
	StoreUsedBytes  uint64         `json:"store_used_bytes"`
	StoreLimitBytes int64          `json:"store_limit_bytes"`
	Streams         []StreamView   `json:"streams,omitempty"`
	Consumers       []ConsumerView `json:"consumers,omitempty"`
	RouteRTTs       []RouteRTTView `json:"route_rtts,omitempty"`
	// RouteRTTsTruncated reports omitted peers or routes without an identity.
	RouteRTTsTruncated bool `json:"route_rtts_truncated"`
	// Truncated reports that the stream or consumer list hit its bound.
	Truncated bool `json:"truncated,omitzero"`
}

// RouteRTTView aggregates this server's pooled and dedicated routes to one peer.
// RTTSeconds is the largest positive measurement, nil when none is available.
type RouteRTTView struct {
	RemoteName          string   `json:"remote_name"`
	Connections         int      `json:"connections"`
	MeasuredConnections int      `json:"measured_connections"`
	RTTSeconds          *float64 `json:"rtt_seconds"`
}

// PeerView is one JetStream metadata peer as seen by this member.
type PeerView struct {
	Name    string        `json:"name"`
	Current bool          `json:"current"`
	Offline bool          `json:"offline"`
	Lag     uint64        `json:"lag"`
	Active  time.Duration `json:"active"`
}

// StreamView is one JetStream stream hosted by this member.
type StreamView struct {
	Name     string `json:"name"`
	Messages uint64 `json:"messages"`
	Bytes    uint64 `json:"bytes"`
	Replicas int    `json:"replicas"`
	Leader   string `json:"leader,omitempty"`
	// MaxReplicaLag is the largest operation lag of any replica.
	MaxReplicaLag uint64 `json:"max_replica_lag"`
	OfflinePeers  int    `json:"offline_peers"`
}

// ConsumerView is one JetStream consumer hosted by this member.
type ConsumerView struct {
	Stream         string `json:"stream"`
	Name           string `json:"name"`
	NumPending     uint64 `json:"num_pending"`
	NumAckPending  int    `json:"num_ack_pending"`
	NumRedelivered int    `json:"num_redelivered"`
	NumWaiting     int    `json:"num_waiting"`
}

// PlacementView summarizes managed TerraBase placement durable state.
type PlacementView struct {
	Databases []DatabaseView `json:"databases,omitempty"`
	// Truncated reports that the database list hit the view bound.
	Truncated bool `json:"truncated,omitzero"`
	// StageCounts aggregates member stages across every listed partition.
	StageCounts map[string]int `json:"stage_counts,omitempty"`
}

// DatabaseView is one database partition's roster progress.
type DatabaseView struct {
	DatabaseID   string         `json:"database_id"`
	PartitionID  string         `json:"partition_id"`
	Generation   uint64         `json:"generation"`
	Terminal     bool           `json:"terminal,omitzero"`
	DesiredSeats int            `json:"desired_seats"`
	Serving      int            `json:"serving"`
	Stages       map[string]int `json:"stages,omitempty"`
	Members      []MemberView   `json:"members,omitempty"`
	// Rollout is present while any seat carries a managed runtime target.
	Rollout *RolloutView `json:"rollout,omitempty"`
}

// MemberView is one seat's durable placement stage.
type MemberView struct {
	SeatID        string    `json:"seat_id"`
	Stage         string    `json:"stage"`
	HostNode      string    `json:"host_node,omitempty"`
	FailureDomain string    `json:"failure_domain,omitempty"`
	UpdatePhase   string    `json:"update_phase,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitzero"`
}

// RolloutView is a managed runtime update's per-seat progress.
type RolloutView struct {
	OperationID    string         `json:"operation_id"`
	ArtifactDigest string         `json:"artifact_digest,omitempty"`
	Seats          int            `json:"seats"`
	Phases         map[string]int `json:"phases"`
	// Completed counts seats whose phase is terminal for the update.
	Completed int `json:"completed"`
}

// Progress returns the fraction of seats that completed the rollout.
func (rollout RolloutView) Progress() float64 {
	if rollout.Seats == 0 {
		return 0
	}
	return float64(rollout.Completed) / float64(rollout.Seats)
}

// DeliveryView counts durable delivery intent processing on this member.
type DeliveryView struct {
	Acknowledged     uint64    `json:"acknowledged"`
	Deferred         uint64    `json:"deferred"`
	TransportRetries uint64    `json:"transport_retries"`
	LastAckAt        time.Time `json:"last_ack_at,omitzero"`
}

// KVSnapshotView reports configuration snapshots in Object Storage. State is
// disabled, paused, follower, unknown, current or failed. Buckets contains one
// metadata record per configured KV bucket, never document values or OCI secrets.
type KVSnapshotView struct {
	State               string    `json:"state"`
	IntervalSeconds     float64   `json:"interval_seconds,omitzero"`
	CheckTimeoutSeconds float64   `json:"check_timeout_seconds,omitzero"`
	LastCheckAt         time.Time `json:"last_check_at,omitzero"`
	// Overdue means a leader has no completed pass within interval plus timeout.
	Overdue bool                   `json:"overdue,omitzero"`
	Buckets []KVSnapshotBucketView `json:"buckets,omitempty"`
}

// KVSnapshotBucketView keeps successful evidence after a failed check. An
// unchanged stream advances LastCurrentAt without advancing LastUploadedAt,
// which records uploads by this process. State is unknown, current, failed,
// absent or empty; absent and empty require successful stream inspection.
type KVSnapshotBucketView struct {
	Bucket         string    `json:"bucket"`
	State          string    `json:"state"`
	LastCheckAt    time.Time `json:"last_check_at,omitzero"`
	LastUploadedAt time.Time `json:"last_uploaded_at,omitzero"`
	LastCurrentAt  time.Time `json:"last_current_at,omitzero"`
	Sequence       uint64    `json:"sequence,omitzero"`
	ErrorClass     string    `json:"error_class,omitempty"`
}

// OCIView is per-operation OCI API usage since this process started.
type OCIView struct {
	Operations []OCIOperationView `json:"operations,omitempty"`
	// Fleet is the latest complete inventory sweep of each region this
	// member observes, when it manages OCI hosts.
	Fleet []OCIFleetView `json:"fleet,omitempty"`
}

// OCIFleetView counts one region's managed OCI resources by lifecycle
// state as of its latest complete Observe sweep: instances in scope of the
// fleet's identity tags (owned or withheld), and the retained data volumes
// and volume attachments of the instances it verified. Unattached retained
// volumes are not listed by the sweep.
type OCIFleetView struct {
	Region      string         `json:"region"`
	ObservedAt  time.Time      `json:"observed_at"`
	Instances   map[string]int `json:"instances,omitempty"`
	Volumes     map[string]int `json:"volumes,omitempty"`
	Attachments map[string]int `json:"attachments,omitempty"`
}

// OCIOperationView counts calls of one templated OCI API operation.
type OCIOperationView struct {
	Service       string  `json:"service"`
	Operation     string  `json:"operation"`
	Calls         uint64  `json:"calls"`
	Errors        uint64  `json:"errors"`
	Throttled     uint64  `json:"throttled"`
	TotalSeconds  float64 `json:"total_seconds"`
	MaxSeconds    float64 `json:"max_seconds"`
	LastStatus    int     `json:"last_status,omitzero"`
	LastErrorCode int     `json:"last_error_code,omitzero"`
}

// SystemView is this machine's CPU, memory, pressure and filesystem state.
type SystemView struct {
	CPUCount        int              `json:"cpu_count"`
	CPUSeconds      CPUSeconds       `json:"cpu_seconds"`
	Load1           float64          `json:"load1"`
	Load5           float64          `json:"load5"`
	Load15          float64          `json:"load15"`
	MemTotalBytes   uint64           `json:"mem_total_bytes"`
	MemAvailBytes   uint64           `json:"mem_available_bytes"`
	SwapTotalBytes  uint64           `json:"swap_total_bytes"`
	SwapFreeBytes   uint64           `json:"swap_free_bytes"`
	Pressure        map[string]PSI   `json:"pressure,omitempty"`
	Filesystems     []FilesystemView `json:"filesystems,omitempty"`
	UptimeSeconds   float64          `json:"uptime_seconds"`
	ProcessRSSBytes uint64           `json:"process_rss_bytes"`
	// NetRxBytes and NetTxBytes are cumulative since boot over every
	// non-loopback interface; zero when /proc/net/dev cannot be read.
	NetRxBytes uint64 `json:"net_rx_bytes,omitzero"`
	NetTxBytes uint64 `json:"net_tx_bytes,omitzero"`
	// Clock is the kernel's NTP discipline state; nil when it cannot be read.
	Clock *ClockView `json:"clock,omitempty"`
}

// ClockView is the kernel clock state set by the node's time daemon
// (systemd-timesyncd or chrony): whether it is synchronized, the offset the
// daemon last measured against its server, and the kernel's bound on the
// clock's error, which grows by 500 µs/s while no sample arrives.
type ClockView struct {
	Synchronized    bool    `json:"synchronized"`
	OffsetSeconds   float64 `json:"offset_seconds"`
	MaxErrorSeconds float64 `json:"max_error_seconds"`
}

// CPUSeconds is cumulative CPU time across all CPUs by mode.
type CPUSeconds struct {
	User    float64 `json:"user"`
	Nice    float64 `json:"nice"`
	System  float64 `json:"system"`
	Idle    float64 `json:"idle"`
	IOWait  float64 `json:"iowait"`
	IRQ     float64 `json:"irq"`
	SoftIRQ float64 `json:"softirq"`
	Steal   float64 `json:"steal"`
}

// Busy returns non-idle CPU seconds.
func (cpu CPUSeconds) Busy() float64 {
	return cpu.User + cpu.Nice + cpu.System + cpu.IRQ + cpu.SoftIRQ + cpu.Steal
}

// PSI is one /proc/pressure resource line pair.
type PSI struct {
	SomeAvg10  float64 `json:"some_avg10"`
	SomeAvg60  float64 `json:"some_avg60"`
	SomeTotal  uint64  `json:"some_total_us"`
	FullAvg10  float64 `json:"full_avg10"`
	FullAvg60  float64 `json:"full_avg60"`
	FullTotal  uint64  `json:"full_total_us"`
	HasFullRow bool    `json:"has_full,omitzero"`
}

// FilesystemView is one statfs observation of a configured mount role.
type FilesystemView struct {
	Role       string `json:"role"`
	Path       string `json:"path"`
	SizeBytes  uint64 `json:"size_bytes"`
	AvailBytes uint64 `json:"avail_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	Files      uint64 `json:"files"`
	FilesFree  uint64 `json:"files_free"`
	// Device identifies the underlying filesystem (the mount's device
	// number); roles on one filesystem share it. Zero when unknown.
	Device uint64 `json:"device,omitempty"`
}

// DistinctFilesystems returns one entry per underlying filesystem, in order
// of first appearance, with the roles that share it joined as "a, b".
// Directory roles (state, install) often live on one filesystem, and adding
// their sizes would count its capacity twice. Entries without a device are
// matched by identical statistics, which a separate filesystem practically
// never shares.
func DistinctFilesystems(filesystems []FilesystemView) []FilesystemView {
	type identity struct {
		device                            uint64
		size, avail, free, files, freeIno uint64
	}
	index := map[identity]int{}
	out := make([]FilesystemView, 0, len(filesystems))
	for _, filesystem := range filesystems {
		key := identity{device: filesystem.Device}
		if filesystem.Device == 0 {
			key = identity{size: filesystem.SizeBytes, avail: filesystem.AvailBytes, free: filesystem.FreeBytes,
				files: filesystem.Files, freeIno: filesystem.FilesFree}
		}
		if filesystem.SizeBytes == 0 {
			// Unobserved (statfs failed): nothing to double count.
			out = append(out, filesystem)
			continue
		}
		if at, ok := index[key]; ok {
			out[at].Role += ", " + filesystem.Role
			continue
		}
		index[key] = len(out)
		out = append(out, filesystem)
	}
	return out
}

// CredentialView is one expiring credential a member runs with: a TLS
// certificate (kind tls) or a NATS JWT (kind nats-jwt). Credentials that
// never expire are not listed.
type CredentialView struct {
	// Name is the configured role of the file, and for a bundle of several
	// certificates also the certificate's subject.
	Name string `json:"name"`
	Kind string `json:"kind"`
	// NotBefore is when the credential was issued, so renewal can act on
	// the fraction of its lifetime left.
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after"`
}

// ClusterSnapshot is the scatter-gathered view of every controller in a cell.
type ClusterSnapshot struct {
	Cell       string           `json:"cell"`
	ObservedAt time.Time        `json:"observed_at"`
	Expected   []string         `json:"expected,omitempty"`
	Members    []MemberSnapshot `json:"members"`
	// Missing lists expected members that did not answer in time.
	Missing []string `json:"missing,omitempty"`
}
