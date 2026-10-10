package devfake

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

const (
	gib = uint64(1) << 30
	// cpus per controller.
	cpus = 4
)

// region is one fake region: its members, their build versions, its
// TerraBase databases and what is wrong with it.
type region struct {
	name        string
	controllers []string
	missing     []string
	hosts       []string
	versions    map[string]string
	databases   []database
	// leader is the authority and JetStream meta leader.
	leader string
	epoch  uint64
	// fullDisk names the controller whose NATS filesystem fills up.
	fullDisk string
	// throttled makes OCI return bursts of 429s.
	throttled bool
	// backlog makes one consumer fall behind.
	backlog bool
}

type database struct {
	id     string
	name   string
	seats  int
	stages []string
	// rollout is a managed TerraBase runtime update in progress.
	rollout *observability.RolloutView
}

// wave is a smooth periodic signal in [-1, 1] with a per-name phase.
func wave(t time.Time, period time.Duration, name string) float64 {
	return math.Sin(2*math.Pi*float64(t.UnixMilli())/float64(period.Milliseconds()) + phase(name))
}

// integral is the integral of base + amp*sin(2πt/period + phase) dt from
// the epoch to t, in seconds, so counters stay monotonic and consistent
// with the gauge they are the integral of.
func integral(t time.Time, base, amp float64, period time.Duration, name string) float64 {
	seconds := float64(t.UnixMilli()) / 1000
	omega := 2 * math.Pi / period.Seconds()
	return base*seconds - amp/omega*math.Cos(omega*seconds+phase(name))
}

func phase(name string) float64 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return float64(hash.Sum32()%6283) / 1000
}

// epochSeconds keeps cumulative counters at realistic magnitudes.
var counterEpoch = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func since(t time.Time) time.Time { return time.UnixMilli(t.Sub(counterEpoch).Milliseconds()) }

// cluster renders the region's cell-wide snapshot at t. It is a pure
// function of t, so history backfill and live sampling agree.
func (region *region) cluster(t time.Time, start time.Time) observability.ClusterSnapshot {
	snapshot := observability.ClusterSnapshot{Cell: region.name, ObservedAt: t,
		Expected: append(append([]string{}, region.controllers...), region.missing...), Missing: region.missing}
	placement := region.placement(t)
	for _, name := range region.controllers {
		snapshot.Members = append(snapshot.Members, region.member(name, t, start, placement))
	}
	return snapshot
}

func (region *region) member(name string, t, start time.Time, placement *observability.PlacementView) observability.MemberSnapshot {
	local := since(t)
	leader := name == region.leader
	util := 0.32 + 0.18*wave(t, 3*time.Hour, name) + 0.05*wave(t, 11*time.Minute, name+"x")
	if leader {
		util += 0.12
	}
	busy := cpus * integral(local, 0.32+bonus(leader), 0.18, 3*time.Hour, name)
	busy += cpus * integral(local, 0, 0.05, 11*time.Minute, name+"x")
	total := cpus * float64(local.UnixMilli()) / 1000
	member := observability.MemberSnapshot{Version: observability.SnapshotVersion, Cell: region.name, Member: name,
		Role: "controller", BuildVersion: region.versions[name], StartedAt: start.Add(-time.Duration(len(name)) * 7 * time.Hour),
		ObservedAt: t, Ready: true,
		Checks: region.checks(name),
		Authority: &observability.AuthorityView{Leader: leader, Ready: true, CanMutate: leader, OwnerID: entityid.Derive("preview-member", region.leader),
			Epoch: region.epoch, Revision: region.epoch*40 + uint64(t.Unix()/30)%40, ExpiresAt: t.Add(8 * time.Second),
			ObservedAt: t},
		System: &observability.SystemView{CPUCount: cpus,
			CPUSeconds: observability.CPUSeconds{User: busy * 0.7, System: busy * 0.3, Idle: total - busy},
			Load1:      util * cpus * 1.1, Load5: (0.32 + bonus(leader)) * cpus, Load15: 0.3 * cpus,
			MemTotalBytes: 16 * gib, MemAvailBytes: uint64(float64(16*gib) * (0.5 - 0.08*wave(t, 2*time.Hour, name+"m"))),
			Pressure:    map[string]observability.PSI{"memory": {SomeAvg10: math.Max(0, 0.4*wave(t, 40*time.Minute, name))}},
			Filesystems: region.filesystems(name, t, start), UptimeSeconds: t.Sub(start).Seconds() + 86400*3,
			ProcessRSSBytes: 380 << 20},
	}
	// Readiness is every check passing, whatever the member's role, as
	// observability.Health.Evaluate decides it.
	member.Ready = allOK(member.Checks)
	member.NATS = region.nats(name, t, leader)
	if leader {
		member.Placement = placement
		member.OCI = region.oci(t, start)
	}
	member.Delivery = &observability.DeliveryView{Acknowledged: uint64(integral(local, 0.02, 0.01, time.Hour, name)),
		Deferred: uint64(integral(local, 0.0004, 0.0002, time.Hour, name)), TransportRetries: 3, LastAckAt: t.Add(-42 * time.Second)}
	return member
}

func bonus(leader bool) float64 {
	if leader {
		return 0.12
	}
	return 0
}

// checks are the member's readiness checks with the same names and detail
// phrases the controller registers (internal/app/observability.go).
func (region *region) checks(name string) []observability.CheckResult {
	peers := len(region.controllers) + len(region.missing)
	cluster := observability.CheckResult{Name: "cluster", OK: true,
		Detail: fmt.Sprintf("%d of %d replicas routed", peers, peers)}
	if len(region.missing) > 0 {
		cluster = observability.CheckResult{Name: "cluster",
			Detail: "regional cluster is below its full replica count"}
	}
	return []observability.CheckResult{
		{Name: "startup", OK: true, Detail: "runtime started"},
		{Name: "nats", OK: true, Detail: "regional broker connected"},
		cluster,
		{Name: "authority", OK: true, Detail: fmt.Sprintf("lease held by %s, epoch %d", region.leader, region.epoch)},
	}
}

func allOK(checks []observability.CheckResult) bool {
	for _, check := range checks {
		if !check.OK {
			return false
		}
	}
	return len(checks) > 0
}

// fullDiskRate is how fast the filling disk fills, as a ratio per hour.
const fullDiskRate = 0.0035

func (region *region) filesystems(name string, t, start time.Time) []observability.FilesystemView {
	hours := float64(t.Sub(counterEpoch).Hours())
	root := 0.31 + 0.0001*hours
	nats := 0.42 + 0.02*wave(t, 6*time.Hour, name) + 0.00005*hours
	if name == region.fullDisk {
		// Fills about 0.35% an hour from 73% a day before the world
		// started: under 72h to full. Anchored to the fixed world start,
		// so live samples keep growing like the backfill.
		nats = 0.715 + fullDiskRate*(t.Sub(start).Hours()+24)
	}
	view := func(role, path string, size uint64, used float64) observability.FilesystemView {
		used = math.Min(math.Max(used, 0), 0.999)
		avail := uint64(float64(size) * (1 - used))
		return observability.FilesystemView{Role: role, Path: path, SizeBytes: size, AvailBytes: avail, FreeBytes: avail,
			Files: 6_553_600, FilesFree: 6_100_000}
	}
	return []observability.FilesystemView{
		view("root", "/", 100*gib, root),
		view("nats", "/var/lib/terrascale/nats", 200*gib, nats),
	}
}

var streamNames = []string{"TS_DECISIONS", "TS_DELIVERY", "TS_PLACEMENT", "TS_HISTORY", "KV_authority"}

func (region *region) nats(name string, t time.Time, leader bool) *observability.NATSView {
	local := since(t)
	rate := 120.0 + 40*float64(len(region.controllers))
	view := &observability.NATSView{ServerName: name, Connections: 9 + len(region.hosts) + int(3*wave(t, time.Hour, name)),
		Routes: len(region.controllers) - 1, ClusterPeers: len(region.controllers), SlowConsumers: 0,
		InMsgs:  int64(integral(local, rate, rate*0.4, 37*time.Minute, name)),
		OutMsgs: int64(integral(local, rate*1.6, rate*0.5, 37*time.Minute, name)),
		InBytes: int64(integral(local, rate*820, rate*300, 37*time.Minute, name)), OutBytes: int64(integral(local, rate*1300, rate*400, 37*time.Minute, name)),
		MetaLeader: region.leader, IsMetaLeader: leader, MetaClusterSize: len(region.controllers) + len(region.missing),
		StoreLimitBytes: int64(64 * gib)}
	var used uint64
	for _, peer := range append(append([]string{}, region.controllers...), region.missing...) {
		if peer == name {
			continue
		}
		missing := contains(region.missing, peer)
		view.MetaPeers = append(view.MetaPeers, observability.PeerView{Name: peer, Current: !missing, Offline: missing,
			Lag: map[bool]uint64{true: 4120, false: 0}[missing], Active: 300 * time.Millisecond})
	}
	if leader {
		for index, stream := range streamNames {
			messages := uint64(20_000*(index+1)) + uint64(integral(local, 0.05*float64(index+1), 0.02, 5*time.Hour, stream))%50_000
			bytes := messages * uint64(600+index*350)
			used += bytes * 3
			lag := uint64(0)
			offline := 0
			if len(region.missing) > 0 {
				offline = 1
				lag = uint64(40 + 30*math.Abs(wave(t, 13*time.Minute, stream)))
			}
			view.Streams = append(view.Streams, observability.StreamView{Name: stream, Messages: messages, Bytes: bytes,
				Replicas: 3, Leader: region.controllers[index%len(region.controllers)], MaxReplicaLag: lag, OfflinePeers: offline})
		}
		pending := uint64(math.Max(0, 6+5*wave(t, 9*time.Minute, "placement")))
		if region.backlog {
			pending = uint64(1800 + 900*wave(t, 50*time.Minute, "delivery"))
		}
		view.Consumers = []observability.ConsumerView{
			{Stream: "TS_DELIVERY", Name: "delivery-apply", NumPending: pending, NumAckPending: int(pending / 20)},
			{Stream: "TS_PLACEMENT", Name: "placement-reconcile", NumPending: uint64(math.Max(0, 3+3*wave(t, 7*time.Minute, "p"))),
				NumAckPending: 1},
			{Stream: "TS_DECISIONS", Name: "decision-tail", NumPending: 0},
		}
	}
	view.StoreUsedBytes = used/uint64(len(region.controllers)) + 2*gib
	return view
}

var ociOperations = []struct {
	service, operation string
	rate, latency      float64
}{
	{"compute", "GET /instances/{id}", 0.9, 0.18},
	{"compute", "POST /instances", 0.01, 2.4},
	{"compute", "GET /vnicAttachments", 0.4, 0.22},
	{"blockstorage", "POST /volumeAttachments", 0.02, 1.1},
	{"blockstorage", "GET /volumes/{id}", 0.5, 0.15},
	{"objectstorage", "PUT /n/{ns}/b/{bucket}/o/{object}", 0.2, 0.65},
}

// stormLead is how long before the world started the 429 storm began.
const stormLead = 40 * time.Minute

// stormShare is the share of compute calls OCI answers with 429 during the
// storm: enough for a warning, not a critical insight.
const stormShare = 0.012

func (region *region) oci(t, start time.Time) *observability.OCIView {
	local := since(t)
	view := &observability.OCIView{}
	for _, op := range ociOperations {
		calls := integral(local, op.rate, op.rate*0.5, 23*time.Minute, op.operation)
		errorRate := 0.004
		throttled := 0.0
		if region.throttled && op.service == "compute" {
			// A 429 storm that began stormLead before the world started and
			// is still going: elapsed storm time comes from the fixed world
			// start, so backfill and live samples share one origin and the
			// counter keeps rising.
			throttled = op.rate * stormShare * math.Max(0, t.Sub(start.Add(-stormLead)).Seconds())
			errorRate = 0.01
		}
		errors := calls*errorRate + throttled
		// Total call duration is the integral of call rate x latency, with
		// latency swinging 15% on a 31-minute wave; it only ever grows.
		seconds := op.latency * (calls + 0.15*integral(local, 0, op.rate, 31*time.Minute, op.operation))
		status := 200
		code := 0
		if throttled > 0 {
			code = 429
		}
		view.Operations = append(view.Operations, observability.OCIOperationView{Service: op.service, Operation: op.operation,
			Calls: uint64(calls), Errors: uint64(errors), Throttled: uint64(throttled), TotalSeconds: seconds,
			MaxSeconds: op.latency * 6, LastStatus: status, LastErrorCode: code})
	}
	// The fleet sweep: every host runs with one attached data volume, except
	// one volume that keeps getting stuck attaching and one host that is
	// still provisioning every other 10 minutes.
	hosts := len(region.hosts)
	instances := map[string]int{"RUNNING": hosts}
	if t.Minute()%20 < 10 {
		instances["RUNNING"], instances["PROVISIONING"] = hosts-1, 1
	}
	view.Fleet = []observability.OCIFleetView{{Region: region.name, ObservedAt: t.Add(-7 * time.Second),
		Instances: instances, Volumes: map[string]int{"AVAILABLE": hosts},
		Attachments: map[string]int{"ATTACHED": hosts - 1, "ATTACHING": 1}}}
	return view
}

func (region *region) placement(t time.Time) *observability.PlacementView {
	view := &observability.PlacementView{StageCounts: map[string]int{}}
	for dbIndex, db := range region.databases {
		entry := observability.DatabaseView{DatabaseID: db.id, PartitionID: entityid.Derive("preview-partition", db.id), Generation: uint64(3 + dbIndex),
			DesiredSeats: db.seats, Stages: map[string]int{}}
		for seat := range db.seats {
			stage := "serving"
			if seat < len(db.stages) {
				stage = db.stages[seat]
			}
			host := region.hosts[(dbIndex+seat)%len(region.hosts)]
			member := observability.MemberView{SeatID: entityid.Derive("preview-seat", region.name, db.id, fmt.Sprint(seat+1)), Stage: stage, HostNode: host,
				FailureDomain: fmt.Sprintf("FAULT-DOMAIN-%d", seat%3+1), UpdatedAt: t.Add(-time.Duration(seat*17+dbIndex*5) * time.Minute)}
			if db.rollout != nil {
				member.UpdatePhase = "done"
				if seat >= db.rollout.Completed {
					member.UpdatePhase = "pending"
				}
			}
			entry.Members = append(entry.Members, member)
			entry.Stages[stage]++
			view.StageCounts[stage]++
			if stage == "serving" {
				entry.Serving++
			}
		}
		entry.Rollout = db.rollout
		view.Databases = append(view.Databases, entry)
	}
	return view
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// nodes are the region's granted nodes: one per controller, then one per
// seat host, each running TerraBase and ts-auth. The second host of a
// region with a draining seat is fenced for a drain.
func (r region) nodes(context.Context) []regionview.Node {
	var nodes []regionview.Node
	digest := "sha256:7da6542c9f0e1b2a"
	for index, controller := range r.controllers {
		state := "running"
		if r.name == "gru" && index == 2 {
			state = "starting"
		}
		nodes = append(nodes, regionview.Node{Name: fmt.Sprintf("ts-%s-%d", r.name, index+1),
			Address: fmt.Sprintf("10.251.0.%d", 11+index), Member: controller,
			Services: []regionview.Service{{Role: "ts-auth", Digest: "sha256:f8e35965a1b2", State: state}},
			Backends: []regionview.Backend{{Set: "ts-auth"}}})
	}
	for index, host := range r.hosts {
		node := regionview.Node{Name: host, Address: fmt.Sprintf("10.251.1.%d", 21+index),
			Services: []regionview.Service{{Role: "terrabase", Digest: digest, State: "running"}},
			Backends: []regionview.Backend{{Set: "terrabase"}}}
		if r.name == "sfo" && index == 1 {
			node.Fence, node.Operation = []string{"drain"}, "drain: fence"
			node.Backends[0].Offline = true
		}
		nodes = append(nodes, node)
	}
	return nodes
}
