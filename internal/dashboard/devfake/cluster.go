package devfake

import (
	"fmt"
	"hash/fnv"
	"math"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
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
		Checks: []observability.CheckResult{{Name: "nats", OK: true}, {Name: "cluster", OK: len(region.missing) == 0,
			Detail: detailIf(len(region.missing) > 0, "regional cluster is below its full replica count")},
			{Name: "authority", OK: true}},
		Authority: &observability.AuthorityView{Leader: leader, Ready: true, CanMutate: leader, OwnerID: region.leader,
			Epoch: region.epoch, Revision: region.epoch*40 + uint64(t.Unix()/30)%40, ExpiresAt: t.Add(8 * time.Second),
			ObservedAt: t},
		System: &observability.SystemView{CPUCount: cpus,
			CPUSeconds: observability.CPUSeconds{User: busy * 0.7, System: busy * 0.3, Idle: total - busy},
			Load1:      util * cpus * 1.1, Load5: (0.32 + bonus(leader)) * cpus, Load15: 0.3 * cpus,
			MemTotalBytes: 16 * gib, MemAvailBytes: uint64(float64(16*gib) * (0.5 - 0.08*wave(t, 2*time.Hour, name+"m"))),
			Pressure:    map[string]observability.PSI{"memory": {SomeAvg10: math.Max(0, 0.4*wave(t, 40*time.Minute, name))}},
			Filesystems: region.filesystems(name, t), UptimeSeconds: t.Sub(start).Seconds() + 86400*3,
			ProcessRSSBytes: 380 << 20},
	}
	member.Ready = member.Checks[1].OK || !leader
	member.NATS = region.nats(name, t, leader)
	if leader {
		member.Placement = placement
		member.OCI = region.oci(t)
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

func detailIf(condition bool, detail string) string {
	if condition {
		return detail
	}
	return ""
}

func (region *region) filesystems(name string, t time.Time) []observability.FilesystemView {
	hours := float64(t.Sub(counterEpoch).Hours())
	root := 0.31 + 0.0001*hours
	nats := 0.42 + 0.02*wave(t, 6*time.Hour, name) + 0.00005*hours
	if name == region.fullDisk {
		// Fills about 0.35% an hour from 73% a day ago: under 72h to full.
		nats = 0.715 + 0.0035*(hours-float64(time.Since(counterEpoch).Hours()-24))
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

func (region *region) oci(t time.Time) *observability.OCIView {
	local := since(t)
	view := &observability.OCIView{}
	for _, op := range ociOperations {
		calls := integral(local, op.rate, op.rate*0.5, 23*time.Minute, op.operation)
		errorRate := 0.004
		throttleRate := 0.0
		if region.throttled && op.service == "compute" {
			// A 429 storm in the last half hour.
			if time.Since(t) < 40*time.Minute {
				throttleRate = 0.12
			}
			errorRate = 0.01
		}
		throttled := integral(local, op.rate*throttleRate, 0, time.Hour, op.operation)
		if region.throttled && op.service == "compute" {
			// Earlier history carried none; keep the counter monotonic.
			throttled = op.rate * 0.12 * math.Max(0, 40*60-time.Since(t).Seconds())
		}
		errors := calls*errorRate + throttled
		seconds := calls * op.latency * (1 + 0.15*wave(t, 31*time.Minute, op.operation))
		status := 200
		code := 0
		if throttled > 0 {
			code = 429
		}
		view.Operations = append(view.Operations, observability.OCIOperationView{Service: op.service, Operation: op.operation,
			Calls: uint64(calls), Errors: uint64(errors), Throttled: uint64(throttled), TotalSeconds: seconds,
			MaxSeconds: op.latency * 6, LastStatus: status, LastErrorCode: code})
	}
	return view
}

func (region *region) placement(t time.Time) *observability.PlacementView {
	view := &observability.PlacementView{StageCounts: map[string]int{}}
	for dbIndex, db := range region.databases {
		entry := observability.DatabaseView{DatabaseID: db.id, PartitionID: "p0", Generation: uint64(3 + dbIndex),
			DesiredSeats: db.seats, Stages: map[string]int{}}
		for seat := range db.seats {
			stage := "serving"
			if seat < len(db.stages) {
				stage = db.stages[seat]
			}
			host := region.hosts[(dbIndex+seat)%len(region.hosts)]
			member := observability.MemberView{SeatID: fmt.Sprintf("%s-%d", db.id, seat+1), Stage: stage, HostNode: host,
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
