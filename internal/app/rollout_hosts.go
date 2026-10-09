package app

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/seatrollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// Host self-update on the authority leader: the host controller hands every
// host's "rollout" exchange to the rollout control (host.RolloutSink), which
// records the host's health proof, posts its step agent's reply to the step
// board and answers with the host's pending step, so host steps travel the
// same board as controller steps.

// rolloutHosts is what the sink needs from the executor's start.
type rolloutHosts struct {
	collector *rolloutexec.Collector
	board     jetstream.KeyValue
	// colocated are the controllers and the hosts on their VMs, which never
	// take part as hosts.
	colocated func(string) bool

	mu sync.Mutex
	// last is when each host's last exchange was accepted, and held when
	// it last said a restart hold is set on it (TS-578).
	last, held map[string]time.Time
}

// maxHostReply bounds a host step agent's reply, as the executor reads it.
const maxHostReply = 4 << 10

// Exchange implements host.RolloutSink. A host joins the release program
// with its first proof and stays in it: one that stops proving holds the host
// rollout instead of being left out, so a TerraBase seat is never moved
// while its peer is silent. A host replaced under its name is a stranger
// until it proves with its new key.
func (c *rolloutControl) Exchange(ctx context.Context, registration host.Registration, exchange host.RolloutExchange,
) (host.RolloutStep, error) {
	hosts := c.hosts.Load()
	if hosts == nil {
		return host.RolloutStep{}, errors.New("the rollout executor is not running")
	}
	node := registration.Node
	if hosts.colocated(node) {
		return host.RolloutStep{}, errors.New("a host on a controller's VM moves with its controller")
	}
	if len(exchange.Reply) > maxHostReply {
		return host.RolloutStep{}, errors.New("host rollout reply is too large")
	}
	now := time.Now()
	hosts.mu.Lock()
	if last, seen := hosts.last[node]; seen && now.Sub(last) < rolloutexec.DefaultProofInterval/2 {
		hosts.mu.Unlock()
		return host.RolloutStep{}, errors.New("host rollout exchange is too frequent")
	}
	hosts.last[node] = now
	hosts.mu.Unlock()
	public, err := decodePublicKey(registration.PublicKey)
	if err != nil {
		return host.RolloutStep{}, err
	}
	keys, err := trust.ParseKeyring(public)
	if err != nil {
		return host.RolloutStep{}, err
	}
	if err := hosts.collector.ObserveFrom(node, exchange.Proof, keys); err != nil {
		return host.RolloutStep{}, fmt.Errorf("host health proof: %w", err)
	}
	hosts.mu.Lock()
	if exchange.Held {
		hosts.held[node] = now
	} else {
		delete(hosts.held, node)
	}
	hosts.mu.Unlock()
	membership, err := protocol.EncodeJSON(rollout.HostMembership{Node: node, PublicKey: registration.PublicKey})
	if err != nil {
		return host.RolloutStep{}, err
	}
	if err := putChanged(ctx, hosts.board, rollout.HostMembershipKey(node), membership); err != nil {
		return host.RolloutStep{}, err
	}
	if len(exchange.Reply) > 0 {
		var reply rolloutexec.StepReply
		if err := json.Unmarshal(exchange.Reply, &reply); err != nil || reply.Unit != node {
			return host.RolloutStep{}, errors.New("host rollout reply is invalid")
		}
		if err := putChanged(ctx, hosts.board, rolloutexec.ReplyKey(node), exchange.Reply); err != nil {
			return host.RolloutStep{}, err
		}
	}
	entry, err := hosts.board.Get(ctx, rolloutexec.StepKey(node))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return host.RolloutStep{}, nil
	}
	if err != nil {
		return host.RolloutStep{}, err
	}
	return host.RolloutStep{Step: entry.Value()}, nil
}

// heldBy reports whether node said recently that a restart hold is set.
func (h *rolloutHosts) heldBy(node string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	at, held := h.held[node]
	return held && time.Since(at) < 3*rolloutexec.DefaultProofInterval
}

// putChanged writes value under key unless it already holds it.
func putChanged(ctx context.Context, kv jetstream.KeyValue, key string, value []byte) error {
	entry, err := kv.Get(ctx, key)
	if err == nil && bytes.Equal(entry.Value(), value) {
		return nil
	}
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return err
	}
	_, err = kv.Put(ctx, key, value)
	return err
}

// Binary implements host.RolloutSink from this node's release root: the
// controllers move before the hosts, so the leader's node holds both the
// release a host moves to and the one it may return to. The host checks the
// bytes against the digest and its step agent against the receipt.
//
// ponytail: one architecture per cell; a host of another one finds no
// release here and its rollout rolls back at the proof deadline.
func (c *rolloutControl) Binary(_ context.Context, digest string, offset int64, limit int) (host.RolloutChunk, error) {
	file, err := os.Open(c.layout.BinaryPath(digest))
	if err != nil {
		return host.RolloutChunk{}, fmt.Errorf("release %s is not on this controller", digest)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || offset > info.Size() {
		return host.RolloutChunk{}, errors.New("rollout binary query is outside the release")
	}
	data := make([]byte, min(int64(limit), info.Size()-offset))
	if _, err := file.ReadAt(data, offset); err != nil && !errors.Is(err, io.EOF) {
		return host.RolloutChunk{}, err
	}
	return host.RolloutChunk{Data: data, Size: info.Size()}, nil
}

// hostRollout is a host agent's part in the cell's orchestrator rollouts.
type hostRollout struct {
	cell, node string
	identity   ed25519.PrivateKey
	// controller is the controller response key host.json pins.
	controller ed25519.PublicKey
	// spool is the relay's directory; layout is the node's release root.
	spool  string
	layout selfupdate.Layout
	// stateRoot holds the host's restart holds (host.RestartHoldSuffix).
	stateRoot string
	// interval defaults to rolloutexec.DefaultProofInterval.
	interval time.Duration
}

// followHostRollouts is a host agent's rollout follower
// (host.AgentConfig.FollowRollouts). Every interval it proves its release
// and passes its step agent's newest reply in one "rollout" exchange, and
// spools the step it gets back, with the release it names, for the node's
// root step agent (the self-update watchdog).
func followHostRollouts(h hostRollout) func(context.Context, host.RolloutSession) {
	return func(ctx context.Context, session host.RolloutSession) {
		identity, err := rolloutexec.ProcessIdentity(h.cell, h.node, "")
		if err != nil {
			slog.Warn("host rollouts disabled", "error", err)
			return
		}
		leaders, err := trust.ParseKeyring(h.controller)
		if err != nil {
			slog.Warn("host rollouts disabled", "error", err)
			return
		}
		if err := os.MkdirAll(h.spool, 0o700); err != nil {
			slog.Warn("host rollouts disabled", "error", err)
			return
		}
		relay := &rolloutexec.Relay{Cell: h.cell, Unit: h.node, SystemdUnit: selfupdate.HostUnit, Leaders: leaders,
			Dir: h.spool, Layout: h.layout, Sources: []rolloutexec.BinarySource{session.FetchRelease}}
		refused := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(cmp.Or(h.interval, rolloutexec.DefaultProofInterval)):
			}
			if session.SessionLost() {
				return
			}
			now := time.Now().UTC()
			proof := identity
			proof.ObservedAt = now
			wire, err := rolloutexec.SignHealthProof(proof, h.identity, now)
			if err != nil {
				slog.Warn("host rollouts stopped", "error", err)
				return
			}
			reply, err := relay.Reply()
			if err != nil {
				slog.Warn("host rollout reply is unreadable", "error", err)
			}
			// An operator holding a restart here (TS-578) holds the host's
			// step too: the leader sends none, and none is spooled.
			holds, _ := filepath.Glob(filepath.Join(h.stateRoot, "*"+host.RestartHoldSuffix))
			held := h.stateRoot != "" && len(holds) > 0
			step, err := session.RolloutExchange(ctx, host.RolloutExchange{Proof: wire, Reply: reply, Held: held})
			if err != nil {
				// A controller without rollouts answers every exchange the
				// same way; say so once.
				if !refused && ctx.Err() == nil {
					slog.Info("host rollout exchange not accepted", "error", err)
				}
				refused = true
				continue
			}
			refused = false
			if len(step.Step) == 0 || held {
				continue
			}
			if err := relay.Spool(ctx, step.Step); err != nil && ctx.Err() == nil {
				slog.Warn("host rollout step not spooled", "error", err)
			}
		}
	}
}

// rolloutGate adds the host rules to the cluster gate. A host step waits
// while the host says a restart hold is set on it (TS-578), while the
// TerraBase seat controller (controller.terrabase_seats) has a seat out of
// rotation, and, for a host with a TerraBase member, until every member of
// the cell serves its desired generation: the previous host's member serves
// again before the next one restarts, a member down for any other reason
// holds every host step, and no TerraBase release is restarting a seat
// meanwhile. The seat controller in turn starts no seat restart while a
// host rollout is active (hostRolloutActive).
//
// With a release fence, a controller or host step then waits until the
// unit's node is out of rotation on the load balancer (rolloutFence).
type rolloutGate struct {
	cluster      rolloutexec.Gate
	drainedSeats func(context.Context) (map[string]bool, error)
	// held reports a host that said a restart hold is set on it.
	held func(unit string) bool
	// serving returns nil while every TerraBase member serves; nil skips it.
	serving func(ctx context.Context, unit string) error
	// fenced returns nil once the unit's node is out of rotation; nil
	// fences nothing.
	fenced func(ctx context.Context, unit string) error
}

func (g rolloutGate) Check(ctx context.Context, record rollout.Record, unit string) error {
	if err := g.cluster.Check(ctx, record, unit); err != nil {
		return err
	}
	if unit == "" {
		return nil
	}
	if record.Kind == rollout.KindHost {
		if err := g.hostRules(ctx, unit); err != nil {
			return err
		}
	}
	if g.fenced != nil {
		return g.fenced(ctx, unit)
	}
	return nil
}

func (g rolloutGate) hostRules(ctx context.Context, unit string) error {
	if g.held != nil && g.held(unit) {
		return fmt.Errorf("%w: an operator holds restarts on %s", rolloutexec.ErrGateHeld, unit)
	}
	if g.drainedSeats != nil {
		drained, err := g.drainedSeats(ctx)
		if err != nil {
			return fmt.Errorf("%w: read the TerraBase seats: %v", rolloutexec.ErrGateHeld, err)
		}
		if len(drained) > 0 {
			return fmt.Errorf("%w: TerraBase seats %s are out of rotation", rolloutexec.ErrGateHeld,
				strings.Join(slices.Sorted(maps.Keys(drained)), ", "))
		}
	}
	if g.serving != nil {
		return g.serving(ctx, unit)
	}
	return nil
}

// terraBaseServing returns nil for a host without a TerraBase member, and
// otherwise only while every TerraBase member of the cell recently reported
// running (which includes its /readyz) at its desired generation.
func terraBaseServing(hosts seatrollout.Hosts) func(context.Context, string) error {
	return func(ctx context.Context, unit string) error {
		desired, err := hosts.ListDesired(ctx, terrabase.Role)
		if err != nil {
			return fmt.Errorf("%w: read the TerraBase members: %v", rolloutexec.ErrGateHeld, err)
		}
		members := map[string]uint64{}
		for _, d := range desired {
			if !d.Withdrawn {
				members[d.Node] = d.Generation
			}
		}
		if _, member := members[unit]; !member {
			return nil
		}
		statuses, err := hosts.ListHosts(ctx)
		if err != nil {
			return fmt.Errorf("%w: read the TerraBase members: %v", rolloutexec.ErrGateHeld, err)
		}
		serving := map[string]bool{}
		for _, status := range statuses {
			for _, report := range status.Reports {
				generation, member := members[report.Node]
				serving[report.Node] = serving[report.Node] || member && report.Role == terrabase.Role &&
					report.State == "running" && report.Generation == generation && time.Since(report.ObservedAt) < host.ReportMaxAge
			}
		}
		for _, node := range slices.Sorted(maps.Keys(members)) {
			if !serving[node] {
				return fmt.Errorf("%w: TerraBase member %s does not serve its desired generation", rolloutexec.ErrGateHeld, node)
			}
		}
		return nil
	}
}

// hostRolloutActive names the cell's active orchestrator host rollout, if
// any; the seat controller starts no seat restart meanwhile.
func (c *rolloutControl) hostRolloutActive(ctx context.Context) (string, error) {
	store := c.store.Load()
	if store == nil {
		return "", nil
	}
	record, _, active, err := store.Active(ctx)
	if err != nil || !active || record.Kind != rollout.KindHost || record.Phase.Terminal() {
		return "", err
	}
	return "orchestrator host rollout " + record.RolloutID + " is active", nil
}

// colocatedNodes reports the controllers and the hosts on their VMs: the node
// nodeOf names for each controller slot, and the slot's own server name. It
// reads nodeOf on every call, so a host grant renamed since start counts.
func colocatedNodes(cell string, controllers []rollout.Unit, nodeOf func(string) string) func(string) bool {
	return func(node string) bool {
		for _, controller := range controllers {
			if node == controller.ID || node == nodeOf(controller.ID) {
				return true
			}
			if name, err := naming.RegionCell(strings.ToUpper(cell)).ControllerSlot(controller.ID); err == nil && name == node {
				return true
			}
		}
		return false
	}
}

// hostUnits lists the cell's joined hosts as rollout units: a host joined
// with its current registered key. A host on a controller's VM shares the
// controller's release root, so it is left out: it runs the controller's
// release from its next restart. TerraBase hosts are grouped by partition
// (all of them together when the partition is unknown), so a wave never
// stops two seats of one partition.
func hostUnits(list func(context.Context) ([]host.HostStatus, error), board jetstream.KeyValue,
	colocated func(string) bool,
) func(context.Context) ([]rollout.Unit, error) {
	return func(ctx context.Context) ([]rollout.Unit, error) {
		hosts, err := list(ctx)
		if err != nil {
			return nil, err
		}
		partitions := map[string][]string{}
		for _, status := range hosts {
			r := status.Registration
			// A durable retirement excludes history; session loss never excludes a current host.
			if status.Retired || colocated(r.Node) {
				continue
			}
			entry, err := board.Get(ctx, rollout.HostMembershipKey(r.Node))
			if errors.Is(err, jetstream.ErrKeyNotFound) {
				return nil, fmt.Errorf("host %s has not joined self-update", r.Node)
			} else if err != nil {
				return nil, err
			}
			var membership rollout.HostMembership
			if err := protocol.DecodeTolerant(entry.Value(), &membership, maxHostReply); err != nil {
				return nil, err
			}
			if membership.Node != r.Node || membership.PublicKey != r.PublicKey {
				return nil, fmt.Errorf("host %s has not proved its current registration key", r.Node)
			}
			var seats []string
			switch {
			case r.ManagedPlacement != nil && r.ManagedPlacement.PartitionID != "":
				seats = []string{r.ManagedPlacement.PartitionID}
			case slices.Contains(r.Roles, terrabase.Role):
				seats = []string{terrabase.Role}
			}
			partitions[r.Node] = seats
		}
		return rolloutexec.HostUnits(partitions), nil
	}
}
