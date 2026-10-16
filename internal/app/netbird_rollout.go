package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	local "github.com/TerraScale/ts-orchestrator/internal/netbird/agent"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

const netbirdHold = "netbird"
const netbirdRecordKey = "netbird.rollout"

var netbirdClientRange = netip.MustParsePrefix("10.200.0.0/16")

func (n *netbirdRollout) artifactsInUse(ctx context.Context) ([]delivery.ArtifactUse, error) {
	var uses []delivery.ArtifactUse
	add := func(pin *cellspec.NetBird) {
		if pin != nil {
			for _, digest := range []string{pin.Pin.Archives.Arm64.BinarySHA256, pin.Pin.Archives.AMD64.BinarySHA256} {
				uses = append(uses, delivery.ArtifactUse{Digest: digest, Role: "netbird", Environment: n.cell})
			}
		}
	}
	add(n.services.netbird())
	var record network.Record
	if err := n.load(ctx, netbirdRecordKey, &record); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if record.ID != "" && record.Phase != "done" {
		add(&cellspec.NetBird{Pin: record.Target.Pin})
	}
	return uses, nil
}

func (r *specRegistry) netbird() *cellspec.NetBird {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current.NetBird
}

// A spec amendment cannot abandon a node already drained or changed. Finish
// its persisted target before using the new pin or disabling management.
func (n *netbirdRollout) target(ctx context.Context) (*cellspec.NetBird, error) {
	var record network.Record
	if err := n.load(ctx, netbirdRecordKey, &record); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if record.ID != "" && record.Phase != "done" && (record.Phase != "failed" || !record.RecoveryComplete) {
		return &cellspec.NetBird{Pin: record.Target.Pin, Enrollment: record.Target.Enrollment}, nil
	}
	return n.services.netbird(), nil
}

type netbirdRollout struct {
	cell             string
	fence            *releaseFence
	services         *specRegistry
	nodes            *nodeOps
	key              ed25519.PrivateKey
	cfg              Config
	fleet            oci.Fleet
	artifacts        jetstream.ObjectStore
	conn             *nats.Conn
	runtime          *natscell.Runtime
	managedAddresses map[string]string
	observed         time.Time
	artifactMu       sync.Mutex
	verifiedMetadata [2][]byte
}

func (n *netbirdRollout) load(ctx context.Context, key string, value any) error {
	if key == netbirdRecordKey || strings.HasPrefix(key, "netbird.command.") {
		return n.loadIntent(ctx, key, value)
	}
	return n.fence.loadJSON(ctx, key, value)
}

func (n *netbirdRollout) saveAt(ctx context.Context, epoch uint64, key string, value any) error {
	if !strings.HasPrefix(key, "netbird.status.") {
		return errors.New("NetBird intent requires a conditional authority commit")
	}
	wire, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := n.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = n.fence.kv.Put(ctx, key, wire)
	return err
}

func (n *netbirdRollout) saveRecordAt(ctx context.Context, epoch uint64, state *netbirdState, record network.Record) error {
	if record.Phase == "drain" && len(record.Fence) == 0 {
		spec, addresses := n.addresses()
		if spec == nil || addresses[record.Node] == "" {
			return errors.New("NetBird admission requires a release fence and verified OCI address")
		}
		if err := netbirdOCIAddress(addresses[record.Node]); err != nil {
			return err
		}
		wire, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		record.Fence, record.OCIAddress = wire, addresses[record.Node]
	}
	next := *state
	if next.Record.ID != record.ID || next.Record.Node != record.Node {
		next.Command = network.Command{}
	}
	next.Record = record
	if !netbirdCommandAllowed(record, next.Command.Action) {
		next.Command = network.Command{}
	}
	return n.commitStateAt(ctx, epoch, state, next)
}

func (n *netbirdRollout) refreshInventory(ctx context.Context) error {
	var record network.Record
	if err := n.load(ctx, netbirdRecordKey, &record); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if record.ID == "" || record.Phase == "done" || record.Phase == "failed" && record.RecoveryComplete {
		return n.refreshManaged(ctx)
	}
	if record.OCIAddress != "" {
		if err := netbirdOCIAddress(record.OCIAddress); err != nil {
			return fmt.Errorf("persisted NetBird OCI recovery address is invalid: %w", err)
		}
		inventoryCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := n.refreshManaged(inventoryCtx)
		cancel()
		if err != nil && record.Phase == "drain" {
			return err
		}
		// Peer discovery cannot hold rollback/return of an already drained node.
		if n.managedAddresses == nil {
			n.managedAddresses = map[string]string{}
		}
		n.managedAddresses[record.Node] = record.OCIAddress
		return nil
	}
	return n.refreshRecoveryNode(ctx, record.Node)
}

func (n *netbirdRollout) Exchange(ctx context.Context, registration host.Registration, status network.Status) ([]byte, error) {
	if err := status.Validate(); err != nil {
		return nil, err
	}
	pin, err := n.target(ctx)
	if err != nil {
		return nil, err
	}
	if pin == nil {
		return nil, nil
	}
	epoch, err := n.fence.leading(ctx)
	if err != nil {
		return nil, err
	}
	if !status.ObservedAt.IsZero() && time.Since(status.ObservedAt) < 15*time.Second && time.Until(status.ObservedAt) < 2*time.Second {
		if len(status.Version) > 32 || len(status.IP) > 64 || len(status.DNS) > 255 || len(status.ActionID) > 160 || len(status.Error) > 512 ||
			status.AppliedTargetHash != "" && !client.SHA256Pattern.MatchString(status.AppliedTargetHash) || status.Missing && status.Version != "" {
			return nil, errors.New("invalid NetBird status")
		}
		if err := n.saveAt(ctx, epoch, "netbird.status."+registration.Node, status); err != nil {
			return nil, err
		}
	}
	state, err := n.state(ctx)
	if err != nil {
		return nil, err
	}
	command, found, err := state.commandFor(registration.Node)
	if err != nil || !found {
		return nil, err
	}
	wire, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	step, err := protocol.SignEnvelope(wire, protocol.EnvelopeScope{Region: n.cell, Kind: "netbird.step", Actor: registration.Node,
		OperationID: command.ID, Epoch: epoch, Generation: command.Generation}, now, now.Add(local.StepLifetime), n.key)
	if err != nil {
		return nil, err
	}
	reply, err := json.Marshal(step)
	if err != nil {
		return nil, err
	}
	// Issuance has the same durable order as phase changes and authority
	// handoff; a superseded snapshot must never yield a signed command.
	if err := n.commitStateAt(ctx, epoch, &state, state); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *netbirdRollout) BinaryAllowed(digest string) bool {
	if pin := n.services.netbird(); pin != nil && (pin.Pin.Archives.Arm64.BinarySHA256 == digest || pin.Pin.Archives.AMD64.BinarySHA256 == digest) {
		return true
	}
	// A pin may change during a rollout; its in-flight transaction keeps
	// using the exact admitted bytes until it returns or rolls back.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var record network.Record
	return n.load(ctx, netbirdRecordKey, &record) == nil && record.Phase != "done" && record.Phase != "failed" &&
		(record.Target.Pin.Archives.Arm64.BinarySHA256 == digest || record.Target.Pin.Archives.AMD64.BinarySHA256 == digest)
}

func (n *netbirdRollout) status(ctx context.Context, node string) (network.Status, error) {
	var status network.Status
	if err := n.load(ctx, "netbird.status."+node, &status); err != nil {
		return status, fmt.Errorf("NetBird worker on %s has not reported: %w", node, err)
	}
	if time.Since(status.ObservedAt) > 15*time.Second {
		return status, fmt.Errorf("NetBird worker on %s is stale", node)
	}
	return status, nil
}

func (n *netbirdRollout) addresses() (*cellspec.ReleaseFence, map[string]string) {
	spec, addresses := n.fence.spec()
	for node, address := range n.managedAddresses {
		if addresses[node] == "" {
			addresses[node] = address
		}
	}
	return spec, addresses
}

func (n *netbirdRollout) preflight(ctx context.Context, node string) error {
	if err := n.artifactsReady(ctx); err != nil {
		return err
	}
	spec, addresses, err := n.preflightAddresses(ctx, node)
	if err != nil {
		return err
	}
	if spec == nil || addresses[node] == "" || len(addresses) < 2 {
		return errors.New("NetBird upgrade requires a release fence and at least two granted nodes")
	}
	leader := n.services.controllerNode(n.cell, n.cfg.NATS.Instance)
	probe, err := n.status(ctx, leader)
	if err != nil {
		return err
	}
	if probe.Missing || probe.Version == "" || !probe.Connected {
		return errors.New("NetBird probing leader has no working mesh client; restore verified bootstrap enrollment over OCI before draining")
	}
	// Refuse a cell already being drained by another rollout. Quorum guards
	// in fence.fence still serialize every actual LB removal.
	keys, err := n.fence.keys(ctx, fencedKey("*"))
	if err != nil {
		return err
	}
	for _, key := range keys {
		record, found, err := n.fence.record(ctx, strings.TrimPrefix(key, fencedKey("")))
		if err != nil {
			return err
		}
		if found && slices.ContainsFunc(record.holders(), func(holder string) bool { return holder != netbirdHold }) {
			return fmt.Errorf("NetBird rollout waits for existing fence on %s", strings.TrimPrefix(key, fencedKey("")))
		}
	}
	if n.nodes != nil && n.nodes.cluster != nil {
		if err := n.nodes.cluster(ctx, node); err != nil {
			return err
		}
	}
	// Verify ordinary SSH on the OCI VCN address. We never change sshd,
	// networking, security lists, public IPs or this independent path.
	if err := n.recoverySSH(ctx, node, addresses[node]); err != nil {
		return fmt.Errorf("OCI SSH recovery path for %s is unavailable: %w", node, err)
	}
	selected, err := n.status(ctx, node)
	if err != nil {
		return err
	}
	bootstrapRemote := selected.Missing && selected.Version == "" && node != n.services.controllerNode(n.cell, n.cfg.NATS.Instance)
	for candidate := range addresses {
		status, err := n.status(ctx, candidate)
		if err != nil {
			return err
		}
		if status.Pending != "" || status.Error != "" {
			return fmt.Errorf("NetBird preflight %s has an unresolved worker operation", candidate)
		}
		// Several joining nodes may need their first authenticated install.
		// Only explicit executable absence can skip mesh health; a failed
		// observation of an installed daemon must still hold the rollout.
		if status.Missing && status.Version == "" {
			continue
		}
		// An unchanged installed leader can admit its first missing peer.
		// Confirmation still proves that peer's traffic over the mesh.
		if err := n.healthyMesh(ctx, candidate, status, time.Time{}, !bootstrapRemote); err != nil {
			return fmt.Errorf("NetBird preflight %s: %w", candidate, err)
		}
	}
	return nil
}

func (n *netbirdRollout) artifactsReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	pin, err := n.target(ctx)
	if err != nil {
		return err
	}
	if pin == nil || n.artifacts == nil {
		return errors.New("NetBird artifacts are not configured")
	}
	if n.conn == nil {
		return errors.New("NetBird artifact admission requires the controller's NATS connection")
	}
	js, err := jetstream.New(n.conn)
	if err != nil {
		return err
	}
	legacy, err := n.conn.JetStream()
	if err != nil {
		return err
	}
	binaries := [2]struct{ architecture, digest string }{
		{"arm64", pin.Pin.Archives.Arm64.BinarySHA256},
		{"amd64", pin.Pin.Archives.AMD64.BinarySHA256},
	}
	var metadata [2]*nats.RawStreamMsg
	for i, binary := range binaries {
		name := "sha256-" + binary.digest
		subject := "$O." + delivery.ArtifactBucket + ".M." + base64.URLEncoding.EncodeToString([]byte(name))
		meta, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, subject, nats.Context(ctx))
		if err != nil {
			return fmt.Errorf("NetBird artifact %s is not staged; no node will be drained: %w", binary.digest, err)
		}
		var info jetstream.ObjectInfo
		if json.Unmarshal(meta.Data, &info) != nil || info.Name != name || info.Bucket != delivery.ArtifactBucket ||
			info.Deleted || info.Size < 64 || info.Size > client.MaxBinaryBytes {
			return fmt.Errorf("NetBird artifact %s is not staged; no node will be drained", binary.digest)
		}
		n.artifactMu.Lock()
		// Object-store writes replace metadata for changed chunks; direct
		// administrative chunk mutation must not bypass that contract.
		verified := bytes.Equal(n.verifiedMetadata[i], meta.Data)
		n.artifactMu.Unlock()
		if !verified {
			if err := verifyNetBirdArtifactContents(ctx, binary.digest, binary.architecture, func(dst io.Writer) error {
				return artifact.ReadVerifiedAuthoritative(ctx, js, &info, delivery.ArtifactBucket, name, binary.digest,
					int64(info.Size), client.MaxBinaryBytes, dst)
			}); err != nil {
				return fmt.Errorf("verify NetBird artifact %s (%s) before drain: %w", binary.digest, binary.architecture, err)
			}
			n.artifactMu.Lock()
			n.verifiedMetadata[i] = meta.Data
			n.artifactMu.Unlock()
		}
		metadata[i] = meta
	}
	// Fence collectors that selected these objects before the pin became active.
	for i, binary := range binaries {
		if err := artifact.Touch(ctx, legacy, delivery.ArtifactBucket, "sha256-"+binary.digest); err != nil {
			return fmt.Errorf("retain NetBird artifact %s before drain: %w", binary.digest, err)
		}
		meta, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, metadata[i].Subject, nats.Context(ctx))
		if err != nil {
			return err
		}
		// Touch keeps the bytes unchanged; replacement requires fresh verification.
		if !bytes.Equal(meta.Data, metadata[i].Data) {
			return fmt.Errorf("retain NetBird artifact %s before drain: %w", binary.digest, artifact.ErrChanged)
		}
	}
	return ctx.Err()
}

// healthy proves a DNS answer and service traffic on the actual mesh IP;
// OCI connectivity and local ready reports alone cannot confirm an upgrade.
func (n *netbirdRollout) healthy(ctx context.Context, node string, status network.Status, since time.Time) error {
	return n.healthyMesh(ctx, node, status, since, true)
}

func (n *netbirdRollout) healthyMesh(ctx context.Context, node string, status network.Status, since time.Time, verifyLeaderPeer bool) error {
	address, err := netip.ParseAddr(status.IP)
	if !status.Connected || err != nil || !netbirdClientRange.Contains(address) || !strings.HasSuffix(status.DNS, ".nb.ts.internal") || len(status.DNS) > 255 {
		return errors.New("NetBird management, signal, mesh IP and peer DNS name are not ready")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// The leader's own mesh address is locally routed. Prove a remote peer
	// too, so an isolated leader cannot confirm itself using loopback traffic.
	if verifyLeaderPeer && node == n.services.controllerNode(n.cell, n.cfg.NATS.Instance) {
		_, addresses := n.addresses()
		peers := make([]string, 0, len(addresses))
		for peer := range addresses {
			if peer != node && n.nodes != nil && n.nodes.controllers != nil && n.nodes.controllers(peer) {
				peers = append(peers, peer)
			}
		}
		slices.Sort(peers)
		if len(peers) == 0 {
			return errors.New("NetBird leader has no remote controller peer to verify")
		}
		if err := n.healthyRemotePeer(ctx, peers); err != nil {
			return err
		}
	}
	answers, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", status.DNS)
	if err != nil || !slices.Contains(answers, address) {
		return errors.New("NetBird DNS answer does not contain the peer's mesh IP")
	}
	if reason, err := nodeRolesServing(ctx, n.fence.hosts, node, since); err != nil || reason != "" {
		return fmt.Errorf("node roles are not ready: %s%v", reason, errSuffix(err))
	}
	_, addresses := n.addresses()
	statuses, err := n.fence.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	found, probed := false, false
	for _, entry := range statuses {
		if entry.Registration.Node != node {
			continue
		}
		found = true
		for _, role := range entry.Registration.Roles {
			desired, err := n.fence.hosts.ListDesired(ctx, role)
			if err != nil {
				return err
			}
			index := slices.IndexFunc(desired, func(d host.Desired) bool { return d.Node == node && !d.Withdrawn })
			if index < 0 {
				continue
			}
			switch role {
			case tsauth.Role:
				if err := meshReady(ctx, status.IP, tsauth.Port, nil); err != nil {
					return fmt.Errorf("ts-auth over NetBird: %w", err)
				}
				probed = true
			case terrabase.Role:
				profile, err := terrabase.ParseProfile(desired[index].Env)
				if err != nil {
					return err
				}
				pem, err := os.ReadFile(n.cfg.Controller.TerraBaseCACertFile)
				if err != nil {
					return err
				}
				roots := x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return errors.New("invalid TerraBase CA")
				}
				if err := meshReady(ctx, status.IP, profile.ClientPort, &tls.Config{RootCAs: roots, ServerName: addresses[node], MinVersion: tls.VersionTLS12}); err != nil {
					return fmt.Errorf("TerraBase over NetBird: %w", err)
				}
				probed = true
			}
		}
	}
	if !found {
		return errors.New("node has no registered host session")
	}
	if n.nodes != nil && n.nodes.controllers != nil && n.nodes.controllers(node) {
		options := []nats.Option{nats.Timeout(3 * time.Second), nats.NoReconnect(), nats.TLSHandshakeFirst(),
			nats.RootCAs(n.cfg.NATS.TLS.CAFile), nats.ClientCert(n.cfg.NATS.TLS.CertFile, n.cfg.NATS.TLS.KeyFile),
			nats.SetCustomDialer(meshDialer{ctx: ctx, address: net.JoinHostPort(status.IP, "4222")}),
			nats.ErrorHandler(natscell.ErrorHandler)}
		if n.cfg.NATS.CredentialsFile != "" {
			options = append(options, nats.UserCredentials(n.cfg.NATS.CredentialsFile))
		} else {
			option, err := nats.NkeyOptionFromSeed(n.cfg.NATS.NKeySeedFile)
			if err != nil {
				return err
			}
			options = append(options, option)
		}
		conn, err := nats.Connect("tls://"+net.JoinHostPort(addresses[node], "4222"), options...)
		if err != nil {
			return errors.New("authenticated NATS over NetBird is unavailable")
		}
		defer conn.Close()
		if err := conn.FlushWithContext(ctx); err != nil {
			return err
		}
		probed = true
	}
	if !probed {
		return errors.New("NetBird peer has no active service endpoint to verify mesh traffic")
	}
	return nil
}

type meshDialer struct {
	ctx     context.Context
	address string
}

func (d meshDialer) Dial(network, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(d.ctx, network, d.address)
}

func meshReady(ctx context.Context, address string, port int, secure *tls.Config) error {
	if port < 1 || port > 65535 {
		return errors.New("mesh readiness port is not configured")
	}
	transport := &http.Transport{TLSClientConfig: secure}
	defer transport.CloseIdleConnections()
	scheme := "http"
	if secure != nil {
		scheme = "https"
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(address, strconv.Itoa(port))+"/readyz", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("mesh readiness HTTP %d", response.StatusCode)
	}
	return nil
}

func (n *netbirdRollout) run(ctx context.Context) {
	var epoch uint64
	var state netbirdState
	reconciler := network.Reconciler{
		Load: func(ctx context.Context) (network.Record, error) {
			var err error
			state, err = n.state(ctx)
			return state.Record, err
		},
		Save: func(ctx context.Context, record network.Record) error {
			return n.saveRecordAt(ctx, epoch, &state, record)
		},
		Status: n.status, Preflight: n.preflight, Healthy: n.healthy,
		Drain: func(ctx context.Context, node string) error {
			return n.drainNode(ctx, epoch, node)
		},
		Return: func(ctx context.Context, node string) error {
			return n.returnNode(ctx, epoch, node)
		},
		Send: func(ctx context.Context, node string, command network.Command) error {
			return n.sendAt(ctx, epoch, &state, node, command)
		},
	}
	last := ""
	for ctx.Err() == nil {
		if n.fence.fencer.Current().CanMutate() {
			epoch = n.fence.fencer.Current().Epoch
			if pin, err := n.target(ctx); err != nil {
				if err.Error() != last {
					slog.WarnContext(ctx, "NetBird transaction held", "error", err)
					last = err.Error()
				}
			} else if pin != nil {
				if err := n.refreshInventory(ctx); err != nil {
					if err.Error() != last {
						slog.WarnContext(ctx, "NetBird inventory held", "error", err)
						last = err.Error()
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
						continue
					}
				}
				_, addresses := n.addresses()
				nodes := make([]string, 0, len(addresses))
				for node := range addresses {
					nodes = append(nodes, node)
				}
				nodes = n.orderNodes(nodes)
				err := reconciler.Tick(ctx, network.Target{Pin: pin.Pin, Enrollment: pin.Enrollment}, nodes)
				if err != nil && err.Error() != last {
					slog.WarnContext(ctx, "NetBird rollout held", "error", err)
					last = err.Error()
				}
				if err == nil {
					last = ""
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (n *netbirdRollout) drainNode(ctx context.Context, epoch uint64, node string) error {
	// Bound the journal read too, before the admitted grace is known.
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var record network.Record
	if err := n.load(readCtx, netbirdRecordKey, &record); err != nil {
		return err
	}
	if record.Node != node || record.Deadline.IsZero() {
		return errors.New("NetBird drain requires this node's persisted phase deadline")
	}
	spec, addresses := n.addresses()
	address := addresses[node]
	if len(record.Fence) > 0 {
		admitted, err := netbirdAdmittedFence(record)
		if err != nil {
			return err
		}
		spec, address = admitted, record.OCIAddress
	}
	if spec == nil || address == "" {
		return errors.New("NetBird recovery has no admitted release fence or OCI address")
	}
	grace := durationOr(spec.DrainGraceSeconds, defaultFenceGrace)
	deadline := time.Now().Add(grace + 30*time.Second)
	ctx, cancelDrain := context.WithDeadline(ctx, deadline)
	defer cancelDrain()
	// Recovery must remain retryable after quorum repairs, even when its
	// previous acknowledgment deadline expired while waiting to re-drain.
	if record.Phase == "drain" && record.Deadline.Before(deadline) {
		var cancelPhase context.CancelFunc
		ctx, cancelPhase = context.WithDeadline(ctx, record.Deadline)
		defer cancelPhase()
	}
	if err := n.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	api, err := n.fence.client(ctx)
	if err != nil {
		return err
	}
	return n.fence.fence(ctx, api, epoch, *spec, node, address, grace, netbirdHold)
}

func (n *netbirdRollout) returnNode(ctx context.Context, epoch uint64, node string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := n.fence.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	// A first-install rollback restores absence, but workloads must still
	// report ready over OCI before their backends return to rotation.
	if reason, err := nodeRolesServing(ctx, n.fence.hosts, node, time.Time{}); err != nil || reason != "" {
		return fmt.Errorf("node roles are not ready: %s%v", reason, errSuffix(err))
	}
	statuses, err := n.fence.hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(statuses, func(status host.HostStatus) bool { return status.Registration.Node == node }) {
		return errors.New("node has no registered host session")
	}
	api, err := n.fence.client(ctx)
	if err != nil {
		return err
	}
	_, err = n.fence.restore(ctx, api, epoch, node, netbirdHold, true)
	return err
}

func hostNetBird(cfg Config, public ed25519.PublicKey) func(context.Context, host.NetBirdSession) {
	if cfg.NATS.Lab {
		return nil
	}
	settings := local.Config{Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Controller: public, Directory: filepath.Join(cfg.Host.StateRoot, cfg.NATS.Cell, cfg.Host.Node, "netbird")}
	return func(ctx context.Context, session host.NetBirdSession) {
		last := ""
		for ctx.Err() == nil && !session.SessionLost() {
			status, err := local.ReadStatus(settings.Directory)
			if err == nil {
				var step host.NetBirdStep
				step, err = session.NetBirdExchange(ctx, status)
				if err == nil && len(step.Step) > 0 {
					err = local.Relay(ctx, settings, step.Step, session.FetchNetBirdBinary)
				}
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) && err.Error() != last {
				slog.WarnContext(ctx, "NetBird relay held", "node", settings.Node, "error", err)
				last = err.Error()
			} else if err == nil {
				last = ""
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}
