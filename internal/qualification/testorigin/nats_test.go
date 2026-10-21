package testorigin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const natsWorldInputLimit = 4 << 20
const natsWorldStoreRoot = "/run/ts-orchestrator-test-origin/nats"
const natsWorldCommand = "test-origin-nats-world"

// Material is supplied, not generated or installed here. TargetFile is the
// exact basename in the signed Vault reference, not a replacement pathname.
type natsWire struct {
	SchemaVersion int                  `json:"schemaVersion"`
	DeploymentID  string               `json:"deploymentId"`
	CandidateID   string               `json:"candidateId"`
	Brokers       []natscell.Config    `json:"brokers"`
	Material      []ociVaultEntry      `json:"material"`
	TicketKeyFile string               `json:"ticketKeyFile"`
	Roster        globalcontrol.Roster `json:"roster"`
}

type natsMaterialEvidence struct {
	SecretID      string   `json:"secretId"`
	VersionNumber int64    `json:"versionNumber"`
	VersionName   string   `json:"versionName"`
	Stages        []string `json:"stages"`
	TargetFile    string   `json:"targetFile"`
	SHA256        string   `json:"sha256"`
}

type natsEvidence struct {
	ServiceUID     uint32                        `json:"serviceUid"`
	ServiceGID     uint32                        `json:"serviceGid"`
	Clusters       []natscell.ClusterObservation `json:"clusters"`
	Bridges        []natscell.BridgeStatus       `json:"bridges"`
	Regional       authority.Snapshot            `json:"regional"`
	Global         authority.Snapshot            `json:"global"`
	RosterSequence uint64                        `json:"rosterSequence"`
	HomeTerm       uint64                        `json:"homeTerm"`
	ClaimSequence  uint64                        `json:"claimSequence"`
	ClaimSHA256    string                        `json:"claimSha256"`
	Material       []natsMaterialEvidence        `json:"material"`
}

type natsWorld struct {
	ctx      context.Context
	cancel   context.CancelFunc
	wire     natsWire
	brokers  []*natscell.Runtime
	regional *authority.Runtime
	global   *authority.Runtime
	home     *globalcontrol.Writer
	store    *brokerauth.Store
	readers  []*brokerauth.Store
	applied  []uint64
	issuer   *brokerauth.Issuer
	public   ed25519.PublicKey
	workers  sync.WaitGroup
	once     sync.Once
	mu       sync.Mutex
	failed   error
	closeErr error
	child    *natsWorldProcess
}

type natsWorldProcess struct {
	input  io.WriteCloser
	output *bufio.Reader
	done   chan struct{}
	err    error
}

func startNATSWorld(ctx context.Context, wire []byte) (_ *natsWorld, err error) {
	if os.Geteuid() != 0 {
		return startNATSWorldLocal(ctx, wire)
	}
	world := &natsWorld{}
	if ctx == nil || ctx.Err() != nil || protocol.DecodeStrict(wire, &world.wire, natsWorldInputLimit) != nil {
		for index := range world.wire.Material {
			clear(world.wire.Material[index].Contents)
		}
		return nil, errors.New("invalid test-origin NATS process input")
	}
	world.ctx, world.cancel = context.WithCancel(ctx)
	defer func() {
		if err != nil {
			err = errors.Join(err, world.Close())
		}
	}()
	if err := world.wire.validate(); err != nil {
		return nil, err
	}
	childInput, err := json.Marshal(world.wire)
	if err != nil || len(childInput) >= natsWorldInputLimit {
		clear(childInput)
		return nil, errors.New("test-origin NATS child input exceeds its bound")
	}
	defer clear(childInput)
	uid, gid, err := natsWorldServiceIdentity()
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(world.ctx, "/proc/self/exe", natsWorldCommand)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	command.Cancel = func() error {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	command.WaitDelay = 5 * time.Second
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	world.child = &natsWorldProcess{input: input,
		output: bufio.NewReaderSize(output, fixtureOutputLimit+1), done: make(chan struct{})}
	go func() {
		world.child.err = command.Wait()
		close(world.child.done)
	}()
	if n, err := input.Write(childInput); err != nil || n != len(childInput) {
		return nil, errors.New("test-origin NATS child input write failed")
	}
	if _, err := input.Write([]byte{'\n'}); err != nil {
		return nil, err
	}
	if _, err := world.readChildEvidence(); err != nil {
		return nil, err
	}
	return world, nil
}

func natsWorldServiceIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return 0, 0, errors.New("dedicated NATS service identity is unavailable")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return 0, 0, errors.New("dedicated NATS service identity is invalid")
	}
	return uint32(uid), uint32(gid), nil
}

// The same measured test ELF owns all brokers under the real service account.
// EOF is normal shutdown; every reply is freshly read production state.
func runNATSWorldChild(ctx context.Context, stdin io.Reader, stdout io.Writer) int {
	if err := serveNATSWorldChild(ctx, stdin, stdout); err != nil {
		return 1
	}
	return 0
}

func serveNATSWorldChild(ctx context.Context, stdin io.Reader, stdout io.Writer) (err error) {
	uid, gid, err := natsWorldServiceIdentity()
	if err != nil || os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return errors.New("test-origin NATS child lacks the dedicated service identity")
	}
	closer, ok := stdin.(io.Closer)
	if !ok || ctx == nil {
		return errors.New("test-origin NATS child requires an owned input pipe")
	}
	input := bufio.NewReaderSize(stdin, natsWorldInputLimit+1)
	stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
	defer stop()
	wire, err := input.ReadSlice('\n')
	if err != nil || len(wire) > natsWorldInputLimit {
		clear(wire)
		return errors.New("invalid test-origin NATS child input")
	}
	world, err := startNATSWorldLocal(ctx, wire)
	clear(wire)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, world.Close()) }()
	stopWorld := context.AfterFunc(world.ctx, func() { _ = closer.Close() })
	defer stopWorld()
	reply := func() error {
		evidence, err := world.Evidence()
		if err != nil {
			return err
		}
		wire, err := json.Marshal(evidence)
		if err != nil || len(wire) >= fixtureOutputLimit {
			return errors.New("test-origin NATS evidence exceeds its bound")
		}
		wire = append(wire, '\n')
		if n, err := stdout.Write(wire); err != nil || n != len(wire) {
			return errors.New("test-origin NATS evidence write failed")
		}
		return nil
	}
	if err := reply(); err != nil {
		return err
	}
	for {
		command, err := input.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(command) == 0 {
			return world.ctx.Err()
		}
		if err != nil || !bytes.Equal(command, []byte("evidence\n")) {
			return errors.New("invalid test-origin NATS child request")
		}
		if err := reply(); err != nil {
			return err
		}
	}
}

func (world *natsWorld) readChildEvidence() (natsEvidence, error) {
	var evidence natsEvidence
	wire, err := world.child.output.ReadSlice('\n')
	if err != nil || protocol.DecodeStrict(wire, &evidence, fixtureOutputLimit) != nil {
		return evidence, errors.New("test-origin NATS service evidence is unavailable")
	}
	if err := world.ctx.Err(); err != nil {
		return natsEvidence{}, err
	}
	return evidence, nil
}

func startNATSWorldLocal(ctx context.Context, wire []byte) (_ *natsWorld, err error) {
	uid, gid, err := natsWorldServiceIdentity()
	if err != nil || os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return nil, errors.New("test-origin NATS constructor requires the dedicated service identity")
	}
	world := &natsWorld{}
	if ctx == nil || ctx.Err() != nil || protocol.DecodeStrict(wire, &world.wire, natsWorldInputLimit) != nil {
		for index := range world.wire.Material {
			clear(world.wire.Material[index].Contents)
		}
		return nil, errors.New("invalid test-origin NATS input")
	}
	world.ctx, world.cancel = context.WithCancel(ctx)
	defer func() {
		if err != nil {
			err = errors.Join(err, world.Close())
		}
	}()
	if err := world.wire.validate(); err != nil {
		return nil, err
	}
	if err := world.checkMaterial(); err != nil {
		return nil, err
	}
	if err := natsWorldClockCheck(); err != nil {
		return nil, err
	}
	for _, cfg := range world.wire.Brokers {
		if err := natscell.ValidateBrokerControllerCredentials(cfg.CredentialsFile, cfg.Cell, cfg.Instance); err != nil {
			return nil, err
		}
		if err := natscell.ValidateGlobalControllerPermissions(cfg); err != nil {
			return nil, err
		}
		broker, err := natscell.Start(world.ctx, cfg)
		if err != nil {
			return nil, err
		}
		world.brokers = append(world.brokers, broker)
	}
	for _, broker := range world.brokers {
		if err := broker.WaitForCluster(world.ctx, 3); err != nil {
			return nil, err
		}
	}
	if err := world.waitFullCluster(); err != nil {
		return nil, err
	}
	js := world.brokers[0].JetStream()
	world.regional, err = authority.Start(world.ctx, js, authority.Config{
		Scope: "gru", DeploymentID: world.wire.DeploymentID, CandidateID: world.wire.CandidateID,
		Replicas: 3, ClockCheck: natsWorldClockCheck,
	})
	if err != nil {
		return nil, err
	}
	world.global, err = authority.Start(world.ctx, js, authority.Config{
		Scope: protocol.GlobalScope, DeploymentID: world.wire.DeploymentID, CandidateID: world.wire.CandidateID,
		Replicas: 3, ClockCheck: natsWorldClockCheck,
	})
	if err != nil {
		return nil, err
	}
	if !world.regional.Current().CanMutate() || !world.global.Current().CanMutate() {
		return nil, authority.ErrNotLeader
	}
	world.home, err = globalcontrol.OpenHome(world.ctx, js, "gru", []string{"fra", "sjc"}, 3, world.global)
	if err != nil {
		return nil, err
	}
	if _, err := world.home.PutRoster(world.ctx, world.global.Current().Epoch, world.wire.Roster); err != nil {
		return nil, err
	}
	if err := world.startBrokerTickets(); err != nil {
		return nil, err
	}
	world.workers.Go(func() {
		defer world.fenceBridges()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-world.ctx.Done():
				return
			case <-ticker.C:
				if err := world.checkMaterial(); err != nil {
					world.fail(err)
					return
				}
				if err := world.renewBrokerTickets(); err != nil {
					world.fail(err)
					return
				}
			}
		}
	})
	return world, nil
}

func (wire natsWire) validate() error {
	if wire.SchemaVersion != 1 || !entityid.Valid(wire.DeploymentID) || !entityid.Valid(wire.CandidateID) ||
		len(wire.Brokers) != 3 || len(wire.Material) == 0 || len(wire.Material) > 64 ||
		wire.TicketKeyFile != filepath.Join(bootstrap.MaterialDirectory, "ticket.key") ||
		wire.Roster.Validate() != nil || wire.Roster.HomeRegion != "gru" || wire.Roster.Generation != 1 ||
		!slices.Equal(wire.Roster.Regions, []globalcontrol.RosterEntry{
			{Cell: "fra", OCIRegion: "eu-frankfurt-1", State: globalcontrol.RegionActive},
			{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive},
			{Cell: "sjc", OCIRegion: "us-sanjose-1", State: globalcontrol.RegionActive},
		}) {
		return errors.New("test-origin NATS requires the fixed GRU/SJC/FRA R3 world")
	}
	material := make(map[string]bool, len(wire.Material))
	for _, entry := range wire.Material {
		if entry.SecretID == "" || entry.VersionNumber <= 0 || len(entry.Stages) == 0 ||
			entry.TargetFile == "" || entry.TargetFile == "." || filepath.Base(entry.TargetFile) != entry.TargetFile ||
			strings.ContainsAny(entry.TargetFile, "/\\") || len(entry.Contents) == 0 || len(entry.Contents) > 64<<10 || material[entry.TargetFile] {
			return errors.New("invalid or duplicate exact NATS Vault material")
		}
		material[entry.TargetFile] = true
	}
	used := make(map[string]bool, len(material))
	use := func(path string) bool {
		base := filepath.Base(path)
		if path != filepath.Join(bootstrap.MaterialDirectory, base) || !material[base] {
			return false
		}
		used[base] = true
		return true
	}
	if !use(wire.TicketKeyFile) {
		return errors.New("broker ticket signer lacks its exact Vault material")
	}
	ids := make([]string, 0, 3)
	routes := make([]string, 0, 3)
	ports := make(map[int]bool, 6)
	for _, cfg := range wire.Brokers {
		e := cfg.Embedded
		if cfg.Cell != "gru" || cfg.Replicas != 3 || cfg.ClientRole != "controller" || cfg.NKeySeedFile != "" ||
			cfg.Instance == "" || len(cfg.Instance) > 63 || filepath.Base(cfg.Instance) != cfg.Instance ||
			slices.Contains(ids, cfg.Instance) || e == nil || e.Host != "127.0.0.1" || e.RouteHost != "127.0.0.1" ||
			e.Port <= 0 || e.Port > 65535 || e.RoutePort <= 0 || e.RoutePort > 65535 || e.Port == e.RoutePort ||
			ports[e.Port] || ports[e.RoutePort] || e.StoreDir != filepath.Join(natsWorldStoreRoot, cfg.Instance) ||
			e.StoreMaxBytes != 0 || len(e.Users) != 0 || e.InterRegion != nil || e.Link != nil ||
			e.RouteUser == "" || len(cfg.OperatorForward) != 0 || cfg.ReloadClientMaterial != nil ||
			cfg.URL != "tls://127.0.0.1:"+strconv.Itoa(e.Port) {
			return errors.New("invalid test-origin production broker topology")
		}
		ports[e.Port], ports[e.RoutePort] = true, true
		ids = append(ids, cfg.Instance)
		routes = append(routes, "nats-route://127.0.0.1:"+strconv.Itoa(e.RoutePort))
		paths := []string{cfg.CredentialsFile, cfg.TLS.CAFile, cfg.TLS.CertFile, cfg.TLS.KeyFile,
			e.TLS.CAFile, e.TLS.CertFile, e.TLS.KeyFile, e.RouteTLS.CAFile, e.RouteTLS.CertFile, e.RouteTLS.KeyFile,
			e.RoutePasswordFile, e.OperatorJWTFile, e.SystemJWTFile, e.CellJWTFile, e.SystemCredentialsFile, e.TicketPublicKeyFile}
		if e.MembershipCredentialsFile != "" {
			paths = append(paths, e.MembershipCredentialsFile)
		}
		for _, path := range paths {
			if !use(path) {
				return errors.New("broker material path lacks its exact installed Vault reference")
			}
		}
	}
	for index, cfg := range wire.Brokers {
		e, first := cfg.Embedded, wire.Brokers[0].Embedded
		if !slices.Equal(e.BrokerIDs, ids) || !slices.Equal(e.Routes, natscell.PeerRoutes(routes, routes[index])) ||
			e.OperatorJWTFile != first.OperatorJWTFile || e.SystemJWTFile != first.SystemJWTFile || e.CellJWTFile != first.CellJWTFile ||
			e.RoutePasswordFile != first.RoutePasswordFile || e.RouteUser != first.RouteUser || e.TicketPublicKeyFile != first.TicketPublicKeyFile {
			return errors.New("broker topology or shared signed account material differs")
		}
	}
	if len(used) != len(material) {
		return errors.New("NATS Vault material contains an unconsumed file")
	}
	return nil
}

func natsWorldClockCheck() error {
	_, err := brokerauth.MeasureHealthyClock(brokerauth.KernelClockProbe{})
	return err
}

func (world *natsWorld) checkMaterial() error {
	root, err := os.OpenRoot(bootstrap.MaterialDirectory)
	if err != nil {
		return errors.New("test-origin NATS installed material directory is unavailable")
	}
	defer root.Close()
	for _, entry := range world.wire.Material {
		file, err := root.OpenFile(entry.TargetFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("test-origin NATS exact installed material is unavailable")
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(len(entry.Contents)) {
			_ = file.Close()
			return errors.New("test-origin NATS installed material type, mode or size differs")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) || stat.Nlink != 1 {
			_ = file.Close()
			return errors.New("test-origin NATS installed material owner or link count differs")
		}
		value, readErr := io.ReadAll(io.LimitReader(file, 64<<10+1))
		afterInfo, afterErr := file.Stat()
		stable := false
		if afterErr == nil {
			if after, ok := afterInfo.Sys().(*syscall.Stat_t); ok {
				stable = stat.Dev == after.Dev && stat.Ino == after.Ino && stat.Mode == after.Mode &&
					stat.Uid == after.Uid && stat.Gid == after.Gid && stat.Nlink == after.Nlink &&
					stat.Size == after.Size && stat.Mtim == after.Mtim && stat.Ctim == after.Ctim
			}
		}
		current, pathErr := root.Lstat(entry.TargetFile)
		stable = stable && pathErr == nil && os.SameFile(info, current)
		closeErr := file.Close()
		equal := bytes.Equal(value, entry.Contents)
		clear(value)
		if readErr != nil || closeErr != nil || !stable || !equal {
			return errors.New("test-origin NATS installed material differs from its exact Vault version")
		}
	}
	return nil
}

func (world *natsWorld) waitFullCluster() error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		for _, broker := range world.brokers {
			ready = ready && broker.FullClusterReady(3)
		}
		if ready {
			return nil
		}
		select {
		case <-world.ctx.Done():
			return world.ctx.Err()
		case <-ticker.C:
		}
	}
}

func (world *natsWorld) materialBytes(path string) []byte {
	for _, entry := range world.wire.Material {
		if path == filepath.Join(bootstrap.MaterialDirectory, entry.TargetFile) {
			return entry.Contents
		}
	}
	return nil
}

func (world *natsWorld) startBrokerTickets() error {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(world.materialBytes(world.wire.TicketKeyFile))))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return errors.New("test-origin broker ticket signer is unavailable")
	}
	// Keep the supplied key only for genuine Issuer.Issue calls; Close wipes it.
	world.issuer = &brokerauth.Issuer{Key: ed25519.PrivateKey(key), Clock: brokerauth.KernelClockProbe{}}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(world.materialBytes(world.wire.Brokers[0].Embedded.TicketPublicKeyFile))))
	if err != nil || len(public) != ed25519.PublicKeySize || !bytes.Equal(public, key[ed25519.SeedSize:]) {
		return errors.New("test-origin broker ticket signer differs from the pinned public key")
	}
	world.public = ed25519.PublicKey(public)
	account := world.brokers[0].CellAccount()
	world.store, err = brokerauth.OpenStore(world.ctx, world.brokers[0].JetStream(), "gru", world.regional)
	if err != nil {
		return err
	}
	world.issuer.Store, world.issuer.Account = world.store, account
	world.issuer.Brokers = make(map[string]struct{}, 3)
	for index, broker := range world.brokers {
		if broker.CellAccount() != account || broker.InitialCellJWT() != world.brokers[0].InitialCellJWT() {
			return errors.New("test-origin broker initial signed account claims differ")
		}
		reader, err := brokerauth.OpenStore(world.ctx, broker.JetStream(), "gru", nil)
		if err != nil {
			return err
		}
		world.readers = append(world.readers, reader)
		world.applied = append(world.applied, 0)
		world.issuer.Brokers[world.wire.Brokers[index].Instance] = struct{}{}
	}
	claim, err := world.store.Read(world.ctx, account)
	if errors.Is(err, brokerauth.ErrNoClaim) {
		claim, err = world.store.Commit(world.ctx, world.regional.Current().Epoch, account, world.brokers[0].InitialCellJWT(), 0)
	}
	if err != nil {
		return err
	}
	if claim.JWT != world.brokers[0].InitialCellJWT() {
		return errors.New("existing durable broker claim differs from supplied material")
	}
	return world.renewBrokerTickets()
}

func (world *natsWorld) renewBrokerTickets() error {
	if err := natsWorldClockCheck(); err != nil {
		return err
	}
	for index, broker := range world.brokers {
		claim, err := world.readers[index].Read(world.ctx, world.issuer.Account)
		if err != nil {
			return err
		}
		if claim.JWT != broker.InitialCellJWT() {
			return brokerauth.ErrClaimChanged
		}
		if world.applied[index] != claim.Sequence {
			if err := broker.ApplyCellClaim(world.ctx, claim.Sequence, claim.JWT); err != nil {
				return err
			}
			world.applied[index] = claim.Sequence
		}
		request, err := brokerauth.NewRequest("gru", world.wire.Brokers[index].Instance, world.issuer.Account)
		if err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(world.ctx, brokerauth.MaxTicketRoundTrip)
		started := time.Now()
		signed, issueErr := world.issuer.Issue(requestCtx, request)
		finished := time.Now()
		cancel()
		if issueErr != nil {
			return issueErr
		}
		current, err := world.readers[index].Read(world.ctx, world.issuer.Account)
		if err != nil {
			return err
		}
		lease, err := authority.Observe(world.ctx, broker.JetStream(), "gru")
		if err != nil {
			return err
		}
		bound, err := brokerauth.MeasureHealthyClock(brokerauth.KernelClockProbe{})
		if err != nil {
			return err
		}
		_, deadline, err := brokerauth.VerifyTicket(signed, world.public, request, started, finished, bound, current, lease)
		if err != nil {
			return err
		}
		if lease.DeploymentID != world.wire.DeploymentID || current.Sequence != claim.Sequence || current.JWT != claim.JWT || broker.Bridge() == nil {
			return authority.ErrFenced
		}
		if err := broker.Bridge().OpenUntil(current.Sequence, current.JWT, deadline); err != nil {
			return err
		}
	}
	return nil
}

func (world *natsWorld) Material() []ociVaultEntry {
	world.mu.Lock()
	defer world.mu.Unlock()
	entries := slices.Clone(world.wire.Material)
	for index := range entries {
		entries[index].Contents = bytes.Clone(entries[index].Contents)
		entries[index].Stages = slices.Clone(entries[index].Stages)
	}
	return entries
}

func (world *natsWorld) Evidence() (natsEvidence, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	if world.child != nil {
		if n, err := world.child.input.Write([]byte("evidence\n")); err != nil || n != len("evidence\n") {
			return natsEvidence{}, errors.New("test-origin NATS service evidence request failed")
		}
		return world.readChildEvidence()
	}
	var result natsEvidence
	if world.failed != nil {
		return result, world.failed
	}
	if err := world.ctx.Err(); err != nil {
		return result, err
	}
	if err := world.checkMaterial(); err != nil {
		return result, err
	}
	if err := world.regional.Guard(world.ctx, world.regional.Current().Epoch); err != nil {
		return result, err
	}
	if err := world.global.Guard(world.ctx, world.global.Current().Epoch); err != nil {
		return result, err
	}
	for _, broker := range world.brokers {
		observation, err := broker.ObserveCluster()
		if err != nil || !observation.Running || observation.MetaSize != 3 || observation.MetaLeader == "" ||
			len(observation.ExpectedPeers) != 3 || len(observation.Routes) != 2 || !broker.FullClusterReady(3) {
			return result, errors.New("test-origin NATS full R3 cluster evidence is unavailable")
		}
		bridge := broker.Bridge().Status()
		if !bridge.Open {
			return result, errors.New("test-origin broker verified ticket is unavailable")
		}
		result.Clusters = append(result.Clusters, observation)
		result.Bridges = append(result.Bridges, bridge)
	}
	roster, sequence, err := world.home.Roster(world.ctx)
	if err != nil || roster.Generation != world.wire.Roster.Generation || roster.HomeRegion != "gru" ||
		!slices.Equal(roster.Regions, world.wire.Roster.Regions) || sequence == 0 {
		return result, errors.New("test-origin HOME roster readback differs")
	}
	term, err := world.home.Term(world.ctx)
	if err != nil || term != world.global.Current().Epoch {
		return result, errors.New("test-origin HOME term differs from the live global authority")
	}
	claim, err := world.store.Read(world.ctx, world.issuer.Account)
	if err != nil {
		return result, err
	}
	for _, bridge := range result.Bridges {
		if bridge.ClaimSequence != claim.Sequence || bridge.JWTHash != claim.Hash {
			return result, errors.New("test-origin broker tickets differ from the durable claim")
		}
	}
	result.Regional, result.Global = world.regional.Current(), world.global.Current()
	result.ServiceUID, result.ServiceGID = uint32(os.Getuid()), uint32(os.Getgid())
	result.RosterSequence, result.HomeTerm = sequence, term
	result.ClaimSequence, result.ClaimSHA256 = claim.Sequence, claim.Hash
	for _, entry := range world.wire.Material {
		digest := sha256.Sum256(entry.Contents)
		result.Material = append(result.Material, natsMaterialEvidence{
			SecretID: entry.SecretID, VersionNumber: entry.VersionNumber, VersionName: entry.VersionName,
			Stages: slices.Clone(entry.Stages), TargetFile: entry.TargetFile, SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if err := world.ctx.Err(); err != nil {
		return natsEvidence{}, err
	}
	return result, nil
}

func (world *natsWorld) fail(err error) {
	world.cancel()
	world.mu.Lock()
	world.failed = errors.Join(world.failed, err)
	world.mu.Unlock()
}

func (world *natsWorld) fenceBridges() {
	for _, broker := range world.brokers {
		if broker.Bridge() != nil {
			broker.Bridge().Fence()
		}
	}
}

func (world *natsWorld) Close() error {
	if world == nil {
		return nil
	}
	world.once.Do(func() {
		if world.child != nil {
			world.mu.Lock()
			defer world.mu.Unlock()
			world.closeErr = world.child.input.Close()
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()
			select {
			case <-world.child.done:
			case <-timer.C:
				world.cancel()
				<-world.child.done
			}
			world.closeErr = errors.Join(world.closeErr, world.child.err)
		}
		world.cancel()
		world.workers.Wait()
		world.fenceBridges()
		world.closeErr = errors.Join(world.closeErr, world.global.Close(), world.regional.Close())
		for _, broker := range slices.Backward(world.brokers) {
			world.closeErr = errors.Join(world.closeErr, broker.Close())
		}
		if world.child == nil {
			world.mu.Lock()
			defer world.mu.Unlock()
		}
		if world.issuer != nil {
			clear(world.issuer.Key)
		}
		for index := range world.wire.Material {
			clear(world.wire.Material[index].Contents)
		}
		world.closeErr = errors.Join(world.closeErr, world.failed)
	})
	return world.closeErr
}
