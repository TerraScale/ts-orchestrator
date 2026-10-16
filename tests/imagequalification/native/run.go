package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"golang.org/x/crypto/ssh"
)

var runPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateRunID(value string) error {
	if !runPattern.MatchString(value) {
		return errors.New("run ID requires 1..16 lowercase alphanumeric characters, starting with a letter")
	}
	return nil
}

// Run contacts only explicit, pinned disposable hosts. Its parent must establish
// OCI confinement/authorization first; this API alone never admits a production
// image, signs gates, creates infrastructure, or claims tenant network isolation.
func Run(ctx context.Context, req Request) (Report, error) {
	report := Report{RunID: req.RunID, Candidate: req.Candidate, ImageOCID: req.ImageOCID, WorkloadImage: req.WorkloadImage, WorkloadArchiveSHA256: req.WorkloadArchiveSHA256, StartedAt: time.Now().UTC()}
	if err := validate(req); err != nil {
		return report, err
	}
	signer, err := readPrivateKey(req.PrivateKeyPath)
	if err != nil {
		return report, err
	}
	worker, err := os.ReadFile(req.WorkerPath)
	if err != nil {
		return report, err
	}
	archiveHash, err := fileDigest(req.WorkloadArchivePath)
	if err != nil {
		return report, err
	}
	if archiveHash != req.WorkloadArchiveSHA256 {
		return report, errors.New("workload archive digest mismatch")
	}
	if digest(worker) != req.WorkerSHA256 {
		return report, errors.New("local native worker digest mismatch")
	}
	return run(ctx, req, report, func(ctx context.Context, h Host) (peer, error) { return connect(ctx, req, h, worker, signer) })
}

func validate(req Request) error {
	if err := validateRunID(req.RunID); err != nil {
		return err
	}
	if len(req.Hosts) != 4 {
		return errors.New("native qualification requires three managers and one separate agent on four distinct Compute hosts")
	}
	c := req.Candidate
	if !release.ValidSourceRevision(c.SourceRevision) || !shaPattern.MatchString(c.ArtifactSHA256) || !shaPattern.MatchString(c.QualificationSHA256) || !release.ValidRegion(c.Cell) || !release.ValidEnvironment(c.Environment) || c.Runtime != release.ProductionRuntime || c.Role == "" {
		return errors.New("native candidate identity is incomplete")
	}
	if c.Architecture != "arm64" && c.Architecture != "amd64" {
		return errors.New("native candidate architecture unsupported")
	}
	if !strings.HasPrefix(req.ImageOCID, "ocid1.image.") || req.SSHUser != "root" || !shaPattern.MatchString(req.WorkerSHA256) {
		return errors.New("native image, root SSH user and worker digest required")
	}
	if !shaPattern.MatchString(req.WorkloadArchiveSHA256) {
		return errors.New("workload archive digest required")
	}
	if !strings.Contains(req.WorkloadImage, "@sha256:") || !shaPattern.MatchString(strings.SplitN(req.WorkloadImage, "@sha256:", 2)[1]) {
		return errors.New("workload must pin an architecture-specific image digest")
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	for _, h := range req.Hosts {
		a, err := netip.ParseAddr(h.Address)
		if err != nil || !a.Is4() || !a.IsPrivate() || ids[h.OCID] || addresses[h.Address] || !strings.HasPrefix(h.OCID, "ocid1.instance.") {
			return errors.New("native hosts require distinct Compute IDs and private IPv4 addresses")
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.SSHHostKey)); err != nil {
			return errors.New("native host requires trusted SSH host key")
		}
		ids[h.OCID], addresses[h.Address] = true, true
		i := h.ExpectedIdentity
		if i.InstanceID != h.OCID || i.ImageOCID != req.ImageOCID || i.Architecture != c.Architecture || i.KernelRelease == "" {
			return errors.New("expected native host identity mismatches candidate")
		}
		for _, hash := range []string{i.KernelSHA256, i.BinarySHA256, i.ContainerdSHA256, i.RuncSHA256} {
			if !shaPattern.MatchString(hash) {
				return errors.New("native component digest missing")
			}
		}
	}
	return nil
}

type recorder struct {
	mu   sync.Mutex
	wire bytes.Buffer
}

func (r *recorder) event(host string, c command, result response, err error) {
	c.Token = ""
	result.WorkerToken = ""
	result.Token = ""
	event := struct {
		At      time.Time `json:"at"`
		Host    string    `json:"host"`
		Command command   `json:"command"`
		Result  response  `json:"result"`
		Error   string    `json:"error,omitempty"`
	}{At: time.Now().UTC(), Host: host, Command: c, Result: result}
	if err != nil {
		event.Error = err.Error()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = json.NewEncoder(&r.wire).Encode(event)
}
func (r *recorder) scenario(name, gate string, start time.Time, hosts []Host) Scenario {
	r.mu.Lock()
	defer r.mu.Unlock()
	wire := bytes.Clone(r.wire.Bytes())
	r.wire.Reset()
	s := Scenario{Name: name, Gate: gate, StartedAt: start, CompletedAt: time.Now().UTC(), Transcript: wire, TranscriptSHA256: digest(wire)}
	for _, h := range hosts {
		s.HostIDs = append(s.HostIDs, h.OCID)
	}
	return s
}

type session struct {
	host Host
	peer peer
	node string
}

func run(ctx context.Context, req Request, initial Report, dial func(context.Context, Host) (peer, error)) (report Report, resultErr error) {
	report = initial
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	rec := &recorder{}
	sessions := make([]session, len(req.Hosts))
	call := func(ctx context.Context, index int, c command) (response, error) {
		operation, cancel := context.WithTimeout(ctx, 50*time.Second)
		defer cancel()
		result, err := sessions[index].peer.call(operation, c)
		rec.event(sessions[index].host.OCID, c, result, err)
		return result, err
	}
	// Cleanup is mandatory even on partial scenario failures. Disposable-host
	// destruction remains the parent's independently authorized cleanup operation.
	var serviceIDs []string
	defer func() {
		cleanupStarted := time.Now().UTC()
		cleanup, stop := context.WithTimeout(context.Background(), 40*time.Second)
		defer stop()
		var cleanupErrors []error
		for i := range sessions {
			if sessions[i].peer != nil {
				_, err := call(cleanup, i, command{Operation: "heal"})
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		for _, id := range serviceIDs {
			removed := false
			for i := range sessions {
				if sessions[i].peer != nil {
					if _, err := call(cleanup, i, command{Operation: "remove", ServiceID: id}); err == nil {
						removed = true
						break
					}
				}
			}
			if !removed {
				cleanupErrors = append(cleanupErrors, errors.New("service cleanup failed: "+id))
				continue
			}
			for i := range sessions {
				if sessions[i].peer != nil {
					err := wait(cleanup, func() (bool, error) {
						state, err := call(cleanup, i, command{Operation: "inventory", ServiceID: id})
						return err == nil && len(state.Tasks) == 0, err
					})
					cleanupErrors = append(cleanupErrors, err)
				}
			}
		}
		for i := range sessions {
			if sessions[i].peer != nil {
				_ = sessions[i].peer.close()
			}
		}
		resultErr = errors.Join(resultErr, errors.Join(cleanupErrors...))
		// The caller receives cleanup evidence as a separate scenario only on success.
		if resultErr == nil {
			report.Scenarios = append(report.Scenarios, rec.scenario("cleanup", "runtime-ha", cleanupStarted, req.Hosts))
			report.CompletedAt = time.Now().UTC()
		} else {
			report.Scenarios = append(report.Scenarios, rec.scenario("failed-run-cleanup", "", cleanupStarted, req.Hosts))
		}
	}()
	start := time.Now().UTC()
	for i, h := range req.Hosts {
		role := "manager"
		if i == 3 {
			role = "container"
		}
		p, err := dial(ctx, h)
		if err != nil {
			return report, err
		}
		sessions[i] = session{host: h, peer: p}
		observed, err := call(ctx, i, command{Operation: "identity", Mode: role, SourceRevision: req.Candidate.SourceRevision, RunID: req.RunID, Host: h, Region: catalog.OCIRegion(req.Candidate.Cell), ContainerdPath: req.ContainerdPath, RuncPath: req.RuncPath})
		if err != nil {
			return report, err
		}
		if _, err := call(ctx, i, command{Operation: "import", Image: req.WorkloadImage, ArchiveSHA256: req.WorkloadArchiveSHA256}); err != nil {
			return report, err
		}
		if observed.Role != role || observed.Identity != h.ExpectedIdentity || observed.WorkerSHA256 != req.WorkerSHA256 || observed.WorkerSourceRevision != req.Candidate.SourceRevision {
			return report, errors.New("observed native identity mismatch")
		}
		report.Hosts = append(report.Hosts, HostReport{Role: observed.Role, OCID: h.OCID, Address: h.Address, Observed: observed.Identity, WorkerSHA256: observed.WorkerSHA256, WorkerSourceRevision: observed.WorkerSourceRevision})
	}
	first, err := call(ctx, 0, command{Operation: "start"})
	if err != nil {
		return report, err
	}
	sessions[0].node = first.NodeID
	material, err := call(ctx, 0, command{Operation: "join-material"})
	if err != nil {
		return report, err
	}
	founder := "native-" + req.RunID + "-" + strings.ReplaceAll(req.Hosts[0].Address, ".", "-")
	for i := range sessions {
		role := "manager"
		token := material.Token
		if i == 3 {
			role = "container"
			token = material.WorkerToken
		}
		if i != 0 {
			joined, err := call(ctx, i, command{Operation: "start", Founder: founder, JoinAddress: req.Hosts[0].Address + ":" + managerPort, Token: token})
			if err != nil {
				return report, err
			}
			sessions[i].node = joined.NodeID
		}
		if sessions[i].node == "" {
			return report, errors.New("native manager omitted certificate identity")
		}
		if _, err := call(ctx, 0, command{Operation: "admit", Mode: role, RunID: req.RunID, Host: req.Hosts[i], NodeID: sessions[i].node}); err != nil {
			return report, err
		}
		report.Hosts[i].NodeID = sessions[i].node
	}
	var leader string
	if err := wait(ctx, func() (bool, error) {
		state, err := call(ctx, 0, command{Operation: "cluster"})
		leader = state.Leader
		return state.Managers == 3 && leader != "", err
	}); err != nil {
		return report, err
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("native-three-manager-formation", "runtime-ha", start, req.Hosts))
	indexOf := func(node string) int {
		for i, s := range sessions {
			if s.node == node {
				return i
			}
		}
		return -1
	}
	leaderIndex := indexOf(leader)
	if leaderIndex < 0 {
		return report, errors.New("leader absent from native inventory")
	}
	for i := range 3 {
		if _, err := call(ctx, 0, command{Operation: "pause", NodeID: sessions[i].node}); err != nil {
			return report, err
		}
	}
	addresses := map[string]string{}
	for _, s := range sessions {
		addresses[s.node] = s.host.Address
	}
	create := func(index int, mode string, port uint32) (string, error) {
		r, err := call(ctx, index, command{Operation: "create", RunID: req.RunID, Region: catalog.OCIRegion(req.Candidate.Cell), Image: req.WorkloadImage, Mode: mode, Port: port})
		if err == nil {
			serviceIDs = append(serviceIDs, r.ServiceID)
		}
		return r.ServiceID, err
	}
	service, err := create(0, "ready", 18080)
	if err != nil {
		return report, err
	}
	observe := func(index int, id string) (response, error) {
		return call(ctx, index, command{Operation: "observe", ServiceID: id, Addresses: addresses})
	}
	var baseline taskState
	if err := wait(ctx, func() (bool, error) {
		r, err := observe(0, service)
		if r.Ready == 1 && len(r.Tasks) == 1 {
			baseline = r.Tasks[0]
		}
		return r.Ready == 1 && len(r.Tasks) == 1, err
	}); err != nil {
		return report, err
	}
	servingIndex := indexOf(baseline.NodeID)
	if servingIndex < 0 || servingIndex == leaderIndex {
		return report, errors.New("serving task did not use surviving native host")
	}
	inventory := func() (taskState, error) {
		var found []taskState
		for i := range sessions {
			r, err := call(ctx, i, command{Operation: "inventory", ServiceID: service})
			if err != nil {
				return taskState{}, err
			}
			found = append(found, r.Tasks...)
		}
		if len(found) != 1 || found[0].ID != baseline.ID || found[0].PID == 0 {
			return taskState{}, errors.New("task identity duplicated, absent or replaced")
		}
		return found[0], nil
	}
	runtimeTask, err := inventory()
	if err != nil {
		return report, err
	}
	checkIdentity := func() error {
		r, err := inventory()
		if err != nil {
			return err
		}
		if r.PID != runtimeTask.PID {
			return errors.New("task process changed during manager or agent disruption")
		}
		return nil
	}
	probe := func(ctx context.Context) error {
		return sessions[servingIndex].peer.probeHTTP(ctx)
	}
	disruptive := func(name string, action func() error) error {
		start := time.Now().UTC()
		if err := continuous(ctx, probe, action, func(err error) {
			rec.event(req.Hosts[servingIndex].OCID, command{Operation: "http-probe"}, response{}, err)
		}); err != nil {
			return err
		}
		if err := checkIdentity(); err != nil {
			return err
		}
		report.Scenarios = append(report.Scenarios, rec.scenario(name, "runtime-ha", start, req.Hosts))
		return nil
	}
	survivor := 0
	for survivor == leaderIndex {
		survivor++
	}
	if err := disruptive("manager-loss", func() error {
		if _, err := call(ctx, leaderIndex, command{Operation: "stop"}); err != nil {
			return err
		}
		if err := wait(ctx, func() (bool, error) {
			r, err := call(ctx, survivor, command{Operation: "cluster"})
			return r.Leader != "" && r.Leader != leader, err
		}); err != nil {
			return err
		}
		// A real service create/remove confirms writes, beyond a stale leader read.
		id, err := create(survivor, "after-loss", 18082)
		if err != nil {
			return err
		}
		if err := wait(ctx, func() (bool, error) { r, err := observe(survivor, id); return r.Ready == 1, err }); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return report, err
	}
	if _, err := call(ctx, leaderIndex, command{Operation: "start"}); err != nil {
		return report, err
	}
	if err := wait(ctx, func() (bool, error) {
		r, err := call(ctx, survivor, command{Operation: "cluster"})
		leader = r.Leader
		return r.Managers == 3 && leader != "", err
	}); err != nil {
		return report, err
	}
	partitioned := indexOf(leader)
	if partitioned < 0 {
		return report, errors.New("partition leader absent from native host inventory")
	}
	survivor = 0
	for survivor == partitioned {
		survivor++
	}
	if _, err := call(ctx, survivor, command{Operation: "pause", NodeID: leader}); err != nil {
		return report, err
	}
	var peers []string
	for i, h := range req.Hosts {
		if i < 3 && i != partitioned {
			peers = append(peers, h.Address)
		}
	}
	if err := disruptive("manager-partition", func() error {
		if _, err := call(ctx, partitioned, command{Operation: "partition", Peers: peers}); err != nil {
			return err
		}
		if err := wait(ctx, func() (bool, error) {
			r, err := call(ctx, survivor, command{Operation: "cluster"})
			return r.Leader != "" && r.Leader != leader, err
		}); err != nil {
			return err
		}
		id, err := create(survivor, "after-partition", 18083)
		if err != nil {
			return err
		}
		if err := wait(ctx, func() (bool, error) { r, err := observe(survivor, id); return r.Ready == 1, err }); err != nil {
			return err
		}
		if _, err := call(ctx, partitioned, command{Operation: "heal"}); err != nil {
			return err
		}
		return wait(ctx, func() (bool, error) {
			r, err := call(ctx, survivor, command{Operation: "cluster"})
			return r.Managers == 3, err
		})
	}); err != nil {
		return report, err
	}
	if err := disruptive("agent-restart", func() error {
		if _, err := call(ctx, servingIndex, command{Operation: "stop"}); err != nil {
			return err
		}
		if err := probe(ctx); err != nil {
			return err
		}
		restarted, err := call(ctx, servingIndex, command{Operation: "start"})
		if err != nil {
			return err
		}
		if restarted.NodeID != sessions[servingIndex].node {
			return errors.New("agent restart replaced certificate identity")
		}
		return wait(ctx, func() (bool, error) {
			r, err := observe(survivor, service)
			return r.Ready == 1 && len(r.Tasks) == 1 && r.Tasks[0].ID == baseline.ID, err
		})
	}); err != nil {
		return report, err
	}

	start = time.Now().UTC()
	// An unavailable agent is a different failure from a quick restart: let the
	// majority replace its task, then require stale-container removal on rejoin.
	control := 0
	for control == servingIndex {
		control++
	}
	for i := range sessions {
		if i != servingIndex {
			if _, err := call(ctx, control, command{Operation: "activate", NodeID: sessions[i].node}); err != nil {
				return report, err
			}
		}
	}
	oldTask, oldNode := baseline.ID, sessions[servingIndex].node
	if _, err := call(ctx, servingIndex, command{Operation: "stop"}); err != nil {
		return report, err
	}
	var replacement taskState
	if err := wait(ctx, func() (bool, error) {
		r, err := observe(control, service)
		if err != nil {
			return false, err
		}
		if r.Ready == 1 && len(r.Tasks) == 1 && r.Tasks[0].ID != oldTask && r.Tasks[0].NodeID != oldNode {
			replacement = r.Tasks[0]
			return true, nil
		}
		return false, nil
	}); err != nil {
		return report, err
	}
	// Two different stateless task generations can coexist while an agent is
	// disconnected. The same upstream task identity must never run on two hosts.
	identities := map[string]bool{}
	for i := range sessions {
		r, err := call(ctx, i, command{Operation: "inventory", ServiceID: service})
		if err != nil {
			return report, err
		}
		for _, t := range r.Tasks {
			if identities[t.ID] {
				return report, errors.New("unavailable agent duplicated the same upstream task identity")
			}
			identities[t.ID] = true
		}
	}
	rejoined, err := call(ctx, servingIndex, command{Operation: "start"})
	if err != nil {
		return report, err
	}
	if rejoined.NodeID != oldNode {
		return report, errors.New("unavailable agent rejoin replaced node certificate identity")
	}
	baseline = replacement
	if err := wait(ctx, func() (bool, error) {
		r, err := inventory()
		if err == nil {
			runtimeTask = r
		}
		return err == nil, err
	}); err != nil {
		return report, err
	}
	servingIndex = indexOf(replacement.NodeID)
	if servingIndex < 0 {
		return report, errors.New("replacement task absent from native inventory")
	}
	if err := probe(ctx); err != nil {
		return report, err
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("unavailable-agent-replacement", "runtime-ha", start, req.Hosts))

	start = time.Now().UTC()
	currentTask, err := inventory()
	if err != nil {
		return report, err
	}
	if !currentTask.Secure {
		return report, errors.New("runtime OCI spec is missing non-root, readonly, no-new-privileges, seccomp or capability confinement")
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("container-isolation", "workload-safety", start, req.Hosts))
	start = time.Now().UTC()
	unready, err := create(survivor, "unready", 18081)
	if err != nil {
		return report, err
	}
	if err := wait(ctx, func() (bool, error) { r, err := observe(survivor, unready); return r.Running == 1 && r.Ready == 0, err }); err != nil {
		return report, err
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("readiness-rejection", "workload-safety", start, req.Hosts))
	start = time.Now().UTC()
	if _, err := call(ctx, survivor, command{Operation: "break-update", ServiceID: service, Image: req.WorkloadImage}); err != nil {
		return report, err
	}
	if err := wait(ctx, func() (bool, error) {
		r, err := observe(survivor, service)
		return r.UpdateState == "ROLLBACK_COMPLETED" && r.Ready == 1, err
	}); err != nil {
		return report, err
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("rollback", "workload-safety", start, req.Hosts))
	return report, nil
}

func wait(ctx context.Context, condition func() (bool, error)) error {
	step, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var last error
	for {
		ok, err := condition()
		if ok && err == nil {
			return nil
		}
		last = err
		select {
		case <-step.Done():
			return fmt.Errorf("native convergence: %w (last=%v)", step.Err(), last)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func probeHTTP(ctx context.Context, url string, dial func(context.Context, string, string) (net.Conn, error)) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: dial}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 33))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || string(body) != "ready" {
		return fmt.Errorf("native HTTP continuity: status=%d body=%q", response.StatusCode, body)
	}
	return nil
}

func continuous(ctx context.Context, probe func(context.Context) error, action func() error, record func(error)) error {
	if err := probe(ctx); err != nil {
		record(err)
		return err
	}
	record(nil)
	monitor, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		for {
			select {
			case <-monitor.Done():
				done <- nil
				return
			case <-time.After(100 * time.Millisecond):
				if err := probe(monitor); err != nil {
					if monitor.Err() != nil {
						done <- nil
						return
					}
					record(err)
					done <- err
					return
				}
				record(nil)
			}
		}
	}()
	err := action()
	stop()
	monitorErr := <-done
	finalErr := probe(ctx)
	record(finalErr)
	return errors.Join(err, monitorErr, finalErr)
}
