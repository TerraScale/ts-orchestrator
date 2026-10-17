package native

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
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
	archiveHash, err := fileDigest(req.WorkloadArchivePath)
	if err != nil {
		return report, err
	}
	if archiveHash != req.WorkloadArchiveSHA256 {
		return report, errors.New("workload archive digest mismatch")
	}
	return run(ctx, req, report, func(ctx context.Context, h Host) (peer, error) { return connect(ctx, req, h) })
}

func validate(req Request) error {
	if err := validateHostRequest(req); err != nil {
		return err
	}
	if req.Delivery == nil {
		return errors.New("native qualification requires the authenticated controller delivery driver")
	}
	c := req.Candidate
	if err := ValidateProfileIdentity(c, req.ProfileIdentity); err != nil {
		return err
	}
	materialScenarios := RequiredMaterialScenarios()
	if len(req.MaterialFixtures) != len(materialScenarios) {
		return errors.New("native qualification requires the exact signed material scenario set")
	}
	for i, fixture := range req.MaterialFixtures {
		if fixture.Scenario != materialScenarios[i] || !shaPattern.MatchString(fixture.SignedProfileSHA256) ||
			!shaPattern.MatchString(fixture.ContainerIntentSHA256) || fixture.SignedProfilePath == "" || fixture.ContainerIntentPath == "" || fixture.EvidenceDirectory == "" {
			return errors.New("native signed material fixtures must match the approved ordered scenarios and digests")
		}
	}
	if !shaPattern.MatchString(req.WorkloadArchiveSHA256) {
		return errors.New("workload archive digest required")
	}
	if !strings.Contains(req.WorkloadImage, "@sha256:") || !shaPattern.MatchString(strings.SplitN(req.WorkloadImage, "@sha256:", 2)[1]) {
		return errors.New("workload must pin an architecture-specific image digest")
	}

	return nil
}

func validateHostRequest(req Request) error {
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
	_ = json.MarshalWrite(&r.wire, event, json.Deterministic(true))
	_ = r.wire.WriteByte('\n')
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
	// Only undo injected faults. The parent destroys its guarded OCI resources.
	defer func() {
		started := time.Now().UTC()
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		var errs []error
		for i := range sessions {
			if sessions[i].peer != nil {
				_, err := call(cleanup, i, command{Operation: "heal"})
				errs = append(errs, err)
				// A process restart is cleanup only if this run stopped that process.
				_, err = call(cleanup, i, command{Operation: "restore"})
				errs = append(errs, err)
				_ = sessions[i].peer.close()
			}
		}
		resultErr = errors.Join(resultErr, errors.Join(errs...))
		name, gate := "cleanup", "runtime-ha"
		if resultErr != nil {
			name, gate = "failed-run-cleanup", ""
		} else {
			report.CompletedAt = time.Now().UTC()
		}
		report.Scenarios = append(report.Scenarios, rec.scenario(name, gate, started, req.Hosts))
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
		observed, err := call(ctx, i, command{Operation: "identity", Mode: role, SourceRevision: req.Candidate.SourceRevision, RunID: req.RunID, Host: h, ContainerdPath: req.ContainerdPath, RuncPath: req.RuncPath})
		if err != nil {
			return report, err
		}
		if observed.Role != role || observed.Identity != h.ExpectedIdentity || observed.WorkerSHA256 != req.WorkerSHA256 || observed.WorkerSourceRevision != req.Candidate.SourceRevision {
			return report, errors.New("observed native identity mismatch")
		}
		sessions[i].node = observed.NodeID
		if observed.NodeID == "" {
			return report, errors.New("installed runtime omitted certificate identity")
		}
		report.Hosts = append(report.Hosts, HostReport{Role: observed.Role, OCID: h.OCID, Address: h.Address, Observed: observed.Identity, WorkerSHA256: observed.WorkerSHA256, WorkerSourceRevision: observed.WorkerSourceRevision})
	}
	for i := range sessions {
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
	addresses := map[string]string{}
	for _, s := range sessions {
		addresses[s.node] = s.host.Address
	}
	fixtures := map[string]MaterialFixture{}
	expected := map[string]swarmruntime.ServiceIntent{}
	for _, fixture := range req.MaterialFixtures {
		intent, err := fixtureIntent(req, fixture)
		if err != nil {
			return report, err
		}
		fixtures[fixture.Scenario], expected[fixture.Scenario] = fixture, intent
	}
	for _, phase := range []string{"after-loss", "after-partition"} {
		ready, next := expected["ready"], expected[phase]
		if !proto.Equal(ready.Container, next.Container) || !proto.Equal(ready.Resources, next.Resources) || len(ready.Ports) != len(next.Ports) {
			return report, errors.New("majority-write signed updates must preserve the serving task specification")
		}
		for i := range ready.Ports {
			if !proto.Equal(ready.Ports[i], next.Ports[i]) {
				return report, errors.New("majority-write signed updates must preserve the serving endpoint")
			}
		}
	}
	stableID := expected["ready"].ID
	for _, intent := range expected {
		if intent.ID != stableID {
			return report, errors.New("qualification phases must retain the same signed stable service identity")
		}
	}
	var expectedPhases []swarmruntime.ServiceIntent
	for _, name := range RequiredMaterialScenarios() {
		expectedPhases = append(expectedPhases, expected[name])
	}
	observe := func(index int) (response, error) {
		return call(ctx, index, command{Operation: "observe", ServiceID: stableID, Addresses: addresses, Expected: expectedPhases})
	}
	apply := func(index int, phase string) error {
		started := time.Now().UTC()
		err := req.Delivery.Apply(ctx, fixtures[phase])
		rec.event("controller", command{Operation: "signed-delivery:" + phase}, response{OperationID: expected[phase].OperationID}, err)
		if err != nil {
			return err
		}
		err = wait(ctx, func() (bool, error) {
			r, err := observe(index)
			return r.OperationID == expected[phase].OperationID, err
		})
		if err != nil {
			return fmt.Errorf("signed delivery %s after %s: %w", phase, time.Since(started), err)
		}
		return nil
	}
	if err := apply(0, "ready"); err != nil {
		return report, err
	}
	var service string
	var baseline taskState
	if err := wait(ctx, func() (bool, error) {
		r, err := observe(0)
		if r.Ready == 1 && len(r.Tasks) == 1 {
			service = r.ServiceID
			baseline = r.Tasks[0]
		}
		return r.Ready == 1 && len(r.Tasks) == 1, err
	}); err != nil {
		return report, err
	}
	servingIndex := indexOf(baseline.NodeID)
	if servingIndex < 0 {
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
	leaderIndex := indexOf(leader)
	if leaderIndex < 0 {
		return report, errors.New("leader absent from installed manager inventory")
	}
	lossIndex := leaderIndex
	if lossIndex == servingIndex {
		lossIndex = (lossIndex + 1) % 3
	}
	survivor := 0
	for survivor == lossIndex {
		survivor++
	}
	if err := disruptive("manager-loss", func() error {
		if _, err := call(ctx, lossIndex, command{Operation: "stop"}); err != nil {
			return err
		}
		if err := wait(ctx, func() (bool, error) {
			r, err := call(ctx, survivor, command{Operation: "cluster"})
			return r.Leader != "" && r.Managers == 2, err
		}); err != nil {
			return err
		}
		return apply(survivor, "after-loss")
	}); err != nil {
		return report, err
	}
	if _, err := call(ctx, lossIndex, command{Operation: "start"}); err != nil {
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
	if partitioned == servingIndex {
		partitioned = (partitioned + 1) % 3
	}
	if partitioned < 0 {
		return report, errors.New("partition leader absent from native host inventory")
	}
	survivor = 0
	for survivor == partitioned {
		survivor++
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
			return r.Leader != "" && r.Managers == 2, err
		}); err != nil {
			return err
		}
		if err := apply(survivor, "after-partition"); err != nil {
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
			r, err := observe(survivor)
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
	oldTask, oldNode := baseline.ID, sessions[servingIndex].node
	if _, err := call(ctx, servingIndex, command{Operation: "stop"}); err != nil {
		return report, err
	}
	var replacement taskState
	if err := wait(ctx, func() (bool, error) {
		r, err := observe(control)
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
	if err := apply(control, "failed-update"); err != nil {
		return report, err
	}
	if err := wait(ctx, func() (bool, error) {
		r, err := observe(control)
		return r.UpdateState == "ROLLBACK_COMPLETED" && r.Ready == 1, err
	}); err != nil {
		return report, err
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("rollback", "workload-safety", start, req.Hosts))
	start = time.Now().UTC()
	if err := apply(control, "unready"); err != nil {
		return report, err
	}
	if err := wait(ctx, func() (bool, error) { r, err := observe(control); return r.Running == 1 && r.Ready == 0, err }); err != nil {
		return report, err
	}
	report.Scenarios = append(report.Scenarios, rec.scenario("readiness-rejection", "workload-safety", start, req.Hosts))

	return report, nil
}

// fixtureIntent checks the approved bytes and root profile. The controller driver
// verifies the signed delivery envelope through the production codec and policy.
func fixtureIntent(req Request, fixture MaterialFixture) (swarmruntime.ServiceIntent, error) {
	profile, err := os.ReadFile(fixture.SignedProfilePath)
	if err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	wire, err := os.ReadFile(fixture.ContainerIntentPath)
	if err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	if len(profile) > maxFrame || len(wire) > maxFrame || digest(profile) != fixture.SignedProfileSHA256 || digest(wire) != fixture.ContainerIntentSHA256 {
		return swarmruntime.ServiceIntent{}, errors.New("approved signed fixture bytes changed")
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(wire, &envelope, json.RejectUnknownMembers(true)); err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	intent, err := delivery.DecodeIntent(envelope.Payload)
	if err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	proof, err := containermaterial.VerifyProfile(profile, req.TrustedRoots, req.ProfileIdentity, intent)
	if err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	if !proof.NoSecrets() {
		return swarmruntime.ServiceIntent{}, errors.New("native qualification requires signed no-secret authority")
	}
	expected, err := containermaterial.ServiceIntent(proof, req.Candidate.Architecture)
	if err != nil {
		return swarmruntime.ServiceIntent{}, err
	}
	if expected.Container.Image != req.WorkloadImage || expected.Role != "ts-auth" || expected.Replicas != 1 {
		return swarmruntime.ServiceIntent{}, errors.New("native signed fixture must name the pinned ts-auth readiness workload")
	}
	return expected, nil
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
