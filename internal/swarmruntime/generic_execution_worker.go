//go:build linux

package swarmruntime

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
)

var ErrGenericExecutionPending = errors.New("original generic execution authority or stopped evidence is pending")

type genericExecutionWorker struct {
	agent *host.Agent
	node  *Node
}

type genericExecutionWitness struct {
	Task               *api.Task              `json:"task"`
	ExecutionSessionID string                 `json:"execution_session_id"`
	Hold               *drainwire.SignedHold  `json:"hold,omitempty"`
	Process            *genericProcessWitness `json:"process,omitempty"`
	Closing            bool                   `json:"closing"`
}

type genericProcessWitness struct {
	ContainerID    string `json:"container_id"`
	Image          string `json:"image"`
	SpecSHA256     string `json:"spec_sha256"`
	KernelStart    string `json:"kernel_start"`
	Cgroup         string `json:"cgroup"`
	HostPID        int    `json:"host_pid"`
	PIDNamespace   uint64 `json:"pid_namespace"`
	MountNamespace uint64 `json:"mount_namespace"`
}

// BindGenericExecution installs the actual authenticated Agent and joined Node.
// Until joined, new generic starts hold; existing running tasks keep running.
func (e *Executor) BindGenericExecution(agent *host.Agent, node *Node) error {
	if agent == nil || node == nil || node.upstream == nil || node.role != "container" && node.role != "wasm" {
		return ErrGenericExecutionPending
	}
	if _, err := agent.GenericExecutionSession(node.admission.InstanceID, node.ID()); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.genericExecution != nil || e.functionNodeID != node.ID() {
		return ErrGenericExecutionPending
	}
	e.genericExecution = &genericExecutionWorker{agent: agent, node: node}
	return nil
}

func (e *Executor) genericWitnessRoot() string {
	return filepath.Join(filepath.Dir(e.logRoot), "execution-holds")
}
func (e *Executor) genericWitnessPath(taskID string) string {
	return filepath.Join(e.genericWitnessRoot(), "ts-"+taskID+".json")
}

func (e *Executor) readGenericWitness(taskID string) (genericExecutionWitness, error) {
	var w genericExecutionWitness
	// Shared disk helpers check current ownership; execution evidence requires root.
	if os.Geteuid() != 0 || taskID == "" || strings.ContainsAny(taskID, "/\\. \t\r\n") {
		return w, ErrGenericExecutionPending
	}
	if err := verifyDiskDirectory(e.genericWitnessRoot()); err != nil {
		return w, err
	}
	path := e.genericWitnessPath(taskID)
	stat, err := diskFileStat(path)
	if err != nil {
		return w, err
	}
	if stat.Mode&0077 != 0 || stat.Size <= 0 || stat.Size > 128<<10 {
		return w, ErrGenericExecutionPending
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return w, err
	}
	defer file.Close()
	var actual unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &actual); err != nil {
		return w, err
	}
	if actual.Dev != stat.Dev || actual.Ino != stat.Ino || actual.Size != stat.Size {
		return w, ErrGenericExecutionPending
	}
	data, err := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	if err != nil || int64(len(data)) != stat.Size {
		return w, errors.Join(ErrGenericExecutionPending, err)
	}
	if err := json.Unmarshal(data, &w, json.RejectUnknownMembers(true)); err != nil {
		return w, err
	}
	if w.Task == nil || w.Task.ID != taskID || !entityid.Valid(w.ExecutionSessionID) {
		return w, ErrGenericExecutionPending
	}
	if _, err := DecodeContainer(w.Task); err != nil {
		return w, err
	}
	hash, err := executionwire.TaskSHA256(w.Task)
	if err != nil {
		return w, err
	}
	if w.Hold != nil && (w.Hold.Hold.Validate() != nil || w.Hold.Hold.TaskSHA256 != hash || w.Hold.Hold.ExecutionSHA256 != taskFingerprint(w.Task) ||
		w.Hold.Hold.ExecutionSessionID != w.ExecutionSessionID || w.Hold.Hold.TaskID != w.Task.ID || w.Hold.Hold.ServiceID != w.Task.ServiceID || w.Hold.Hold.NodeID != w.Task.NodeID) {
		return w, ErrGenericExecutionPending
	}
	if w.Process != nil && (w.Hold == nil || !w.Process.valid(taskID)) {
		return w, ErrGenericExecutionPending
	}
	return w, nil
}

func (p genericProcessWitness) valid(taskID string) bool {
	start, err := strconv.ParseUint(p.KernelStart, 10, 64)
	return p.ContainerID == "ts-"+taskID && p.Image != "" && len(p.SpecSHA256) == 64 && p.HostPID > 1 &&
		err == nil && start > 0 && p.Cgroup == "0::/terrascale/"+p.ContainerID+"\n" && p.PIDNamespace != 0 && p.MountNamespace != 0
}

// The executor mutex serializes writers. Retain this separate from removable logs.
func (e *Executor) writeGenericWitness(w genericExecutionWitness) error {
	if os.Geteuid() != 0 || w.Task == nil || strings.ContainsAny(w.Task.ID, "/\\. \t\r\n") {
		return ErrGenericExecutionPending
	}
	root := e.genericWitnessRoot()
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	parent, err := os.Open(filepath.Dir(root))
	if err != nil {
		return err
	}
	syncParent := parent.Sync()
	if err := errors.Join(syncParent, parent.Close()); err != nil {
		return err
	}
	if err := verifyDiskDirectory(root); err != nil {
		return err
	}
	wire, err := json.Marshal(w, json.Deterministic(true))
	if err != nil || len(wire) > 128<<10 {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	file, err := os.CreateTemp(root, ".execution-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(wire); err != nil {
		_ = file.Close()
		return err
	}
	syncErr := file.Sync()
	if err := errors.Join(syncErr, file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), e.genericWitnessPath(w.Task.ID)); err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	syncErr = directory.Sync()
	return errors.Join(syncErr, directory.Close())
}

// Called before NewTask, never to manufacture an original hold for a survivor.
func (c *controller) acquireGenericExecution(ctx context.Context) error {
	if !c.poolExecutionTask() {
		return nil
	}
	e := c.executor
	worker := e.genericExecution
	if worker == nil {
		return swarmexec.MakeTemporary(ErrGenericExecutionPending)
	}
	identity, err := worker.agent.GenericExecutionSession(worker.node.admission.InstanceID, worker.node.ID())
	if err != nil {
		return err
	}
	w, err := e.readGenericWitness(c.task.ID)
	if errors.Is(err, os.ErrNotExist) {
		w = genericExecutionWitness{Task: c.task.Copy(), ExecutionSessionID: entityid.New()}
		if err := e.writeGenericWitness(w); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	hash, err := executionwire.TaskSHA256(c.task)
	if err != nil {
		return err
	}
	retained, err := executionwire.TaskSHA256(w.Task)
	if err != nil || retained != hash || w.Closing || w.Process != nil {
		return ErrGenericExecutionPending
	}
	reply, err := worker.agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "acquire", Task: c.task.Copy(), ExecutionSessionID: w.ExecutionSessionID})
	if err != nil {
		return err
	}
	if reply.Hold == nil || reply.Hold.Hold.InstanceID != worker.node.admission.InstanceID || !reply.Hold.Hold.HostSession.SameIdentity(identity) || reply.Hold.Hold.TaskSHA256 != hash ||
		reply.Hold.Hold.ExecutionSHA256 != c.fingerprint || reply.Hold.Hold.ExecutionSessionID != w.ExecutionSessionID ||
		reply.Hold.Hold.NodeID != c.task.NodeID || reply.Hold.Hold.TaskID != c.task.ID || reply.Hold.Hold.ServiceID != c.task.ServiceID ||
		w.Hold != nil && !sameGenericHold(*w.Hold, *reply.Hold) {
		return ErrGenericExecutionPending
	}
	if err := worker.verifyHold(*reply.Hold); err != nil {
		return err
	}
	w.Hold = reply.Hold
	return e.writeGenericWitness(w)
}

func (w *genericExecutionWorker) verifyHold(hold drainwire.SignedHold) error {
	if len(hold.CertificateChain) == 0 {
		return ErrGenericExecutionPending
	}
	certificate, err := x509.ParseCertificate(hold.CertificateChain[0])
	if err != nil || len(certificate.Subject.Organization) != 1 {
		return ErrGenericExecutionPending
	}
	ca, err := os.ReadFile(filepath.Join(w.node.stateDir, "certificates", "swarm-root-ca.crt"))
	if err != nil {
		return err
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hold.CertificateChain[0]})
	return drainwire.VerifySignedHold(hold, leaf, ca, certificate.Subject.Organization[0], time.Now().UTC())
}

// Called on a real Created process before Start while the executor mutex is held.
func (c *controller) retainGenericProcess(ctx context.Context, task containerd.Task) error {
	if !c.poolExecutionTask() {
		return nil
	}
	e := c.executor
	worker := e.genericExecution
	if worker == nil {
		return ErrGenericExecutionPending
	}
	w, err := e.readGenericWitness(c.task.ID)
	if err != nil || w.Hold == nil || w.Closing || !time.Now().Before(w.Hold.Hold.ExpiresAt) {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	identity, err := worker.agent.GenericExecutionSession(worker.node.admission.InstanceID, worker.node.ID())
	if err != nil || !identity.SameIdentity(w.Hold.Hold.HostSession) {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	hash, err := executionwire.TaskSHA256(c.task)
	if err != nil || hash != w.Hold.Hold.TaskSHA256 {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	if err := worker.verifyHold(*w.Hold); err != nil {
		return err
	}
	reply, err := worker.agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "acquire", Task: c.task.Copy(), ExecutionSessionID: w.ExecutionSessionID})
	if err != nil || reply.Hold == nil || !sameGenericHold(*w.Hold, *reply.Hold) {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	observed, err := c.observeGenericProcess(ctx, task)
	if err != nil {
		return err
	}
	if w.Process != nil && *w.Process != observed {
		return ErrGenericExecutionPending
	}
	w.Process = &observed
	return e.writeGenericWitness(w)
}

func (c *controller) observeGenericProcess(ctx context.Context, task containerd.Task) (genericProcessWitness, error) {
	var result genericProcessWitness
	ctr, err := c.container(ctx)
	if err != nil {
		return result, err
	}
	info, err := ctr.Info(ctx)
	if err != nil || info.Image != c.spec.Image || info.Runtime.Name != "io.containerd.runc.v2" {
		return result, errors.Join(ErrGenericExecutionPending, err)
	}
	spec, err := ctr.Spec(ctx)
	if err != nil || spec.Root == nil || !spec.Root.Readonly || spec.Linux == nil || spec.Linux.CgroupsPath != "/terrascale/"+c.id {
		return result, errors.Join(ErrGenericExecutionPending, err)
	}
	data, err := json.Marshal(spec, json.Deterministic(true))
	if err != nil {
		return result, err
	}
	result = genericProcessWitness{ContainerID: c.id, Image: c.spec.Image, SpecSHA256: fmt.Sprintf("%x", sha256.Sum256(data)), HostPID: int(task.Pid())}
	status, err := task.Status(ctx)
	if err != nil || status.Status != containerd.Created && status.Status != containerd.Running || result.HostPID < 2 {
		return result, errors.Join(ErrGenericExecutionPending, err)
	}
	read := func() error {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", result.HostPID))
		if err != nil {
			return err
		}
		_, suffix, ok := strings.CutLast(string(raw), ") ")
		fields := strings.Fields(suffix)
		if !ok || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
			return ErrGenericExecutionPending
		}
		result.KernelStart = fields[19]
		group, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", result.HostPID))
		if err != nil {
			return err
		}
		result.Cgroup = string(group)
		var pidNS, mountNS unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", result.HostPID), &pidNS); err != nil {
			return err
		}
		if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", result.HostPID), &mountNS); err != nil {
			return err
		}
		result.PIDNamespace, result.MountNamespace = pidNS.Ino, mountNS.Ino
		return nil
	}
	if err := read(); err != nil {
		return result, err
	}
	before := result
	if err := read(); err != nil {
		return result, err
	}
	if result != before || !result.valid(c.task.ID) {
		return result, ErrGenericExecutionPending
	}
	current, err := ctr.Task(ctx, nil)
	if err != nil || int(current.Pid()) != result.HostPID {
		return result, errors.Join(ErrGenericExecutionPending, err)
	}
	return result, ctx.Err()
}

// RunGenericExecution keeps retained process evidence after controller removal.
// Missing local records or original host sessions yield no stopped signature.
func (e *Executor) RunGenericExecution(ctx context.Context) error {
	ticks := time.Tick(time.Second)
	for {
		if err := e.reconcileGenericExecution(ctx); err != nil && ctx.Err() == nil {
			slog.DebugContext(ctx, "generic execution drain evidence pending", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
		}
	}
}

func (e *Executor) reconcileGenericExecution(ctx context.Context) error {
	e.mu.Lock()
	worker := e.genericExecution
	e.mu.Unlock()
	if worker == nil {
		return ErrGenericExecutionPending
	}
	reply, err := worker.agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "poll"})
	if err != nil {
		return err
	}
	for _, challenge := range reply.Challenges {
		observed, err := e.observeGenericStop(ctx, worker, challenge)
		if err != nil {
			continue
		} // Still running or unknown retains the root hold.
		proof, err := worker.signStop(ctx, observed)
		if err != nil {
			return err
		}
		if _, err := worker.agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "stop", Stop: &proof}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type observedGenericStop struct {
	payload drainwire.StopPayload
	worker  *genericExecutionWorker
}

func (e *Executor) observeGenericStop(ctx context.Context, worker *genericExecutionWorker, challenge drainwire.DrainStopChallenge) (observedGenericStop, error) {
	var empty observedGenericStop
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.genericExecution != worker || challenge.Validate(time.Now().UTC()) != nil {
		return empty, ErrGenericExecutionPending
	}
	w, err := e.readGenericWitness(challenge.TaskID)
	if err != nil || w.Hold == nil || w.Process == nil || !challenge.Matches(w.Hold.Hold) {
		return empty, errors.Join(ErrGenericExecutionPending, err)
	}
	current, err := worker.agent.GenericExecutionSession(worker.node.admission.InstanceID, worker.node.ID())
	if err != nil || !current.SameIdentity(w.Hold.Hold.HostSession) {
		return empty, errors.Join(ErrGenericExecutionPending, err)
	}
	if err := worker.verifyHold(*w.Hold); err != nil {
		return empty, err
	}
	// Persist the irreversible local no-restart gate before any stopped proof.
	if !w.Closing {
		w.Closing = true
		if err := e.writeGenericWitness(w); err != nil {
			return empty, err
		}
	}
	for range 2 {
		if err := e.verifyGenericStopped(ctx, w); err != nil {
			return empty, err
		}
	}
	p := *w.Process
	return observedGenericStop{worker: worker, payload: drainwire.StopPayload{Challenge: challenge, ObservedAt: time.Now().UTC(),
		ContainerID: p.ContainerID, KernelStart: p.KernelStart, Cgroup: p.Cgroup, HostPID: p.HostPID, PIDNamespace: p.PIDNamespace, MountNamespace: p.MountNamespace}}, nil
}

func (e *Executor) verifyGenericStopped(ctx context.Context, w genericExecutionWitness) error {
	p := w.Process
	if p == nil || !p.valid(w.Task.ID) || !w.Closing {
		return ErrGenericExecutionPending
	}
	ctx = runtimeContext(ctx)
	ctr, err := e.client.LoadContainer(ctx, p.ContainerID)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if err == nil {
		info, err := ctr.Info(ctx)
		if err != nil || info.Image != p.Image || info.Runtime.Name != "io.containerd.runc.v2" ||
			info.Labels["terrascale.task"] != w.Task.ID || info.Labels["terrascale.service"] != w.Task.ServiceID || info.Labels["terrascale.spec"] != w.Hold.Hold.ExecutionSHA256 {
			return errors.Join(ErrGenericExecutionPending, err)
		}
		spec, err := ctr.Spec(ctx)
		if err != nil {
			return err
		}
		wire, err := json.Marshal(spec, json.Deterministic(true))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(wire)) != p.SpecSHA256 {
			return errors.Join(ErrGenericExecutionPending, err)
		}
		task, err := ctr.Task(ctx, nil)
		if err != nil && !errdefs.IsNotFound(err) {
			return err
		}
		if err == nil {
			status, err := task.Status(ctx)
			if err != nil || status.Status != containerd.Stopped || task.Pid() != 0 && int(task.Pid()) != p.HostPID {
				return errors.Join(ErrGenericExecutionPending, err)
			}
		}
	}
	if err := genericOriginalProcessStopped(p.HostPID, p.KernelStart); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup/terrascale", p.ContainerID, "cgroup.events"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && !strings.Contains("\n"+string(data), "\npopulated 0\n") {
		return ErrGenericExecutionPending
	}
	return ctx.Err()
}

func genericOriginalProcessStopped(pid int, start string) error {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, suffix, ok := strings.CutLast(string(raw), ") ")
	fields := strings.Fields(suffix)
	if !ok || len(fields) < 20 {
		return ErrGenericExecutionPending
	}
	actual, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || actual == 0 {
		return ErrGenericExecutionPending
	}
	if fields[19] != start || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return nil
	}
	return ErrGenericExecutionPending
}

func (w *genericExecutionWorker) signStop(ctx context.Context, observed observedGenericStop) (drainwire.SignedStop, error) {
	var empty drainwire.SignedStop
	p := observed.payload
	if observed.worker != w || w.node == nil || p.HostPID < 2 || p.Challenge.NodeID != w.node.ID() ||
		p.Challenge.InstanceID != w.node.admission.InstanceID || p.Challenge.Validate(time.Now().UTC()) != nil ||
		time.Since(p.ObservedAt) > time.Second {
		return empty, ErrGenericExecutionPending
	}
	current, err := w.agent.GenericExecutionSession(w.node.admission.InstanceID, w.node.ID())
	if err != nil || current.HostSessionID != p.Challenge.HostSessionID || current.HostEpoch != p.Challenge.HostEpoch ||
		current.RegistrationID != p.Challenge.RegistrationID || current.RegistrationGeneration != p.Challenge.RegistrationGeneration ||
		current.Cell != p.Challenge.Cell || current.HostNode != p.Challenge.HostNode {
		return empty, errors.Join(ErrGenericExecutionPending, err)
	}
	key, chain, err := w.node.nodeSigningKey()
	if err != nil {
		return empty, err
	}
	certificate, err := x509.ParseCertificate(chain[0])
	if err != nil || len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != "swarm-worker" {
		return empty, ErrGenericExecutionPending
	}
	wire, err := drainwire.StopSigningBytes(p)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	digest := sha256.Sum256(wire)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return empty, err
	}
	return drainwire.SignedStop{StopPayload: p, CertificateChain: chain, Signature: signature}, nil
}

func (c *controller) guardGenericStart(ctx context.Context) error {
	if !c.poolExecutionTask() {
		return nil
	}
	e := c.executor
	if e.genericExecution == nil {
		return ErrGenericExecutionPending
	}
	w, err := e.readGenericWitness(c.task.ID)
	if err != nil || w.Hold == nil || w.Process == nil || w.Closing || !time.Now().Before(w.Hold.Hold.ExpiresAt) {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	worker := e.genericExecution
	current, err := worker.agent.GenericExecutionSession(worker.node.admission.InstanceID, worker.node.ID())
	if err != nil || !current.SameIdentity(w.Hold.Hold.HostSession) {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	// The protected pool fence is reread after credential/runtime waits.
	reply, err := worker.agent.GenericExecution(ctx, host.GenericExecutionQuery{Action: "acquire", Task: c.task.Copy(), ExecutionSessionID: w.ExecutionSessionID})
	if err != nil || reply.Hold == nil || !sameGenericHold(*w.Hold, *reply.Hold) || !time.Now().Before(w.Hold.Hold.ExpiresAt) {
		return errors.Join(ErrGenericExecutionPending, err)
	}
	return nil
}

// Manager ownhost tasks are outside pool-worker retirement; DATA owns its holds.
// An unknown node role cannot bypass a worker's original execution admission.
func (c *controller) poolExecutionTask() bool {
	return c.stateful == nil && (c.executor.node == nil || c.executor.node.Role != api.NodeRoleManager)
}
