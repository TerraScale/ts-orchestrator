package native

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const runtimeSocket = "/run/containerd/containerd.sock"
const managerPort = "2377"
const runtimeUnit = "terrascale-orchestrator-managed-runtime.service"
const candidateBinary = "/usr/local/bin/terrascale-orchestrator"

// Serve observes the installed candidate and injects faults on approved disposable hosts.
func Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	lifetime, cancel := context.WithTimeout(ctx, 16*time.Minute)
	defer cancel()
	w := &worker{}
	defer w.cleanup()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxFrame)
	for scanner.Scan() {
		var c command
		if err := json.Unmarshal(scanner.Bytes(), &c, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		operation, cancel := context.WithTimeout(lifetime, 45*time.Second)
		result, err := w.execute(operation, c)
		cancel()
		if err != nil {
			result.Error = err.Error()
		}
		if err := json.MarshalWrite(output, result, json.Deterministic(true)); err != nil {
			return err
		}
		if _, err := io.WriteString(output, "\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
}

type worker struct {
	root, nodeID, role, binaryHash string
	runtime                        *containerd.Client
	partition                      []string
	stopped                        bool
}

func (w *worker) execute(ctx context.Context, c command) (response, error) {
	if c.Operation == "identity" {
		if w.root != "" {
			return response{}, errors.New("worker already initialized")
		}
		if err := validateRunID(c.RunID); err != nil {
			return response{}, err
		}
		if os.Geteuid() != 0 {
			return response{}, errors.New("disposable native worker requires root")
		}
		marker, err := os.ReadFile("/run/ts-native-disposable")
		if err != nil || strings.TrimSpace(string(marker)) != c.RunID {
			return response{}, errors.New("disposable launch marker absent or wrong run")
		}
		workerHash, source, err := workerIdentity()
		if err != nil {
			return response{}, err
		}
		if source != c.SourceRevision {
			return response{}, errors.New("native worker source revision differs from candidate")
		}
		identity, err := MeasureIdentity(ctx, c.ContainerdPath, c.RuncPath)
		if err != nil {
			return response{}, err
		}
		if identity != c.Host.ExpectedIdentity || identity.InstanceID != c.Host.OCID {
			return response{}, errors.New("native host identity mismatch")
		}
		if c.Mode != "manager" && c.Mode != "container" {
			return response{}, errors.New("invalid installed runtime role")
		}
		root := "/var/lib/terrascale-orchestrator-host/swarm"
		if c.Mode == "container" {
			root += "-worker"
		}
		cert, err := os.ReadFile(filepath.Join(root, "node/certificates/swarm-node.crt"))
		if err != nil {
			return response{}, err
		}
		block, _ := pem.Decode(cert)
		if block == nil {
			return response{}, errors.New("installed runtime certificate missing")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return response{}, err
		}
		expectedRole := "swarm-manager"
		if c.Mode == "container" {
			expectedRole = "swarm-worker"
		}
		if leaf.Subject.CommonName == "" || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != expectedRole {
			return response{}, errors.New("installed runtime certificate role mismatch")
		}
		w.root, w.nodeID, w.role, w.binaryHash = root, leaf.Subject.CommonName, c.Mode, identity.BinarySHA256
		if err := w.installedProcess(ctx); err != nil {
			w.root = ""
			return response{}, err
		}
		w.runtime, err = containerd.New(runtimeSocket, containerd.WithDefaultNamespace("terrascale"))
		if err != nil {
			return response{}, err
		}
		return response{Role: c.Mode, NodeID: w.nodeID, Identity: identity, WorkerSHA256: workerHash, WorkerSourceRevision: source}, nil
	}
	if w.root == "" {
		return response{}, errors.New("identity must be verified before runtime operations")
	}
	switch c.Operation {
	case "stop":
		if w.stopped {
			return response{}, errors.New("runtime already stopped")
		}
		w.stopped = true
		if out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", runtimeUnit).CombinedOutput(); err != nil {
			return response{}, fmt.Errorf("stop installed runtime: %w: %s", err, out)
		}
		return response{}, nil
	case "restore":
		if !w.stopped {
			return response{}, nil
		}
		fallthrough
	case "start":
		if !w.stopped {
			return response{}, errors.New("runtime was not stopped by this worker")
		}
		args := []string{"start", runtimeUnit}
		if w.role == "manager" {
			args = append(args, "terrascale-orchestrator-controller.service")
		}
		if out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput(); err != nil {
			return response{}, fmt.Errorf("restart installed runtime: %w: %s", err, out)
		}
		w.stopped = false
		if err := w.installedProcess(ctx); err != nil {
			return response{}, err
		}
		cert, err := os.ReadFile(filepath.Join(w.root, "node/certificates/swarm-node.crt"))
		if err != nil {
			return response{}, err
		}
		block, _ := pem.Decode(cert)
		if block == nil {
			return response{}, errors.New("runtime certificate disappeared")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || leaf.Subject.CommonName != w.nodeID {
			return response{}, errors.New("runtime restart replaced certificate identity")
		}
		return response{NodeID: w.nodeID}, nil
	case "partition":
		if len(w.partition) != 0 {
			return response{}, errors.New("partition already applied")
		}
		for _, ip := range c.Peers {
			a, err := netip.ParseAddr(ip)
			if err != nil || !a.Is4() || !a.IsPrivate() {
				return response{}, errors.New("partition peer must be private IPv4")
			}
		}
		for _, ip := range c.Peers {
			w.partition = append(w.partition, ip)
			if err := partitionRule(ctx, "-I", ip); err != nil {
				return response{}, err
			}
		}
		return response{}, nil
	case "heal":
		return response{}, w.heal(ctx)
	case "inventory":
		return w.inventory(ctx, c.ServiceID)
	case "http-probe":
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/readyz", nil)
		if err != nil {
			return response{}, err
		}
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		result, err := client.Do(request)
		if err != nil {
			return response{}, err
		}
		defer result.Body.Close()
		if result.StatusCode != http.StatusOK {
			return response{}, fmt.Errorf("application readiness HTTP %d", result.StatusCode)
		}
		return response{}, nil
	}
	if c.Operation != "cluster" && c.Operation != "observe" {
		return response{}, errors.New("unknown native observation or fault operation")
	}
	if w.role != "manager" || w.stopped {
		return response{}, errors.New("installed manager unavailable")
	}
	client, closer, err := w.control(ctx)
	if err != nil {
		return response{}, err
	}
	defer closer.Close()
	switch c.Operation {
	case "cluster":
		nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return response{}, err
		}
		result := response{}
		for _, n := range nodes.Nodes {
			if n.ManagerStatus != nil && n.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE {
				result.Managers++
				if n.ManagerStatus.Leader {
					result.Leader = n.ID
				}
			}
		}
		return result, nil
	case "observe":
		// The signed stable intent ID is a label; the upstream service ID is assigned by SwarmKit.
		listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
		if err != nil {
			return response{}, err
		}
		var service *api.Service
		for _, s := range listed.Services {
			if s.Spec.Annotations.Labels[swarmruntime.LabelIntentID] == c.ServiceID {
				if service != nil {
					return response{}, errors.New("duplicate stable service identity")
				}
				service = s
			}
		}
		if service == nil {
			return response{}, errors.New("signed service has not been delivered")
		}
		var expected *swarmruntime.ServiceIntent
		for i := range c.Expected {
			candidate := &c.Expected[i]
			if candidate.ID == c.ServiceID && candidate.OperationID == service.Spec.Annotations.Labels[swarmruntime.LabelOperationID] {
				expected = candidate
				break
			}
		}
		if expected == nil {
			return response{}, errors.New("observed service has no approved signed phase")
		}
		if err := verifyObservedService(service, *expected); err != nil {
			return response{}, err
		}
		view, err := swarmruntime.ObserveService(ctx, client, service.ID, func(ctx context.Context, task *api.Task) error {
			ip, err := netip.ParseAddr(c.Addresses[task.NodeID])
			if err != nil {
				return err
			}
			return swarmruntime.ProbeTask(ctx, task, ip)
		})
		if err != nil {
			return response{}, err
		}
		result := response{ServiceID: service.ID, OperationID: service.Spec.Annotations.Labels[swarmruntime.LabelOperationID], Running: view.RunningReplicas, Ready: view.ReadyReplicas, UpdateState: view.UpdateState}
		for _, t := range view.Tasks {
			if t.State == "RUNNING" && t.Ready {
				result.Tasks = append(result.Tasks, taskState{ID: t.TaskID, NodeID: t.NodeID})
			}
		}
		return result, nil
	default:
		return response{}, errors.New("unknown native observation or fault operation")
	}
}

func verifyObservedService(service *api.Service, expected swarmruntime.ServiceIntent) error {
	actual, err := swarmruntime.DecodeContainer(&api.Task{ID: "observation", ServiceID: service.ID, Spec: service.Spec.Task})
	if err != nil {
		return err
	}
	if !proto.Equal(actual, expected.Container) || !proto.Equal(service.Spec.Task.Resources, expected.Resources) || service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas != expected.Replicas || service.Spec.Endpoint == nil || len(service.Spec.Endpoint.Ports) != len(expected.Ports) {
		return errors.New("observed service differs from signed args, resources or endpoint")
	}
	for i, port := range expected.Ports {
		if !proto.Equal(service.Spec.Endpoint.Ports[i], port) {
			return errors.New("observed service endpoint differs from signed profile")
		}
	}
	return nil
}

func (w *worker) installedProcess(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", runtimeUnit, "--property=MainPID", "--value").Output()
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid < 1 {
		return errors.New("installed managed runtime is not running")
	}
	hash, err := fileDigest(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || hash != w.binaryHash {
		return errors.New("running managed runtime binary differs from approved image")
	}
	command, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || string(command) != candidateBinary+"\x00managed-runtime-start\x00" {
		return errors.New("installed runtime does not execute the candidate managed-runtime-start")
	}
	return nil
}

func (w *worker) control(ctx context.Context) (api.ControlClient, io.Closer, error) {
	root, err := os.ReadFile(filepath.Join(w.root, "node/certificates/swarm-root-ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		return nil, nil, errors.New("installed runtime CA missing")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != w.nodeID {
			return errors.New("control socket certificate identity mismatch")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
		return err
	}}
	socket := filepath.Join(w.root, "node/control.sock")
	connection, err := grpc.NewClient("passthrough:///"+socket, grpc.WithTransportCredentials(credentials.NewTLS(config)), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}))
	if err != nil {
		return nil, nil, err
	}
	return api.NewControlClient(connection), connection, nil
}

func (w *worker) inventory(ctx context.Context, service string) (response, error) {
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	containers, err := w.runtime.Containers(ctx, "labels.terrascale.service=="+service)
	if err != nil {
		return response{}, err
	}
	result := response{}
	for _, container := range containers {
		t, err := container.Task(ctx, nil)
		if err != nil {
			return result, err
		}
		spec, err := container.Spec(ctx)
		if err != nil {
			return result, err
		}
		p := spec.Process
		secure := p != nil && p.User.UID == 65532 && p.User.GID == 65532 && p.NoNewPrivileges && spec.Root != nil && spec.Root.Readonly && spec.Linux != nil && spec.Linux.Seccomp != nil
		if p != nil && p.Capabilities != nil {
			secure = secure && len(p.Capabilities.Bounding) == 0 && len(p.Capabilities.Permitted) == 0 && len(p.Capabilities.Effective) == 0 && len(p.Capabilities.Inheritable) == 0 && len(p.Capabilities.Ambient) == 0
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", t.Pid()))
		if err != nil {
			return result, err
		}
		mountinfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", t.Pid()))
		if err != nil {
			return result, err
		}
		var readonly bool
		for line := range strings.SplitSeq(string(mountinfo), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 5 && fields[4] == "/" {
				readonly = strings.Contains(","+fields[5]+",", ",ro,")
			}
		}
		secure = secure && readonly
		for _, namespace := range []string{"pid", "mnt"} {
			child, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", t.Pid(), namespace))
			if err != nil {
				return result, err
			}
			own, err := os.Readlink("/proc/self/ns/" + namespace)
			if err != nil {
				return result, err
			}
			secure = secure && child != own
		}
		actual := string(status)
		secure = secure && strings.Contains(actual, "Uid:\t65532\t65532\t65532\t65532") && strings.Contains(actual, "Gid:\t65532\t65532\t65532\t65532") && strings.Contains(actual, "NoNewPrivs:\t1") && strings.Contains(actual, "Seccomp:\t2") && strings.Contains(actual, "CapEff:\t0000000000000000")
		result.Tasks = append(result.Tasks, taskState{ID: strings.TrimPrefix(container.ID(), "ts-"), NodeID: w.nodeID, PID: t.Pid(), Containers: len(containers), Secure: secure})
	}
	return result, nil
}

func partitionRule(ctx context.Context, operation, ip string) error {
	var errs []error
	for _, chain := range []string{"INPUT", "OUTPUT"} {
		flag := "-s"
		if chain == "OUTPUT" {
			flag = "-d"
		}
		for _, portFlag := range []string{"--sport", "--dport"} {
			args := []string{"-w", "5", operation, chain, flag, ip, "-p", "tcp", portFlag, managerPort, "-j", "DROP"}
			if out, err := exec.CommandContext(ctx, "/usr/sbin/iptables", args...).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Errorf("partition rule: %w: %s", err, out))
			}
		}
	}
	return errors.Join(errs...)
}

func (w *worker) heal(ctx context.Context) error {
	var errs []error
	for _, ip := range w.partition {
		errs = append(errs, partitionRule(ctx, "-D", ip))
	}
	if errors.Join(errs...) == nil {
		w.partition = nil
	}
	return errors.Join(errs...)
}

func (w *worker) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	_ = w.heal(ctx)
	if w.stopped {
		_, _ = w.execute(ctx, command{Operation: "start"})
	}
	if w.runtime != nil {
		_ = w.runtime.Close()
	}
}

func workerIdentity() (string, string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", errors.New("native worker lacks build provenance")
	}
	var revision string
	for _, setting := range info.Settings {
		if setting.Key == "vcs.modified" && setting.Value != "false" {
			return "", "", errors.New("native worker built from modified source")
		}
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
	}
	if revision == "" {
		return "", "", errors.New("native worker lacks source revision")
	}
	executable, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	hash, err := fileDigest(executable)
	return hash, revision, err
}
