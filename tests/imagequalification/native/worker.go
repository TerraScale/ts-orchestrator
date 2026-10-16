package native

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	ocidigest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

const runtimeSocket = "/run/containerd/containerd.sock"
const managerPort = "4242"

// Serve is the test-only remote process protocol. The standalone executable must
// also dispatch CORE's runtime logger callback before calling Serve.
func Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	lifetime, cancel := context.WithTimeout(ctx, 16*time.Minute)
	defer cancel()
	w := &worker{ctx: lifetime}
	defer w.cleanup()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxFrame)

	for scanner.Scan() {
		var c command
		var result response
		if err := json.Unmarshal(scanner.Bytes(), &c, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		operation, cancel := context.WithTimeout(ctx, 45*time.Second)
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
	ctx       context.Context
	root      string
	cfg       swarmruntime.NodeConfig
	executor  *swarmruntime.Executor
	node      *swarmruntime.Node
	nodeID    string
	runtime   *containerd.Client
	partition []string
	services  map[string]bool
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
		for _, unit := range []string{"terrascale-orchestrator-host.service", "terrascale-orchestrator-controller.service", "netbird.service"} {
			err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", unit).Run()
			if err == nil {
				return response{}, errors.New("production service active: " + unit)
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || (exit.ExitCode() != 3 && exit.ExitCode() != 4) {
				return response{}, errors.New("production service status unavailable: " + unit)
			}
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
		if identity.InstanceID != c.Host.OCID || identity.ImageOCID != c.Host.ExpectedIdentity.ImageOCID || identity != c.Host.ExpectedIdentity {
			return response{}, errors.New("native host identity mismatch")
		}
		root := "/run/ts-native-" + c.RunID + "/state"
		if err := os.Mkdir(root, 0700); err != nil {
			return response{}, err
		}
		w.root = root
		w.cfg = swarmruntime.NodeConfig{StateDir: filepath.Join(root, "node"), ListenAddress: "0.0.0.0:" + managerPort, AdvertiseAddress: c.Host.Address + ":" + managerPort, Admission: swarmruntime.Admission{Region: c.Region, HostID: "native-" + c.RunID + "-" + strings.ReplaceAll(c.Host.Address, ".", "-"), InstanceID: c.Host.OCID, Role: c.Mode}}
		w.executor, err = swarmruntime.NewExecutor(runtimeSocket, root)
		if err != nil {
			return response{}, err
		}
		w.runtime, err = containerd.New(runtimeSocket, containerd.WithDefaultNamespace("terrascale"))
		if err != nil {
			return response{}, err
		}
		w.services = map[string]bool{}
		return response{Role: w.cfg.Admission.Role, Identity: identity, WorkerSHA256: workerHash, WorkerSourceRevision: source}, nil
	}
	if w.root == "" {
		return response{}, errors.New("identity must be verified before runtime operations")
	}
	switch c.Operation {
	case "import":
		archivePath := filepath.Join(filepath.Dir(w.root), "workload.oci")
		hash, err := fileDigest(archivePath)
		if err != nil {
			return response{}, err
		}
		if hash != c.ArchiveSHA256 {
			return response{}, errors.New("remote workload archive digest mismatch")
		}
		archive, err := os.Open(archivePath)
		if err != nil {
			return response{}, err
		}
		defer archive.Close()
		runtimeCtx := namespaces.WithNamespace(ctx, "terrascale")
		imported, err := w.runtime.Import(runtimeCtx, archive, containerd.WithImageRefTranslator(func(string) string { return "" }), containerd.WithDigestRef(func(d ocidigest.Digest) string {
			if strings.HasSuffix(c.Image, "@"+d.String()) {
				return c.Image
			}
			return ""
		}))
		if err != nil {
			return response{}, err
		}
		var found bool
		for _, image := range imported {
			if image.Name != c.Image {
				continue
			}
			if image.Target.MediaType != imagespec.MediaTypeImageManifest && image.Target.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
				return response{}, errors.New("workload requires native child manifest")
			}
			found = true
		}
		if !found {
			return response{}, errors.New("archive omitted pinned workload child manifest")
		}
		image, err := w.runtime.GetImage(runtimeCtx, c.Image)
		if err != nil {
			return response{}, err
		}
		configuration, err := image.Spec(runtimeCtx)
		if err != nil {
			return response{}, err
		}
		if configuration.OS != "linux" || configuration.Architecture != runtime.GOARCH {
			return response{}, errors.New("archive architecture mismatch")
		}
		return response{}, image.Unpack(runtimeCtx, "native")
	case "start":
		if w.node != nil {
			return response{}, errors.New("node already started")
		}
		if w.cfg.Admission.FounderID == "" {
			w.cfg.Admission.FounderID = c.Founder
			if c.Founder == "" {
				w.cfg.Admission.FounderID = w.cfg.Admission.HostID
			}
			w.cfg.Admission.ManagerAddress, w.cfg.Admission.JoinToken = c.JoinAddress, c.Token
		}
		// Node lifetime is the protocol process, not one command deadline.
		n, err := swarmruntime.StartNode(w.ctx, w.cfg, w.executor)
		if err != nil {
			return response{}, err
		}
		w.node = n
		w.nodeID = n.ID()
		return response{NodeID: n.ID()}, nil
	case "stop":
		if w.node == nil {
			return response{}, errors.New("node already stopped")
		}
		err := w.node.Stop(ctx)
		w.node = nil
		return response{}, err
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
	}
	if w.node == nil {
		return response{}, errors.New("manager is stopped")
	}
	client, err := w.node.ControlClient(ctx)
	if err != nil {
		return response{}, err
	}
	switch c.Operation {
	case "join-material":
		clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
		if err != nil {
			return response{}, err
		}
		if len(clusters.Clusters) != 1 {
			return response{}, errors.New("expected one regional cluster")
		}
		return response{Token: clusters.Clusters[0].RootCA.JoinTokens.Manager, WorkerToken: clusters.Clusters[0].RootCA.JoinTokens.Worker}, nil
	case "admit":
		admission := w.cfg.Admission
		admission.HostID = "native-" + c.RunID + "-" + strings.ReplaceAll(c.Host.Address, ".", "-")
		admission.InstanceID = c.Host.OCID
		admission.Role = c.Mode
		_, err := swarmruntime.AdmitNode(ctx, client, c.NodeID, admission)
		return response{}, err
	case "cluster":
		nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		result := response{}
		if err != nil {
			return result, err
		}
		for _, n := range nodes.Nodes {
			if n.ManagerStatus != nil && n.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE {
				result.Managers++
				if n.ManagerStatus.Leader {
					result.Leader = n.ID
				}
			}
		}
		return result, nil
	case "pause", "activate":
		found, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: c.NodeID})
		if err != nil {
			return response{}, err
		}
		spec := found.Node.Spec.Copy()
		spec.Availability = api.NodeAvailabilityPause
		if c.Operation == "activate" {
			spec.Availability = api.NodeAvailabilityActive
		}
		_, err = client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: c.NodeID, NodeVersion: &found.Node.Meta.Version, Spec: spec})
		return response{}, err
	case "create":
		spec, err := infrastructureService(c)
		if err != nil {
			return response{}, err
		}
		created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: spec})
		if err != nil {
			return response{}, err
		}
		w.services[created.Service.ID] = true
		return response{ServiceID: created.Service.ID}, nil
	case "observe":
		view, err := swarmruntime.ObserveService(ctx, client, c.ServiceID, func(ctx context.Context, task *api.Task) error {
			ip, err := netip.ParseAddr(c.Addresses[task.NodeID])
			if err != nil {
				return err
			}
			return swarmruntime.ProbeTask(ctx, task, ip)
		})
		if err != nil {
			return response{}, err
		}
		result := response{Running: view.RunningReplicas, Ready: view.ReadyReplicas, UpdateState: view.UpdateState}
		for _, t := range view.Tasks {
			if t.State == "RUNNING" && t.Ready {
				result.Tasks = append(result.Tasks, taskState{ID: t.TaskID, NodeID: t.NodeID})
			}
		}
		return result, nil
	case "break-update":
		service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: c.ServiceID})
		if err != nil {
			return response{}, err
		}
		spec := service.Service.Spec.Copy()
		encoded, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: c.Image, User: "65532:65532", Command: []string{"/bin/sh", "-c", "exit 17"}})
		if err != nil {
			return response{}, err
		}
		spec.Task.Runtime = encoded
		_, err = client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: c.ServiceID, ServiceVersion: &service.Service.Meta.Version, Spec: spec})
		return response{}, err
	case "remove":
		_, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: c.ServiceID})
		delete(w.services, c.ServiceID)
		return response{}, err
	default:
		return response{}, errors.New("unknown native operation")
	}
}

func infrastructureService(c command) (*api.ServiceSpec, error) {
	if c.Port < 1024 || c.Port > 65535 {
		return nil, errors.New("invalid infrastructure test port")
	}
	status, body := "200 OK", "ready"
	if c.Mode == "unready" {
		status, body = "503 Service Unavailable", "unready"
	}
	script := fmt.Sprintf("exec nc -lk -p %d -e /bin/sh -c \"printf 'HTTP/1.1 %s\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s'\"", c.Port, status, len(body), body)
	encoded, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: c.Image, User: "65532:65532", Command: []string{"/bin/sh", "-c", script}})
	if err != nil {
		return nil, err
	}
	// Infrastructure fixture intentionally exercises upstream task/runtime mapping;
	// it never substitutes for signed first-party production release admission.
	resources := &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}
	return &api.ServiceSpec{
		Annotations: api.Annotations{Name: "native-" + c.RunID + "-" + c.Mode, Labels: map[string]string{swarmruntime.LabelRegion: c.Region}},
		Task:        api.TaskSpec{Runtime: encoded, Resources: &api.ResourceRequirements{Limits: resources, Reservations: resources.Copy()}, Placement: &api.Placement{Constraints: []string{"node.labels." + swarmruntime.LabelRegion + "==" + c.Region, "node.labels." + swarmruntime.LabelExecutionScope + "==platform"}}, Restart: &api.RestartPolicy{Condition: api.RestartOnAny, Delay: types.DurationProto(time.Second)}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}},
		Endpoint:    &api.EndpointSpec{Mode: api.ResolutionModeDNSRoundRobin, Ports: []*api.PortConfig{{Name: "ready", Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, TargetPort: c.Port, PublishedPort: c.Port}}},
		Update:      &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_ROLLBACK, Monitor: types.DurationProto(5 * time.Second), Order: api.UpdateConfig_STOP_FIRST},
		Rollback:    &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_PAUSE, Monitor: types.DurationProto(5 * time.Second), Order: api.UpdateConfig_STOP_FIRST},
	}, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = w.heal(ctx)
	if w.node != nil {
		if client, err := w.node.ControlClient(ctx); err == nil {
			for id := range w.services {
				_, _ = client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: id})
			}
		}
		_ = w.node.Stop(ctx)
	}
	if w.executor != nil {
		_ = w.executor.Close()
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
