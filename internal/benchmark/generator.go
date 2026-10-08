package benchmark

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/core"
	sdk "terrascale.tech/sdk"
)

type Job struct {
	ID           string            `json:"id"`
	Region       string            `json:"region"`
	InstanceID   string            `json:"instance_id"`
	Workload     Workload          `json:"workload"`
	Clients      []string          `json:"clients"`
	Images       map[string]string `json:"images"`
	ClientID     vaultsecret.Ref   `json:"client_id"`
	ClientSecret vaultsecret.Ref   `json:"client_secret"`
	AuthOrigin   string            `json:"auth_origin"`
	AuthTenant   string            `json:"auth_tenant"`
}

func ociRegion(region string) (string, error) {
	switch region {
	case "gru":
		return "sa-saopaulo-1", nil
	case "sfo":
		return "us-sanjose-1", nil
	default:
		return "", errors.New("region must be gru or sfo")
	}
}

// Admission rejects every orchestrator-owned node, even one currently drained.
func admitInstance(instance core.Instance, region, id string) error {
	full, err := ociRegion(region)
	if err != nil {
		return err
	}
	if instance.Id == nil || *instance.Id != id || !strings.HasPrefix(id, "ocid1.instance.oc1."+full+".") || instance.LifecycleState != core.InstanceLifecycleStateRunning || instance.DisplayName == nil || strings.Contains(strings.ToLower(*instance.DisplayName), "desktop") || instance.FreeformTags["ts-benchmark"] != "load-generator" || instance.FreeformTags["ts-benchmark-region"] != region {
		return errors.New("generator must be a RUNNING, region-tagged dedicated benchmark instance")
	}
	for key, value := range instance.FreeformTags {
		if value != "" && (strings.HasPrefix(key, "terrascale-") || key == "ts-cell" || key == "ts-host-node" || key == "ts-managed-by" || key == "ts-resource" || key == "ts-owner" || key == "ts-pool") {
			return errors.New("generator is an orchestrator-owned resource; serving and drained cell nodes are forbidden")
		}
	}
	name := strings.ToLower(*instance.DisplayName)
	if strings.HasPrefix(name, "ts-gru-") || strings.HasPrefix(name, "ts-sfo-") || strings.HasPrefix(name, "gru-1-") || strings.HasPrefix(name, "sfo-1-") {
		return errors.New("cell node names are forbidden for generators")
	}
	return nil
}

type SSHGenerator struct {
	Address    string
	User       string
	WorkerPath string
	Job        Job
}

// Execute admits the OCI identity, pins SSH host keys, and bounds remote work.
func (g SSHGenerator) Execute(ctx context.Context, runID string, w Workload, clients []string, emit func(Sample) error) error {
	full, err := ociRegion(g.Job.Region)
	if err != nil {
		return err
	}
	factory, err := ociclient.OperatorConfig(full)
	if err != nil {
		return err
	}
	compute, err := factory.Compute()
	if err != nil {
		return err
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: &g.Job.InstanceID})
	if err != nil {
		return errors.New("cannot inspect generator OCI instance")
	}
	if err := admitInstance(response.Instance, g.Job.Region, g.Job.InstanceID); err != nil {
		return err
	}
	if net.ParseIP(g.Address) == nil || !namePattern.MatchString(g.User) || !workerPathPattern.MatchString(g.WorkerPath) {
		return errors.New("generator requires an IP address, SSH user and safe absolute ts-orch path")
	}
	if response.CompartmentId == nil {
		return errors.New("generator OCI compartment unavailable")
	}
	attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{InstanceId: &g.Job.InstanceID, CompartmentId: response.CompartmentId})
	if err != nil || attachments.OpcNextPage != nil {
		return errors.New("cannot verify generator network identity")
	}
	network, err := factory.Network()
	if err != nil {
		return err
	}
	matched := false
	for _, attachment := range attachments.Items {
		if attachment.InstanceId == nil || *attachment.InstanceId != g.Job.InstanceID || attachment.VnicId == nil || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
			continue
		}
		vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return errors.New("cannot inspect generator network identity")
		}
		if vnic.PrivateIp != nil && *vnic.PrivateIp == g.Address {
			matched = true
		}
	}
	if !matched {
		return errors.New("SSH address must match the admitted generator's OCI private VNIC IP")
	}
	// The worker independently checks its own IMDS identity against InstanceID;
	// an address pointing at another host cannot run this job.
	job := g.Job
	job.ID = newID()
	job.Workload = w
	job.Clients = clients
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "ssh", "-F", "/dev/null", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oClearAllForwardings=yes", "-oConnectTimeout=10", "--", g.User+"@"+g.Address, "timeout --signal=INT --kill-after=120s 900s nice -n 19 "+g.WorkerPath+" bench worker")
	command.Stdin = bytes.NewReader(data)
	pipe, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return errors.New("cannot start benchmark SSH worker")
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	var streamErr error
	for scanner.Scan() {
		var sample Sample
		if err := json.Unmarshal(scanner.Bytes(), &sample); err != nil {
			streamErr = errors.New("worker returned invalid JSONL")
			break
		}
		if err := emit(sample); err != nil {
			streamErr = err
			break
		}
	}
	if streamErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if streamErr != nil {
		return streamErr
	}
	if scanner.Err() != nil {
		return errors.New("worker stream exceeded limits or disconnected")
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("benchmark worker failed; inspect worker locally without printing credentials")
	}
	return nil
}

func localInstanceID(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer Oracle")
	client := http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return "", errors.New("worker must run on OCI")
	}
	defer response.Body.Close()
	var metadata struct {
		ID string `json:"id"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&metadata) != nil || metadata.ID == "" {
		return "", errors.New("worker OCI identity unavailable")
	}
	return metadata.ID, nil
}

func noServingProcesses() error {
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	if strings.EqualFold(host, "mariogk-desktop") {
		return errors.New("mariogk-desktop is forbidden")
	}
	paths, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		return err
	}
	for _, path := range paths {
		if path == fmt.Sprintf("/proc/%d/cmdline", os.Getpid()) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return errors.New("cannot prove generator process isolation")
		}
		parts := bytes.Split(data, []byte{0})
		if len(parts) == 0 {
			continue
		}
		name := strings.ToLower(filepath.Base(string(parts[0])))
		if strings.Contains(name, "terrabase") || strings.Contains(name, "tb-server") || strings.Contains(name, "ts-auth") || strings.Contains(name, "nats-server") {
			return errors.New("serving process exists on generator")
		}
		if name == "dotnet" && len(parts) > 1 {
			app := strings.ToLower(string(parts[1]))
			if strings.Contains(app, "terrabase") || strings.Contains(app, "auth") {
				return errors.New("serving dotnet process exists on generator")
			}
		}
		if (name == "ts-orch" || name == "terrascale-orchestrator") && len(parts) > 1 && (string(parts[1]) == "run" || string(parts[1]) == "host") {
			return errors.New("orchestrator runtime exists on generator")
		}
	}
	return nil
}

// Worker is a bounded load-generator job, never a regional workload allocation.
func Worker(ctx context.Context, in io.Reader, out io.Writer) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, MaxRun)
	defer cancel()
	var job Job
	decoder := json.NewDecoder(io.LimitReader(in, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil {
		return errors.New("invalid benchmark job")
	}
	if !idPattern.MatchString(job.ID) || job.Workload.Validate() != nil || len(job.Clients) < 1 || len(job.Clients) > 3 {
		return errors.New("invalid benchmark job bounds")
	}
	for i, client := range job.Clients {
		if !contains(languages, client) || contains(job.Clients[:i], client) || !imagePattern.MatchString(job.Images[client]) {
			return errors.New("clients require distinct languages and digest-pinned images")
		}
	}
	id, err := localInstanceID(ctx)
	if err != nil {
		return err
	}
	if id != job.InstanceID {
		return errors.New("SSH target does not match admitted OCI instance")
	}
	full, err := ociRegion(job.Region)
	if err != nil {
		return err
	}
	factory, err := ociclient.InstancePrincipal(full)
	if err != nil {
		return err
	}
	compute, err := factory.Compute()
	if err != nil {
		return err
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: &id})
	if err != nil {
		return errors.New("worker cannot inspect its OCI instance")
	}
	if err := admitInstance(response.Instance, job.Region, id); err != nil {
		return err
	}
	if err := noServingProcesses(); err != nil {
		return err
	}
	// Refuse unavailable images before reading any credential or creating jobs.
	for _, client := range job.Clients {
		if exec.CommandContext(ctx, "podman", "image", "exists", job.Images[client]).Run() != nil {
			return errors.New("benchmark client image is not preloaded on generator")
		}
	}
	secrets, err := vaultsecret.ReadRefs(ctx, map[string]vaultsecret.Ref{"TS_BENCH_CLIENT_ID": job.ClientID, "TS_BENCH_CLIENT_SECRET": job.ClientSecret})
	if err != nil {
		return err
	}
	auth, err := sdk.NewClient(sdk.Config{TSAuthBaseURL: job.AuthOrigin})
	if err != nil {
		return err
	}
	tenant, err := auth.TSAuth.Instance(job.AuthTenant)
	if err != nil {
		return err
	}
	if _, err := tenant.OIDC.RequestClientCredentialsToken(ctx, sdk.TSAuthOAuthClientAuthentication{ClientID: secrets["TS_BENCH_CLIENT_ID"], ClientSecret: secrets["TS_BENCH_CLIENT_SECRET"], Method: sdk.TSAuthClientSecretBasic}, ""); err != nil {
		return errors.New("benchmark client credentials authentication failed")
	}
	for _, secret := range secrets {
		if strings.ContainsAny(secret, "\n\r\x00") {
			return errors.New("benchmark credential cannot be represented as a container environment")
		}
	}
	return runContainers(ctx, job, secrets, out)
}

func runContainers(ctx context.Context, job Job, secrets map[string]string, out io.Writer) (resultErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	names := make([]string, 0, len(job.Clients))
	for _, client := range job.Clients {
		names = append(names, "bench-"+job.ID+"-"+client)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
		defer stop()
		// Names are newly generated ULIDs; never replace a pre-existing container.
		for _, name := range names {
			inspect := exec.CommandContext(cleanup, "podman", "inspect", "--format", "{{ index .Config.Labels \"ts-bench-job\" }}", name)
			data, err := inspect.Output()
			if err != nil {
				check := exec.CommandContext(cleanup, "podman", "container", "exists", name).Run()
				var exit *exec.ExitError
				if !errors.As(check, &exit) || exit.ExitCode() != 1 {
					resultErr = errors.Join(resultErr, errors.New("cannot verify benchmark container cleanup"))
				}
				continue
			}
			if strings.TrimSpace(string(data)) != job.ID {
				resultErr = errors.Join(resultErr, errors.New("refused cleanup of a foreign container"))
				continue
			}
			if exec.CommandContext(cleanup, "podman", "stop", "--ignore", "--time", "30", name).Run() != nil {
				resultErr = errors.Join(resultErr, errors.New("benchmark container stop failed"))
			}
			if exec.CommandContext(cleanup, "podman", "rm", "--force", "--ignore", name).Run() != nil {
				resultErr = errors.Join(resultErr, errors.New("benchmark container cleanup failed"))
			}
		}
	}()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var runErr error
	workload, _ := json.Marshal(job.Workload)
	for i, client := range job.Clients {
		wg.Add(1)
		go func(client, name string) {
			defer wg.Done()
			err := container(ctx, job, client, name, workload, secrets, func(line []byte) error {
				var sample Sample
				if json.Unmarshal(line, &sample) != nil {
					return errors.New("client returned malformed JSONL")
				}
				if err := sample.Validate(client, job.Region, job.Workload.Name); err != nil {
					return err
				}
				mu.Lock()
				defer mu.Unlock()
				_, err := out.Write(append(line, '\n'))
				return err
			})
			if err != nil {
				mu.Lock()
				runErr = errors.Join(runErr, err)
				mu.Unlock()
				cancel()
			}
		}(client, names[i])
	}
	wg.Wait()
	return runErr
}

func container(ctx context.Context, job Job, client, name string, workload []byte, secrets map[string]string, emit func([]byte) error) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer reader.Close()
	// Secrets cross an inherited pipe, never argv, logs, a disk file or stdin.
	env := fmt.Sprintf("TS_BENCH_CLIENT_ID=%s\nTS_BENCH_CLIENT_SECRET=%s\nTS_BENCH_RUN_ID=%s\n", secrets["TS_BENCH_CLIENT_ID"], secrets["TS_BENCH_CLIENT_SECRET"], newID())
	go func() { _, _ = io.WriteString(writer, env); _ = writer.Close() }()
	command := exec.CommandContext(ctx, "podman", "run", "--rm", "--pull=never", "--name", name, "--label", "ts-bench-job="+job.ID, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256", "--cpus=1", "--memory=1g", "--tmpfs", "/tmp:rw,size=256m", "--stop-signal=SIGINT", "--stop-timeout=30", "--timeout=840", "--env-file=/proc/self/fd/3", "-i", job.Images[client], "run", "--workload", "/dev/stdin", "--region", job.Region, "--out", "/dev/stdout")
	command.ExtraFiles = []*os.File{reader}
	command.Stdin = bytes.NewReader(workload)
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return errors.New("client container could not start")
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	var emitErr error
	for scanner.Scan() {
		if err := emit(bytes.Clone(scanner.Bytes())); err != nil {
			emitErr = err
			_ = command.Process.Kill()
			break
		}
	}
	err = command.Wait()
	if emitErr != nil {
		return emitErr
	}
	if scanner.Err() != nil {
		return errors.New("client JSONL exceeded limits")
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("benchmark client container failed")
	}
	return nil
}
