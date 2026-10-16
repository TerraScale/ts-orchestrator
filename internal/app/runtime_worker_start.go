package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/sdnotify"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/moby/swarmkit/v2/api"
)

const runtimeWorkerDirectory = "/var/lib/terrascale-orchestrator-host/swarm-worker"
const runtimeWorkerConfigPath = "/etc/terrascale-orchestrator/host.json"
const runtimeWorkerPublicPath = "/etc/terrascale-orchestrator/host-enrollment-public.json"

func setupRuntimeWorker(ctx context.Context, output io.Writer) error {
	return runHostSetup(ctx, []string{"--public-config", runtimeWorkerPublicPath,
		"--output-root", filepath.Dir(runtimeWorkerConfigPath)}, output)
}

func readRuntimeWorker(ctx context.Context) (hostenroll.VerifiedSwarmWorker, hostenroll.PublicBundle, error) {
	bundle, err := hostenroll.ReadPublicBundle(runtimeWorkerPublicPath)
	if err != nil {
		return hostenroll.VerifiedSwarmWorker{}, bundle, err
	}
	wire, err := readRuntimeWorkerTransport()
	if err != nil {
		return hostenroll.VerifiedSwarmWorker{}, bundle, err
	}
	accepted, err := verifyRuntimeWorker(ctx, bundle, wire)
	return accepted, bundle, err
}

func verifyRuntimeWorker(ctx context.Context, bundle hostenroll.PublicBundle, wire []byte) (hostenroll.VerifiedSwarmWorker, error) {
	metadata, err := hostenroll.ReadInstanceMetadata(ctx, hostenroll.NewIMDSClient())
	if errors.Is(err, hostenroll.ErrNotManagedHost) {
		metadata, err = hostenroll.ReadPoolNodeMetadata(ctx, hostenroll.NewIMDSClient(), bundle.Cell, bundle.Region)
	}
	if err != nil {
		return hostenroll.VerifiedSwarmWorker{}, err
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return hostenroll.VerifiedSwarmWorker{}, err
	}
	return hostenroll.VerifyWorkerTransport(wire, public, metadata, runtime.GOARCH, time.Now().UTC())
}

func readRuntimeWorkerTransport() ([]byte, error) {
	path := filepath.Join(filepath.Dir(runtimeWorkerConfigPath), runtimeWorkerTransportFilename)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	limit := int64(2 * (hostenroll.MaxRequestBytes + hostenroll.MaxResponseBytes))
	if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("worker transport must be a bounded root-owned private regular file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(wire)) > limit {
		return nil, errors.New("worker transport read failed or exceeded its bound")
	}
	return wire, nil
}

type functionMaterialSource struct{ agent *host.Agent }

func (source functionMaterialSource) CurrentFunctionMaterial(ctx context.Context, binding swarmruntime.FunctionTaskBinding) (swarmruntime.FunctionMaterial, error) {
	material, err := source.agent.CurrentFunctionMaterial(ctx, host.FunctionMaterialBinding{
		TaskID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID,
		InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID, Fingerprint: binding.Fingerprint,
	})
	return swarmruntime.FunctionMaterial{Binding: binding, ExpiresAt: material.ExpiresAt, CredentialExpiresAt: material.CredentialExpiresAt, Files: material.Files}, err
}

// runRuntimeWorker owns one signed host session and one accepted embedded node.
func runRuntimeWorker(ctx context.Context, output io.Writer) error {
	if err := setupRuntimeWorker(ctx, output); err != nil {
		return err
	}
	accepted, bundle, err := readRuntimeWorker(ctx)
	if err != nil {
		if err := refreshRuntimeWorkerTransport(ctx); err != nil {
			return fmt.Errorf("refresh current runtime worker recipient: %w", err)
		}
		accepted, bundle, err = readRuntimeWorker(ctx)
		if err != nil {
			return fmt.Errorf("verify refreshed runtime worker recipient: %w", err)
		}
	}
	cfg, err := LoadConfig(runtimeWorkerConfigPath)
	if err != nil {
		return err
	}
	key, err := readPrivateKey(cfg.Host.IdentityKeyFile)
	if err != nil {
		return err
	}
	defer clear(key)
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return err
	}
	natsUser, err := hostNATSUserPublicKey(cfg.NATS)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cfg.NATS.ClientRole = "host"
	cfg.NATS.ReloadClientMaterial = hostCredentialReloader(runtimeWorkerConfigPath, cfg, key)
	broker, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer broker.Close()
	ready := make(chan struct{})
	agent, err := host.NewAgent(host.AgentConfig{Cell: cfg.NATS.Cell, Node: cfg.Host.Node,
		Environment: cfg.Host.Environment, Roles: cfg.Host.Roles, Conn: broker.Conn(), Identity: key,
		NATSUserPublicKey: natsUser, ControllerPublicKey: public,
		InstallRoot: cfg.Host.InstallRoot, StateRoot: cfg.Host.StateRoot,
		WorkloadIdentity: host.WorkloadIdentity{UID: cfg.Host.WorkloadUID, GID: cfg.Host.WorkloadGID},
		ClockCheck:       controllerClockCheck(hostClockProbe()),
		FollowRollouts:   hostRollouts(cfg, key, public), FollowNetBird: hostNetBird(cfg, public),
		Initialized: func() { close(ready) },
	})
	if err != nil {
		return err
	}
	sessionDone := make(chan error, 1)
	go func() { sessionDone <- agent.RunSession(ctx); cancel() }()
	defer func() { cancel(); <-sessionDone }()
	select {
	case <-ready:
	case <-ctx.Done():
		return errors.New("worker host session stopped before admission")
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return err
	}
	signed := accepted.Worker()
	if local.instanceID != signed.InstanceID || local.factory.Region() != signed.OCIRegion {
		return errors.New("worker OCI principal differs from current enrolled recipient")
	}
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return err
	}
	executor, err := swarmruntime.NewExecutor("/run/containerd/containerd.sock", runtimeWorkerDirectory)
	if err != nil {
		return err
	}
	defer executor.Close()
	admission := swarmruntime.Admission{Region: signed.Region, HostID: signed.RegistrationID,
		InstanceID: signed.InstanceID, FounderID: signed.FounderID, Role: signed.Role, ManagerAddress: signed.ManagerAddress}
	switch signed.Role {
	case "container":
		err = executor.BindContainerMaterial(admission, containerMaterialSource{agent})
	case "wasm":
		err = executor.BindFunctionMaterial(admission, functionMaterialSource{agent})
	default:
		err = errors.New("runtime enrollment has no supported worker role")
	}
	if err != nil {
		return err
	}
	var enrollmentMu sync.Mutex
	var node *swarmruntime.Node
	// New pulls reobserve the installed projection; task lifetime is independent
	// of the short enrollment projection's expiry.
	if err := executor.SetRegistryResolver(func(pullCtx context.Context, task *api.Task, recipient *api.Node) (remotes.Resolver, error) {
		enrollmentMu.Lock()
		defer enrollmentMu.Unlock()
		current, currentBundle, err := readRuntimeWorker(pullCtx)
		if err != nil {
			if err := refreshRuntimeWorkerTransport(pullCtx); err != nil {
				return nil, err
			}
			current, currentBundle, err = readRuntimeWorker(pullCtx)
		}
		if err != nil {
			return nil, err
		}
		if node == nil {
			return nil, errors.New("worker registry awaits actual node join")
		}
		if err := postRuntimeWorkerBinding(pullCtx, currentBundle, current, node, key); err != nil {
			return nil, err
		}
		var resolver swarmruntime.RegistryResolver
		if signed.Role == "wasm" {
			resolver, err = functionRuntimeRegistryResolver(pullCtx, cfg, agent, current)
		} else {
			resolver, err = workerRuntimeRegistryResolver(pullCtx, cfg, agent, current)
		}
		if err != nil {
			return nil, err
		}
		return resolver(pullCtx, task, recipient)
	}); err != nil {
		return err
	}
	joined, err := swarmruntime.StartAcceptedWorker(ctx, accepted, &bundles, executor)
	if err != nil {
		return err
	}
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = joined.Stop(stop)
	}()
	enrollmentMu.Lock()
	node = joined
	enrollmentMu.Unlock()
	if err := postRuntimeWorkerBinding(ctx, bundle, accepted, joined, key); err != nil {
		return err
	}
	renewalDone := make(chan struct{})
	go func() {
		defer close(renewalDone)
		previous := accepted.Wire()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			}
			enrollmentMu.Lock()
			current, currentBundle, err := readRuntimeWorker(ctx)
			if err == nil && !bytes.Equal(previous, current.Wire()) {
				if postRuntimeWorkerBinding(ctx, currentBundle, current, joined, key) == nil {
					previous = current.Wire()
				}
			}
			enrollmentMu.Unlock()
		}
	}()
	defer func() { cancel(); <-renewalDone }()
	if signed.Role == "container" {
		location, err := instancePrincipalChannel(signed.OCIRegion, signed.Cell).get(ctx)
		if err != nil {
			return err
		}
		initialize, done := context.WithTimeout(ctx, 30*time.Second)
		err = executor.InitializeStateful(initialize, agent, signed.InstanceID, joined, local.baked.Roots,
			location, filepath.Join(runtimeWorkerDirectory, "execution"))
		done()
		if err != nil {
			return err
		}
	}
	notifier := sdnotify.FromEnvironment()
	if err := notifier.Ready("accepted worker node and signed host session ready"); err != nil {
		return err
	}
	defer func() { _ = notifier.Stopping() }()
	if _, err := fmt.Fprintln(output, "accepted runtime worker ready"); err != nil {
		return err
	}
	return joined.Wait(ctx)
}

func postRuntimeWorkerBinding(ctx context.Context, bundle hostenroll.PublicBundle, accepted hostenroll.VerifiedSwarmWorker,
	node *swarmruntime.Node, key ed25519.PrivateKey,
) error {
	binding, err := node.WorkerBinding(accepted, key)
	if err != nil {
		return err
	}
	var transport hostenroll.WorkerTransport
	if err := json.Unmarshal(accepted.Wire(), &transport, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(runtimeWorkerBinding{Query: swarmruntime.WorkerRegistrationQuery{
		Request: transport.Request, Response: transport.Response}, Binding: binding})
	if err != nil {
		return err
	}
	_, err = postRuntimeWorkerDocument(ctx, bundle, "/v1/runtime/worker-bind", wire, http.StatusNoContent)
	return err
}

func refreshRuntimeWorkerTransport(ctx context.Context) error {
	bundle, err := hostenroll.ReadPublicBundle(runtimeWorkerPublicPath)
	if err != nil {
		return err
	}
	wire, err := readRuntimeWorkerTransport()
	if err != nil {
		return err
	}
	response, err := postRuntimeWorkerDocument(ctx, bundle, "/v1/runtime/worker-refresh", wire, http.StatusOK)
	if err != nil {
		return err
	}
	var previous, current hostenroll.WorkerTransport
	if protocol.DecodeStrict(wire, &previous, 2*(hostenroll.MaxRequestBytes+hostenroll.MaxResponseBytes)) != nil ||
		protocol.DecodeStrict(response, &current, 2*(hostenroll.MaxRequestBytes+hostenroll.MaxResponseBytes)) != nil ||
		!bytes.Equal(previous.Request, current.Request) {
		return errors.New("worker projection refresh changed its enrollment request")
	}
	if _, err := verifyRuntimeWorker(ctx, bundle, response); err != nil {
		return err
	}
	return writeAtomicHostFile(filepath.Join(filepath.Dir(runtimeWorkerConfigPath), runtimeWorkerTransportFilename), response, 0o600)
}

func postRuntimeWorkerDocument(ctx context.Context, bundle hostenroll.PublicBundle, path string, wire []byte, status int) ([]byte, error) {
	roots, err := bundle.RootCAs()
	if err != nil {
		return nil, err
	}
	httpTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer httpTransport.CloseIdleConnections()
	client := &http.Client{Transport: httpTransport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error
	for _, endpoint := range bundle.ControllerEndpoints {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+endpoint+path, bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			last = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 2*(hostenroll.MaxRequestBytes+hostenroll.MaxResponseBytes)+1))
		_ = response.Body.Close()
		if response.StatusCode == status && readErr == nil && len(body) <= 2*(hostenroll.MaxRequestBytes+hostenroll.MaxResponseBytes) {
			return body, nil
		}
		last = fmt.Errorf("worker binding admission returned status %d", response.StatusCode)
	}
	return nil, fmt.Errorf("private runtime worker request: %w", last)
}
