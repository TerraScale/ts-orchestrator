package native

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerProtocolSubprocessRejectsUnverifiedHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	process.Env = append(os.Environ(), "TS_NATIVE_PROTOCOL_FIXTURE=1")
	in, err := process.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(in, "{\"operation\":\"cluster\"}\n"); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() {
		t.Fatalf("worker returned no frame: %v", scanner.Err())
	}
	var result response
	if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Error, "identity must be verified") {
		t.Fatalf("unverified worker operated: %+v", result)
	}
	in.Close()
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("TS_NATIVE_PROTOCOL_FIXTURE") == "1" {
		if err := Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestContinuousHTTPRecordsProcessWindowAndRejectsOutage(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, "ready")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "process-marker")
	var samples atomic.Int32
	action := func() error {
		child := exec.CommandContext(ctx, "sh", "-c", "printf observed > \"$1\"; sleep 0.35", "fixture", marker)
		if err := child.Run(); err != nil {
			return err
		}
		wire, err := os.ReadFile(marker)
		if err != nil {
			return err
		}
		if string(wire) != "observed" {
			return errors.New("child filesystem observation missing")
		}
		return nil
	}
	if err := continuous(ctx, func(ctx context.Context) error {
		return probeHTTP(ctx, server.URL+"/readyz", (&net.Dialer{}).DialContext)
	}, action, func(error) { samples.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if samples.Load() < 3 {
		t.Fatalf("only %d HTTP samples during child process", samples.Load())
	}
	err := continuous(ctx, func(ctx context.Context) error {
		return probeHTTP(ctx, server.URL+"/readyz", (&net.Dialer{}).DialContext)
	}, func() error {
		status.Store(http.StatusServiceUnavailable)
		return exec.CommandContext(ctx, "sh", "-c", "sleep 0.25").Run()
	}, func(error) {})
	if err == nil {
		t.Fatal("HTTP503 during disruption accepted")
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

func TestObserverRejectsEnrollmentAndServiceAuthority(t *testing.T) {
	w := worker{root: t.TempDir(), role: "manager"}
	for _, operation := range []string{"create", "admit", "join-material", "break-update", "remove", "import", "pause", "activate"} {
		t.Run(operation, func(t *testing.T) {
			_, err := w.execute(t.Context(), command{Operation: operation})
			if err == nil || !strings.Contains(err.Error(), "unknown native observation or fault operation") {
				t.Fatalf("authority operation %s reached runtime: %v", operation, err)
			}
		})
	}
}

func TestObservedServiceRequiresExactSignedProfile(t *testing.T) {
	expected := swarmruntime.ServiceIntent{Replicas: 1, Container: &api.ContainerSpec{Image: "example.invalid/native@sha256:" + strings.Repeat("a", 64), User: "65532:65532", Args: []string{"serve", "8080"}}, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 64 << 20}, Reservations: &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 64 << 20}}, Ports: []*api.PortConfig{{Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, TargetPort: 8080, PublishedPort: 8080}}}
	encoded, err := swarmruntime.ContainerRuntime(expected.Container)
	if err != nil {
		t.Fatal(err)
	}
	service := &api.Service{ID: "observed", Spec: api.ServiceSpec{Task: api.TaskSpec{Runtime: encoded, Resources: expected.Resources.Copy()}, Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}}, Endpoint: &api.EndpointSpec{Ports: []*api.PortConfig{expected.Ports[0].Copy()}}}}
	if err := verifyObservedService(service, expected); err != nil {
		t.Fatal(err)
	}
	service.Spec.Task.Resources.Limits.MemoryBytes++
	if err := verifyObservedService(service, expected); err == nil {
		t.Fatal("unsigned resource change accepted")
	}
	service.Spec.Task.Resources = expected.Resources.Copy()
	service.Spec.Endpoint.Ports[0].PublishedPort++
	if err := verifyObservedService(service, expected); err == nil {
		t.Fatal("unsigned endpoint change accepted")
	}
	service.Spec.Endpoint.Ports[0] = expected.Ports[0].Copy()
	changed := expected.Container.Copy()
	changed.Args = []string{"unsigned"}
	service.Spec.Task.Runtime, err = swarmruntime.ContainerRuntime(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyObservedService(service, expected); err == nil {
		t.Fatal("unsigned arguments accepted")
	}
}
