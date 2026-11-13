package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// ProbeTask checks the application on an independently admitted private host.
// shortcut: readiness is HTTP only, qualify other protocols before admitting them.
func ProbeTask(ctx context.Context, task *api.Task, nodeAddress netip.Addr) error {
	endpoint, err := taskEndpoint(task, nodeAddress)
	if err != nil {
		return err
	}
	return probeReady(ctx, task, endpoint)
}

// ProbeLocalTask checks a task on this host; host networking binds its port on loopback.
// shortcut: a replica on another host of the region passes when this host's replica answers; probe its node address (ProbeTask) once multi-host readiness matters.
func ProbeLocalTask(ctx context.Context, task *api.Task) error {
	port, err := taskPort(task)
	if err != nil {
		return err
	}
	return probeReady(ctx, task, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port))
}

func probeReady(ctx context.Context, task *api.Task, endpoint netip.AddrPort) error {
	spec, err := DecodeContainer(task)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	transport := &http.Transport{
		// No environment proxy, DNS, redirect, or caller-provided URL may change the target.
		DialContext:            (&net.Dialer{Timeout: time.Second}).DialContext,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 8 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+endpoint.String()+ReadyPath(spec), nil)
	if err != nil {
		return errors.New("build task readiness request")
	}
	response, err := client.Do(request)
	if err != nil {
		return &TaskReadinessError{Status: "request-failed"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &TaskReadinessError{Status: fmt.Sprintf("HTTP %d", response.StatusCode)}
	}
	return nil
}

// TaskReadinessError is a running task's application answering its readyPath
// with anything but 200: Status is "HTTP <code>" or "request-failed".
type TaskReadinessError struct{ Status string }

func (e *TaskReadinessError) Error() string {
	if e.Status == "request-failed" {
		return "task application readiness request failed"
	}
	return "task application readiness returned " + e.Status
}

func taskEndpoint(task *api.Task, nodeAddress netip.Addr) (netip.AddrPort, error) {
	if !nodeAddress.Is4() || !nodeAddress.IsPrivate() {
		return netip.AddrPort{}, errors.New("task readiness requires an admitted private IPv4 host")
	}
	port, err := taskPort(task)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(nodeAddress, port), nil
}

func taskPort(task *api.Task) (uint16, error) {
	if _, err := DecodeContainer(task); err != nil {
		return 0, err
	}
	if task.DesiredState != api.TaskStateRunning || task.Status.State != api.TaskStateRunning {
		return 0, errors.New("task is not running with running intent")
	}
	return hostPort(task)
}

// probeLocalPort probes a task the executor is starting, before SwarmKit sees it RUNNING.
func probeLocalPort(ctx context.Context, task *api.Task, port uint16) error {
	return probeReady(ctx, task, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port))
}

func hostPort(task *api.Task) (uint16, error) {
	// A spec using TaskPortEnv publishes no host port; the executor serves LabelPort.
	if port, err := strconv.ParseUint(task.ServiceAnnotations.Labels[LabelPort], 10, 16); err == nil && port >= 1024 {
		return uint16(port), nil
	}
	if task.Endpoint == nil || task.Endpoint.Spec == nil || len(task.Endpoint.Spec.Ports) == 0 {
		return 0, errors.New("task readiness requires a reserved host port")
	}
	// The first port serves readiness (a spec's postgres port follows it). Generic host ports remain in Spec; the executor owns their durable host reservations.
	port := task.Endpoint.Spec.Ports[0]
	if port == nil || port.PublishMode != api.PublishModeHost || port.Protocol != api.ProtocolTCP || port.PublishedPort < 1024 || port.PublishedPort > 65535 || port.TargetPort != port.PublishedPort {
		return 0, errors.New("task readiness requires a non-privileged host TCP port")
	}
	return uint16(port.PublishedPort), nil
}
