package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nlb"
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
		return errors.New("task application readiness request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("task application readiness returned HTTP %d", response.StatusCode)
	}
	return nil
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
func probeLocalPort(ctx context.Context, task *api.Task) error {
	port, err := hostPort(task)
	if err != nil {
		return err
	}
	return probeReady(ctx, task, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port))
}

func hostPort(task *api.Task) (uint16, error) {
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

// ServiceBackends derives ingress from current upstream tasks and real readiness.
// nodeAddresses is a snapshot of admitted host inventory, never request-supplied addresses.
// An observed unhealthy service produces an empty desired set to remove stale traffic;
// an unavailable SwarmKit API returns an error without inventing observations.
func ServiceBackends(ctx context.Context, client api.ControlClient, serviceID, nlbID, backendSet string, nodeAddresses map[string]netip.Addr) (nlb.Spec, ServiceObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	backends := map[string]nlb.Backend{}
	var hostObservationErr error
	view, err := ObserveService(ctx, client, serviceID, func(ctx context.Context, task *api.Task) error {
		address, ok := nodeAddresses[task.NodeID]
		if !ok {
			return errors.New("task host is absent from admitted inventory")
		}
		response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			hostObservationErr = errors.New("task host state is unavailable")
			return hostObservationErr
		}
		node := response.Node
		if node == nil || node.ID != task.NodeID || node.Status.State != api.NodeStatus_READY || (node.Spec.Availability != api.NodeAvailabilityActive && node.Spec.Availability != api.NodeAvailabilityPause) || node.Spec.Annotations.Labels[LabelExecutionScope] != "platform" || task.ServiceAnnotations.Labels[LabelRegion] == "" || node.Spec.Annotations.Labels[LabelRegion] != task.ServiceAnnotations.Labels[LabelRegion] {
			return errors.New("task host is not an active admitted regional container host")
		}
		if err := ProbeTask(ctx, task, address); err != nil {
			return err
		}
		endpoint, _ := taskEndpoint(task, address)
		backends[endpoint.String()] = nlb.Backend{IP: address.String(), Port: int(endpoint.Port())}
		return nil
	})
	if err != nil {
		return nlb.Spec{}, ServiceObservation{}, err
	}
	if hostObservationErr != nil {
		return nlb.Spec{}, view, hostObservationErr
	}
	if err := ctx.Err(); err != nil {
		return nlb.Spec{}, view, err
	}
	spec := nlb.Spec{NLBID: nlbID, BackendSet: backendSet, AllowEmpty: true}
	for _, backend := range backends {
		spec.Backends = append(spec.Backends, backend)
	}
	slices.SortFunc(spec.Backends, func(a, b nlb.Backend) int { return strings.Compare(a.Name(), b.Name()) })
	if err := spec.Validate(); err != nil {
		return nlb.Spec{}, view, err
	}
	return spec, view, nil
}
