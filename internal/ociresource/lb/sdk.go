package lb

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

const (
	workRequestTimeout   = 10 * time.Minute
	firstWorkRequestPoll = 2 * time.Second
	maxWorkRequestPoll   = 30 * time.Second
)

type sdkAPI struct {
	client loadbalancer.LoadBalancerClient
	pause  func(context.Context, time.Duration) error
}

// NewSDKAPI builds the load balancer API on the shared rate-limited factory.
func NewSDKAPI(factory *ociclient.Factory) (API, error) {
	client, err := factory.LoadBalancer()
	if err != nil {
		return nil, err
	}
	return sdkAPI{client: client, pause: sleep}, nil
}

func sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func deref[T any](value *T) T {
	var zero T
	if value == nil {
		return zero
	}
	return *value
}

// gone wraps a 404 as ociresource.ErrGone.
func gone(what string, err error) error {
	if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
		return fmt.Errorf("%s: %w: %w", what, ociresource.ErrGone, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func (a sdkAPI) GetLoadBalancer(ctx context.Context, id string) (LoadBalancer, error) {
	response, err := a.client.GetLoadBalancer(ctx, loadbalancer.GetLoadBalancerRequest{LoadBalancerId: new(id)})
	if err != nil {
		return LoadBalancer{}, gone("get OCI load balancer", err)
	}
	return LoadBalancer{ID: deref(response.Id), ETag: deref(response.ETag),
		Tags: ociresource.Tags{Freeform: response.FreeformTags, Defined: response.DefinedTags}}, nil
}

// ListBackends returns every backend of the set in one call: unlike the NLB
// API, the L7 ListBackends request takes no page token and its response
// carries no opc-next-page, so there is no later page to follow.
func (a sdkAPI) ListBackends(ctx context.Context, id, backendSet string) ([]Backend, error) {
	response, err := a.client.ListBackends(ctx, loadbalancer.ListBackendsRequest{LoadBalancerId: new(id), BackendSetName: new(backendSet)})
	if err != nil {
		return nil, gone("list OCI load balancer backends", err)
	}
	backends := make([]Backend, 0, len(response.Items))
	for _, item := range response.Items {
		backends = append(backends, Backend{IP: deref(item.IpAddress), Port: deref(item.Port), Drain: deref(item.Drain),
			weight: deref(item.Weight), backup: deref(item.Backup), offline: deref(item.Offline), name: deref(item.Name)})
	}
	return backends, nil
}

// UnhealthyBackends reads the set's health summary: every backend it lists
// as warning, critical or unknown.
func (a sdkAPI) UnhealthyBackends(ctx context.Context, id, backendSet string) (map[string]bool, error) {
	response, err := a.client.GetBackendSetHealth(ctx, loadbalancer.GetBackendSetHealthRequest{LoadBalancerId: new(id),
		BackendSetName: new(backendSet)})
	if err != nil {
		return nil, gone("get OCI load balancer backend set health", err)
	}
	unhealthy := map[string]bool{}
	for _, name := range slices.Concat(response.WarningStateBackendNames, response.CriticalStateBackendNames, response.UnknownStateBackendNames) {
		unhealthy[name] = true
	}
	return unhealthy, nil
}

func (a sdkAPI) CreateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error) {
	response, err := a.client.CreateBackend(ctx, loadbalancer.CreateBackendRequest{LoadBalancerId: new(id),
		BackendSetName: new(backendSet), OpcRetryToken: new(common.RetryToken()),
		CreateBackendDetails: loadbalancer.CreateBackendDetails{IpAddress: new(backend.IP), Port: new(backend.Port),
			Weight: new(defaultWeight), Backup: new(false), Drain: new(backend.Drain), Offline: new(backend.offline)}})
	if err != nil {
		return "", fmt.Errorf("create OCI load balancer backend: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

// UpdateBackend sets every flag from the backend: weight (zero means 1),
// backup, drain and offline. The reconciler passes its managed shape; a
// release fence passes the observed one with Fenced.
func (a sdkAPI) UpdateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error) {
	response, err := a.client.UpdateBackend(ctx, loadbalancer.UpdateBackendRequest{LoadBalancerId: new(id),
		BackendSetName: new(backendSet), BackendName: new(backend.Name()), OpcRetryToken: new(common.RetryToken()),
		UpdateBackendDetails: loadbalancer.UpdateBackendDetails{Weight: new(cmp.Or(backend.weight, defaultWeight)),
			Backup: new(backend.backup), Drain: new(backend.Drain), Offline: new(backend.offline)}})
	if err != nil {
		return "", fmt.Errorf("update OCI load balancer backend: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

func (a sdkAPI) DeleteBackend(ctx context.Context, id, backendSet, name string) (string, error) {
	response, err := a.client.DeleteBackend(ctx, loadbalancer.DeleteBackendRequest{LoadBalancerId: new(id),
		BackendSetName: new(backendSet), BackendName: new(name)})
	if err != nil {
		return "", fmt.Errorf("delete OCI load balancer backend: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

func (a sdkAPI) UpdateTags(ctx context.Context, id, etag string, tags ociresource.Tags) (string, error) {
	request := loadbalancer.UpdateLoadBalancerRequest{LoadBalancerId: new(id),
		UpdateLoadBalancerDetails: loadbalancer.UpdateLoadBalancerDetails{
			FreeformTags: maps.Clone(tags.Freeform), DefinedTags: tags.Defined}}
	if etag != "" {
		request.IfMatch = new(etag)
	}
	response, err := a.client.UpdateLoadBalancer(ctx, request)
	if err != nil {
		return "", fmt.Errorf("update OCI load balancer tags: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

// WaitWorkRequest polls with doubling backoff until the work request ends.
func (a sdkAPI) WaitWorkRequest(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, workRequestTimeout)
	defer cancel()
	delay := firstWorkRequestPoll
	for {
		response, err := a.client.GetWorkRequest(ctx, loadbalancer.GetWorkRequestRequest{WorkRequestId: new(id)})
		if err != nil {
			return fmt.Errorf("get OCI load balancer work request: %w", err)
		}
		switch response.LifecycleState {
		case loadbalancer.WorkRequestLifecycleStateSucceeded:
			return nil
		case loadbalancer.WorkRequestLifecycleStateAccepted, loadbalancer.WorkRequestLifecycleStateInProgress:
		default:
			return fmt.Errorf("OCI load balancer work request %s ended %s: %s", id, response.LifecycleState, deref(response.Message))
		}
		if err := a.pause(ctx, delay); err != nil {
			return fmt.Errorf("OCI load balancer work request %s did not finish: %w", id, err)
		}
		delay = min(delay*2, maxWorkRequestPoll)
	}
}
