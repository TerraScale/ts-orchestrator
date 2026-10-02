package nlb

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

const (
	maxPages             = 16
	workRequestTimeout   = 10 * time.Minute
	firstWorkRequestPoll = 2 * time.Second
	maxWorkRequestPoll   = 30 * time.Second
)

type sdkAPI struct {
	client networkloadbalancer.NetworkLoadBalancerClient
	pause  func(context.Context, time.Duration) error
}

// NewSDKAPI builds the NLB API on the shared rate-limited factory.
func NewSDKAPI(factory *ociclient.Factory) (API, error) {
	client, err := factory.NetworkLoadBalancer()
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

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (a sdkAPI) GetLoadBalancer(ctx context.Context, id string) (LoadBalancer, error) {
	response, err := a.client.GetNetworkLoadBalancer(ctx, networkloadbalancer.GetNetworkLoadBalancerRequest{NetworkLoadBalancerId: new(id)})
	if err != nil {
		if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return LoadBalancer{}, fmt.Errorf("get OCI NLB: %w: %w", ociresource.ErrGone, err)
		}
		return LoadBalancer{}, fmt.Errorf("get OCI NLB: %w", err)
	}
	return LoadBalancer{ID: deref(response.Id), ETag: deref(response.Etag),
		Tags: ociresource.Tags{Freeform: response.FreeformTags, Defined: response.DefinedTags}}, nil
}

func (a sdkAPI) ListBackends(ctx context.Context, id, backendSet string) ([]Backend, error) {
	var backends []Backend
	var page *string
	for range maxPages {
		response, err := a.client.ListBackends(ctx, networkloadbalancer.ListBackendsRequest{NetworkLoadBalancerId: new(id),
			BackendSetName: new(backendSet), Page: page})
		if err != nil {
			return nil, fmt.Errorf("list OCI NLB backends: %w", err)
		}
		for _, item := range response.Items {
			if item.TargetId != nil && *item.TargetId != "" {
				// Instance-targeted backends are not modeled; surface them as
				// an unmatched name so an enforce pass replaces them by IP.
				backends = append(backends, Backend{IP: "target:" + *item.TargetId, Port: intValue(item.Port), name: deref(item.Name)})
				continue
			}
			backends = append(backends, Backend{IP: deref(item.IpAddress), Port: intValue(item.Port), Weight: intValue(item.Weight),
				name: deref(item.Name)})
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return backends, nil
		}
		page = response.OpcNextPage
	}
	return nil, errors.New("OCI NLB backend list exceeds its page bound")
}

func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func (a sdkAPI) CreateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error) {
	response, err := a.client.CreateBackend(ctx, networkloadbalancer.CreateBackendRequest{NetworkLoadBalancerId: new(id),
		BackendSetName: new(backendSet), OpcRetryToken: new(common.RetryToken()),
		CreateBackendDetails: networkloadbalancer.CreateBackendDetails{IpAddress: new(backend.IP), Port: new(backend.Port),
			Name: new(backend.key()), Weight: new(backend.weight())}})
	if err != nil {
		return "", fmt.Errorf("create OCI NLB backend: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

func (a sdkAPI) UpdateBackend(ctx context.Context, id, backendSet string, backend Backend) (string, error) {
	response, err := a.client.UpdateBackend(ctx, networkloadbalancer.UpdateBackendRequest{NetworkLoadBalancerId: new(id),
		BackendSetName: new(backendSet), BackendName: new(backend.Name()), OpcRetryToken: new(common.RetryToken()),
		UpdateBackendDetails: networkloadbalancer.UpdateBackendDetails{Weight: new(backend.weight())}})
	if err != nil {
		return "", fmt.Errorf("update OCI NLB backend: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

func (a sdkAPI) DeleteBackend(ctx context.Context, id, backendSet, name string) (string, error) {
	response, err := a.client.DeleteBackend(ctx, networkloadbalancer.DeleteBackendRequest{NetworkLoadBalancerId: new(id),
		BackendSetName: new(backendSet), BackendName: new(name)})
	if err != nil {
		return "", fmt.Errorf("delete OCI NLB backend: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

func (a sdkAPI) UpdateTags(ctx context.Context, id, etag string, tags ociresource.Tags) (string, error) {
	request := networkloadbalancer.UpdateNetworkLoadBalancerRequest{NetworkLoadBalancerId: new(id),
		UpdateNetworkLoadBalancerDetails: networkloadbalancer.UpdateNetworkLoadBalancerDetails{
			FreeformTags: maps.Clone(tags.Freeform), DefinedTags: tags.Defined}}
	if etag != "" {
		request.IfMatch = new(etag)
	}
	response, err := a.client.UpdateNetworkLoadBalancer(ctx, request)
	if err != nil {
		return "", fmt.Errorf("update OCI NLB tags: %w", err)
	}
	return deref(response.OpcWorkRequestId), nil
}

// WaitWorkRequest polls with doubling backoff until the work request ends.
func (a sdkAPI) WaitWorkRequest(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, workRequestTimeout)
	defer cancel()
	delay := firstWorkRequestPoll
	for {
		response, err := a.client.GetWorkRequest(ctx, networkloadbalancer.GetWorkRequestRequest{WorkRequestId: new(id)})
		if err != nil {
			return fmt.Errorf("get OCI NLB work request: %w", err)
		}
		switch response.Status {
		case networkloadbalancer.OperationStatusSucceeded:
			return nil
		case networkloadbalancer.OperationStatusAccepted, networkloadbalancer.OperationStatusInProgress:
		default:
			return fmt.Errorf("OCI NLB work request %s ended %s", id, response.Status)
		}
		if err := a.pause(ctx, delay); err != nil {
			return fmt.Errorf("OCI NLB work request %s did not finish: %w", id, err)
		}
		delay = min(delay*2, maxWorkRequestPoll)
	}
}
