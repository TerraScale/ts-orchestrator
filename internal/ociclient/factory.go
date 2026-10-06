// Package ociclient is the shared OCI SDK client factory. Every TerraScale OCI
// caller builds its service clients here so that one process shares one
// authentication provider, one token bucket per OCI service, and one
// 429/5xx-aware retry policy instead of each caller hammering OCI
// independently.
package ociclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/limits"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/usageapi"
	"github.com/oracle/oci-go-sdk/v65/workrequests"
	"golang.org/x/time/rate"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// SecretUnsafeEnv are the OCI SDK variables that print request and response
// bodies or redirect endpoints and TLS trust. Callers that move secrets
// through the SDK refuse to run while any is set.
var SecretUnsafeEnv = []string{"OCI_GO_SDK_DEBUG", "OCI_METADATA_BASE_URL", "OCI_SDK_AUTH_CLIENT_REGION_URL",
	"OCI_DEFAULT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"}

// Service names one OCI API family. Each has its own token bucket because OCI
// throttles per service.
type Service string

const (
	ServiceCompute       Service = "compute"
	ServiceBlockstorage  Service = "blockstorage"
	ServiceNetwork       Service = "network"
	ServiceObjectStorage Service = "objectstorage"
	ServiceNLB           Service = "networkloadbalancer"
	ServiceWorkRequests  Service = "workrequests"
	ServiceIdentity      Service = "identity"
	ServiceKMS           Service = "kms"
	ServiceSearch        Service = "resourcesearch"
	ServiceLimits        Service = "limits"
	ServiceVault         Service = "vault"
	ServiceUsage         Service = "usageapi"
)

// Limit is one token bucket: a sustained rate and a burst.
type Limit struct {
	PerSecond float64
	Burst     int
}

// DefaultLimits stay well below OCI's published per-tenancy throttles so that
// three regional controllers and an operator tool can share a tenancy.
var DefaultLimits = map[Service]Limit{
	ServiceCompute:       {PerSecond: 8, Burst: 16},
	ServiceBlockstorage:  {PerSecond: 8, Burst: 16},
	ServiceNetwork:       {PerSecond: 8, Burst: 16},
	ServiceObjectStorage: {PerSecond: 20, Burst: 40},
	ServiceNLB:           {PerSecond: 4, Burst: 8},
	ServiceWorkRequests:  {PerSecond: 4, Burst: 8},
	ServiceIdentity:      {PerSecond: 4, Burst: 8},
	ServiceKMS:           {PerSecond: 4, Burst: 8},
	ServiceSearch:        {PerSecond: 4, Burst: 8},
	ServiceLimits:        {PerSecond: 4, Burst: 8},
	ServiceVault:         {PerSecond: 4, Burst: 8},
	ServiceUsage:         {PerSecond: 1, Burst: 2},
}

var defaultLimit = Limit{PerSecond: 4, Burst: 8}

// Options configures a Factory.
type Options struct {
	// Region is the canonical OCI region identifier from the catalog.
	Region string
	// Limits overrides DefaultLimits per service.
	Limits map[Service]Limit
	Retry  RetryOptions
}

// Factory hands out rate-limited, retrying OCI service clients for one region.
type Factory struct {
	provider common.ConfigurationProvider
	region   string
	limits   map[Service]Limit
	policy   common.RetryPolicy

	mu       sync.Mutex
	limiters map[Service]*rate.Limiter
}

// New builds a factory over an existing configuration provider. Region must be
// an OCI region in the catalog: the factory never addresses another region.
func New(provider common.ConfigurationProvider, options Options) (*Factory, error) {
	if provider == nil {
		return nil, errors.New("OCI client factory requires a configuration provider")
	}
	if !catalog.IsOCIRegion(options.Region) {
		return nil, fmt.Errorf("OCI client factory region %q is not in the region catalog", options.Region)
	}
	limits := make(map[Service]Limit, len(DefaultLimits))
	for service, limit := range DefaultLimits {
		limits[service] = limit
	}
	for service, limit := range options.Limits {
		if limit.PerSecond <= 0 || limit.Burst < 1 {
			return nil, fmt.Errorf("OCI client limit for %s must be positive", service)
		}
		limits[service] = limit
	}
	return &Factory{provider: provider, region: options.Region, limits: limits,
		policy: RetryPolicy(options.Retry), limiters: map[Service]*rate.Limiter{}}, nil
}

var (
	sharedMu        sync.Mutex
	sharedPrincipal = map[string]*Factory{}
)

// InstancePrincipal returns the process-wide instance-principal factory for
// region, creating it on first use so every in-binary caller shares limiters.
// The provider is fetched from the metadata service outside the lock, so one
// slow or hung fetch never serializes every other region's factory; a racing
// creator's factory is discarded and the installed one returned.
func InstancePrincipal(region string) (*Factory, error) {
	sharedMu.Lock()
	factory := sharedPrincipal[region]
	sharedMu.Unlock()
	if factory != nil {
		return factory, nil
	}
	if !catalog.IsOCIRegion(region) {
		return nil, fmt.Errorf("OCI region %q is not in the region catalog", region)
	}
	provider, err := newInstancePrincipalProvider(common.Region(region))
	if err != nil {
		return nil, fmt.Errorf("create OCI instance-principal provider: %w", err)
	}
	created, err := New(provider, Options{Region: region})
	if err != nil {
		return nil, err
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if factory := sharedPrincipal[region]; factory != nil {
		return factory, nil
	}
	sharedPrincipal[region] = created
	return created, nil
}

// newInstancePrincipalProvider fetches instance-principal credentials; tests
// replace it.
var newInstancePrincipalProvider = func(region common.Region) (common.ConfigurationProvider, error) {
	return auth.InstancePrincipalConfigurationProviderForRegion(region)
}

// OperatorConfig returns a factory over the operator's ~/.oci/config DEFAULT
// profile, the same credentials the retired Python CLI used.
func OperatorConfig(region string) (*Factory, error) {
	return New(common.DefaultConfigProvider(), Options{Region: region})
}

// Region is the OCI region identifier this factory serves.
func (f *Factory) Region() string { return f.region }

// Provider exposes the shared configuration provider for SDK helpers that need
// it directly (for example the Object Storage upload manager).
func (f *Factory) Provider() common.ConfigurationProvider { return f.provider }

// Limiter returns the shared token bucket for service.
func (f *Factory) Limiter(service Service) *rate.Limiter {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limiter := f.limiters[service]; limiter != nil {
		return limiter
	}
	limit, ok := f.limits[service]
	if !ok {
		limit = defaultLimit
	}
	limiter := rate.NewLimiter(rate.Limit(limit.PerSecond), limit.Burst)
	f.limiters[service] = limiter
	return limiter
}

// Configure installs the shared limiter and retry policy on an SDK client and
// pins it to the factory region. An existing interceptor still runs, after the
// limiter admits the request. Each retry attempt passes through the limiter.
func (f *Factory) Configure(client *common.BaseClient, service Service) {
	limiter := f.Limiter(service)
	previous := client.Interceptor
	client.Interceptor = func(request *http.Request) error {
		ctx := request.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		if err := limiter.Wait(ctx); err != nil {
			return fmt.Errorf("OCI %s rate limiter: %w", service, err)
		}
		if previous != nil {
			return previous(request)
		}
		return nil
	}
	policy := f.policy
	// Set only the retry policy: replacing the whole configuration would drop
	// a circuit breaker the SDK installed from OCI_SDK_DEFAULT_CIRCUITBREAKER_ENABLED
	// or its global setting.
	client.Configuration.RetryPolicy = &policy
}

// PinHost replaces a client's endpoint with an exact canonical endpoint. It is
// used by callers whose signed configuration names the endpoint.
func PinHost(client *common.BaseClient, endpoint string) {
	if endpoint = strings.TrimSuffix(endpoint, "/"); endpoint != "" {
		client.Host = endpoint
	}
}

// Compute returns a rate-limited Compute client.
func (f *Factory) Compute() (core.ComputeClient, error) {
	client, err := core.NewComputeClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI Compute client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceCompute)
	return client, nil
}

// Blockstorage returns a rate-limited Block Volume client.
func (f *Factory) Blockstorage() (core.BlockstorageClient, error) {
	client, err := core.NewBlockstorageClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI Block Volume client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceBlockstorage)
	return client, nil
}

// Network returns a rate-limited Virtual Network client.
func (f *Factory) Network() (core.VirtualNetworkClient, error) {
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI network client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceNetwork)
	return client, nil
}

// ObjectStorage returns a rate-limited Object Storage client.
func (f *Factory) ObjectStorage() (objectstorage.ObjectStorageClient, error) {
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI Object Storage client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceObjectStorage)
	return client, nil
}

// NetworkLoadBalancer returns a rate-limited NLB client.
func (f *Factory) NetworkLoadBalancer() (networkloadbalancer.NetworkLoadBalancerClient, error) {
	client, err := networkloadbalancer.NewNetworkLoadBalancerClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI network load balancer client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceNLB)
	return client, nil
}

// LoadBalancer returns a rate-limited flexible (L7) load balancer client. It
// shares the NLB token bucket: both are OCI load balancing.
func (f *Factory) LoadBalancer() (loadbalancer.LoadBalancerClient, error) {
	client, err := loadbalancer.NewLoadBalancerClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI load balancer client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceNLB)
	return client, nil
}

// Identity returns a rate-limited IAM client.
func (f *Factory) Identity() (identity.IdentityClient, error) {
	client, err := identity.NewIdentityClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI identity client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceIdentity)
	return client, nil
}

// Limits returns a rate-limited service limits and quota client.
func (f *Factory) Limits() (limits.LimitsClient, error) {
	client, err := limits.NewLimitsClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI limits client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceLimits)
	return client, nil
}

// WorkRequests returns a rate-limited core work request client.
func (f *Factory) WorkRequests() (workrequests.WorkRequestClient, error) {
	client, err := workrequests.NewWorkRequestClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI work request client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceWorkRequests)
	return client, nil
}

// Usage returns a rate-limited usage API client for cost queries.
func (f *Factory) Usage() (usageapi.UsageapiClient, error) {
	client, err := usageapi.NewUsageapiClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI usage API client: %w", err)
	}
	client.SetRegion(f.region)
	f.Configure(&client.BaseClient, ServiceUsage)
	return client, nil
}

// HomeRegion asks the identity service for the tenancy's home region, where
// region subscriptions and the usage API are served. A home region outside
// the product catalog is refused rather than guessed at.
func (f *Factory) HomeRegion(ctx context.Context, tenancy string) (string, error) {
	client, err := f.Identity()
	if err != nil {
		return "", err
	}
	response, err := client.GetTenancy(ctx, identity.GetTenancyRequest{TenancyId: &tenancy})
	if err != nil {
		return "", fmt.Errorf("read the tenancy home region: %w", err)
	}
	return TenancyHomeRegion(response.HomeRegionKey)
}

// TenancyHomeRegion maps a tenancy's home region key to its catalog OCI
// region.
func TenancyHomeRegion(key *string) (string, error) {
	if key == nil {
		return "", errors.New("tenancy has no home region key")
	}
	for _, entry := range catalog.Entries() {
		if strings.EqualFold(entry.OCIRegionKey, *key) {
			return entry.OCIRegion, nil
		}
	}
	return "", fmt.Errorf("tenancy home region %q is not a catalog region", *key)
}
