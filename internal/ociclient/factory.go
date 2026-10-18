// Package ociclient is the shared OCI SDK client factory. Every TerraScale OCI
// caller builds its service clients here so that one process shares one
// authentication provider, one token bucket per OCI service, and one
// 429/5xx-aware retry policy instead of each caller hammering OCI
// independently.
package ociclient

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/limits"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"
	"github.com/oracle/oci-go-sdk/v65/usageapi"
	"github.com/oracle/oci-go-sdk/v65/workrequests"
	"golang.org/x/time/rate"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
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
	ServiceCompute           Service = "compute"
	ServiceComputeManagement Service = "computemanagement"
	ServiceBlockstorage      Service = "blockstorage"
	ServiceNetwork           Service = "network"
	ServiceObjectStorage     Service = "objectstorage"
	ServiceNLB               Service = "networkloadbalancer"
	ServiceWorkRequests      Service = "workrequests"
	ServiceIdentity          Service = "identity"
	ServiceKMS               Service = "kms"
	ServiceSearch            Service = "resourcesearch"
	ServiceLimits            Service = "limits"
	ServiceVault             Service = "vault"
	ServiceUsage             Service = "usageapi"
	ServiceArtifacts         Service = "artifacts"
)

// Limit is one token bucket: a sustained rate and a burst.
type Limit struct {
	PerSecond float64
	Burst     int
}

// DefaultLimits stay well below OCI's published per-tenancy throttles so that
// three regional controllers and an operator tool can share a tenancy.
var DefaultLimits = map[Service]Limit{
	ServiceCompute:           {PerSecond: 8, Burst: 16},
	ServiceComputeManagement: {PerSecond: 8, Burst: 16},
	ServiceBlockstorage:      {PerSecond: 8, Burst: 16},
	ServiceNetwork:           {PerSecond: 8, Burst: 16},
	ServiceObjectStorage:     {PerSecond: 20, Burst: 40},
	ServiceNLB:               {PerSecond: 4, Burst: 8},
	ServiceWorkRequests:      {PerSecond: 4, Burst: 8},
	ServiceIdentity:          {PerSecond: 4, Burst: 8},
	ServiceKMS:               {PerSecond: 4, Burst: 8},
	ServiceSearch:            {PerSecond: 4, Burst: 8},
	ServiceLimits:            {PerSecond: 4, Burst: 8},
	ServiceVault:             {PerSecond: 4, Burst: 8},
	ServiceUsage:             {PerSecond: 1, Burst: 2},
	ServiceArtifacts:         {PerSecond: 4, Burst: 8},
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

	mu           sync.Mutex
	limiters     map[Service]*rate.Limiter
	origin       *Factory
	regions      map[string]*Factory
	transport    *common.OciHTTPTransportWrapper
	transportKey sdkTransportKey
}

type sdkTransportKey struct {
	template *http.Transport
	tlsPaths [3]string
	refresh  time.Duration
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
// The provider is fetched from the metadata service outside the map lock, so a
// cached region never waits for a fetch; a racing creator's factory is
// discarded and the installed one returned.
func InstancePrincipal(region string) (*Factory, error) {
	return InstancePrincipalContext(context.Background(), region)
}

// InstancePrincipalContext bounds cold credential acquisition without retaining ctx in the shared factory.
func InstancePrincipalContext(ctx context.Context, region string) (*Factory, error) {
	ctx, release, err := credentialContext(ctx)
	defer release()
	if err != nil {
		return nil, err
	}
	sharedMu.Lock()
	factory := sharedPrincipal[region]
	sharedMu.Unlock()
	if factory != nil {
		return factory, nil
	}
	if !catalog.IsOCIRegion(region) {
		return nil, fmt.Errorf("OCI region %q is not in the region catalog", region)
	}
	provider, err := InstancePrincipalProviderContext(ctx, common.Region(region), nil)
	if err != nil {
		return nil, fmt.Errorf("create OCI instance-principal provider: %w", err)
	}
	created, err := New(provider, Options{Region: region})
	if err != nil {
		return nil, err
	}
	if err := checkCredentialSource(ctx); err != nil {
		return nil, err
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if factory := sharedPrincipal[region]; factory != nil {
		return factory, nil
	}
	sharedPrincipal[region] = created
	return created, nil
}

// InstancePrincipalProvider fetches instance-principal credentials for region
// from the metadata service, with modifier wrapping the SDK's HTTP client (nil
// keeps it). Every in-binary instance-principal provider must be built here:
// the SDK writes package-level metadata URLs on every provider it builds, so
// builds share one process-wide serialization token.
func InstancePrincipalProvider(region common.Region,
	modifier func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error),
) (common.ConfigurationProvider, error) {
	return InstancePrincipalProviderContext(context.Background(), region, modifier)
}

// InstancePrincipalProviderContext serializes SDK globals while allowing queued callers to cancel.
func InstancePrincipalProviderContext(ctx context.Context, region common.Region,
	modifier func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error),
) (common.ConfigurationProvider, error) {
	ctx, release, err := credentialContext(ctx)
	defer release()
	if err != nil {
		return nil, err
	}
	select {
	case providerToken <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-providerToken }()
	if err := checkCredentialSource(ctx); err != nil {
		return nil, err
	}
	provider, err := newInstancePrincipalProvider(ctx, region, func(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
		if modifier != nil {
			var err error
			dispatcher, err = modifier(dispatcher)
			if err != nil {
				return nil, err
			}
		}
		return credentialDispatcher{next: dispatcher}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return contextualPrincipal{ConfigurationProvider: provider}, nil
}

var providerToken = make(chan struct{}, 1)

// newInstancePrincipalProvider is the SDK's constructor; tests replace it.
var newInstancePrincipalProvider = auth.InstancePrincipalConfigurationForRegionWithCustomClientContext

// OperatorConfig returns a factory over the operator's ~/.oci/config DEFAULT
// profile, the same credentials the retired Python CLI used.
func OperatorConfig(region string) (*Factory, error) {
	return New(common.DefaultConfigProvider(), Options{Region: region})
}

// Region is the OCI region identifier this factory serves.
func (f *Factory) Region() string { return f.region }

// ForRegion preserves this factory's authentication and retry policy while
// selecting another catalog region, including the tenancy's home region.
func (f *Factory) ForRegion(region string) (*Factory, error) {
	if !catalog.IsOCIRegion(region) {
		return nil, fmt.Errorf("OCI region %q is not in the region catalog", region)
	}
	if f.origin != nil {
		return f.origin.ForRegion(region)
	}
	if region == f.region {
		return f, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if sibling := f.regions[region]; sibling != nil {
		return sibling, nil
	}
	if f.regions == nil {
		f.regions = map[string]*Factory{}
	}
	sibling := &Factory{provider: f.provider, region: region, limits: f.limits,
		policy: f.policy, limiters: map[Service]*rate.Limiter{}, origin: f}
	f.regions[region] = sibling
	return sibling, nil
}

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
		if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions {
			if guard, ok := ctx.Value(authorityKey{}).(func(context.Context) error); ok {
				if err := guard(ctx); err != nil {
					return fmt.Errorf("OCI %s write authority: %w", service, err)
				}
			}
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
	ConfigureReadCancellation(client)
}

// configureSDK shares only constructor-issued transports, before request wrappers.
func (f *Factory) configureSDK(client *common.BaseClient, service Service) {
	if dispatcher, ok := client.HTTPClient.(*http.Client); ok {
		if transport, ok := dispatcher.Transport.(*common.OciHTTPTransportWrapper); ok {
			if template, ok := http.DefaultTransport.(*http.Transport); ok {
				key := sdkTransportKey{template: template, refresh: transport.RefreshRate,
					// These vendor TLS paths preserve the SDK's certificate configuration and refresh behavior.
					tlsPaths: [3]string{os.Getenv("OCI_DEFAULT_CERTS_PATH"), os.Getenv("OCI_DEFAULT_CLIENT_CERTS_PATH"), os.Getenv("OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH")}}
				f.mu.Lock()
				if f.transport == nil || f.transportKey != key {
					f.transport, f.transportKey = transport, key
				}
				dispatcher.Transport = f.transport
				f.mu.Unlock()
			}
		}
	}
	f.Configure(client, service)
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
	f.configureSDK(&client.BaseClient, ServiceCompute)
	return client, nil
}

// ComputeManagement returns a rate-limited Compute Management client for
// instance pools and instance configurations.
func (f *Factory) ComputeManagement() (core.ComputeManagementClient, error) {
	client, err := core.NewComputeManagementClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI Compute Management client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceComputeManagement)
	return client, nil
}

// Blockstorage returns a rate-limited Block Volume client.
func (f *Factory) Blockstorage() (core.BlockstorageClient, error) {
	client, err := core.NewBlockstorageClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI Block Volume client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceBlockstorage)
	return client, nil
}

// Network returns a rate-limited Virtual Network client.
func (f *Factory) Network() (core.VirtualNetworkClient, error) {
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI network client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceNetwork)
	return client, nil
}

// ObjectStorage returns a rate-limited Object Storage client.
func (f *Factory) ObjectStorage() (objectstorage.ObjectStorageClient, error) {
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI Object Storage client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceObjectStorage)
	client.HTTPClient = Instrument(client.HTTPClient, string(ServiceObjectStorage))
	return client, nil
}

// NetworkLoadBalancer returns a rate-limited NLB client.
func (f *Factory) NetworkLoadBalancer() (networkloadbalancer.NetworkLoadBalancerClient, error) {
	client, err := networkloadbalancer.NewNetworkLoadBalancerClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI network load balancer client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceNLB)
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
	f.configureSDK(&client.BaseClient, ServiceNLB)
	return client, nil
}

// Identity returns a rate-limited IAM client.
func (f *Factory) Identity() (identity.IdentityClient, error) {
	client, err := identity.NewIdentityClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI identity client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceIdentity)
	return client, nil
}

// Limits returns a rate-limited service limits and quota client.
func (f *Factory) Limits() (limits.LimitsClient, error) {
	client, err := limits.NewLimitsClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI limits client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceLimits)
	return client, nil
}

// WorkRequests returns a rate-limited core work request client.
func (f *Factory) WorkRequests() (workrequests.WorkRequestClient, error) {
	client, err := workrequests.NewWorkRequestClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI work request client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceWorkRequests)
	return client, nil
}

// Usage returns a rate-limited usage API client for cost queries.
func (f *Factory) Usage() (usageapi.UsageapiClient, error) {
	client, err := usageapi.NewUsageapiClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI usage API client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceUsage)
	return client, nil
}

// Artifacts returns the regional OCIR repository and container image client.
func (f *Factory) Artifacts() (artifacts.ArtifactsClient, error) {
	client, err := artifacts.NewArtifactsClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI artifacts client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceArtifacts)
	client.HTTPClient = Instrument(client.HTTPClient, string(ServiceArtifacts))
	return client, nil
}

// Search returns a rate-limited Resource Search client.
func (f *Factory) Search() (resourcesearch.ResourceSearchClient, error) {
	client, err := resourcesearch.NewResourceSearchClientWithConfigurationProvider(f.provider)
	if err != nil {
		return client, fmt.Errorf("create OCI resource search client: %w", err)
	}
	client.SetRegion(f.region)
	f.configureSDK(&client.BaseClient, ServiceSearch)
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
	response, err := client.GetTenancy(RequestContext(ctx), identity.GetTenancyRequest{TenancyId: &tenancy})
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

// Metrics is the shared OCI API metric set; the OCI fleet also adds its inventory gauges.
var Metrics = metrics.NewSet()

// maxOperationsPerService bounds label cardinality. A raw path never
// becomes a label: OCIDs and names are templated, and unknown shapes past
// the bound collapse into "other".
const maxOperationsPerService = 64

var apiStats = &operationStats{byKey: map[apiOperationKey]*observability.OCIOperationView{},
	perService: map[string]int{}}

type apiOperationKey struct {
	service   string
	operation string
}

type operationStats struct {
	mu         sync.Mutex
	byKey      map[apiOperationKey]*observability.OCIOperationView
	perService map[string]int
}

// instrumentedDispatcher wraps one SDK client's HTTP dispatcher. It observes
// only the method, a templated route, the status and the latency; request
// and response bodies, headers and signatures are never read.
type instrumentedDispatcher struct {
	next    common.HTTPRequestDispatcher
	service string
	now     func() time.Time
}

// Instrument records one HTTP attempt without changing the dispatcher, limiter or retry policy.
func Instrument(next common.HTTPRequestDispatcher, service string) common.HTTPRequestDispatcher {
	if next == nil {
		next = http.DefaultClient
	}
	return &instrumentedDispatcher{next: next, service: service, now: time.Now}
}

func (dispatcher *instrumentedDispatcher) Do(request *http.Request) (*http.Response, error) {
	started := dispatcher.now()
	response, err := dispatcher.next.Do(request)
	elapsed := dispatcher.now().Sub(started)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	apiStats.record(dispatcher.service, operationTemplate(request), status, err != nil, elapsed)
	return response, err
}

func (stats *operationStats) record(service, operation string, status int, transportError bool, elapsed time.Duration) {
	stats.mu.Lock()
	key := apiOperationKey{service: service, operation: operation}
	view, known := stats.byKey[key]
	if !known {
		if stats.perService[service] >= maxOperationsPerService {
			key.operation = "other"
			view, known = stats.byKey[key]
		}
		if !known {
			view = &observability.OCIOperationView{Service: service, Operation: key.operation}
			stats.byKey[key] = view
			stats.perService[service]++
		}
	}
	seconds := elapsed.Seconds()
	view.Calls++
	view.TotalSeconds += seconds
	view.MaxSeconds = max(view.MaxSeconds, seconds)
	view.LastStatus = status
	failed := transportError || status >= 400
	if failed {
		view.Errors++
		view.LastErrorCode = status
	}
	if status == http.StatusTooManyRequests {
		view.Throttled++
	}
	operation = key.operation
	stats.mu.Unlock()

	code := strconv.Itoa(status)
	if transportError {
		code = "transport_error"
	}
	labels := []string{"service", service, "operation", operation}
	Metrics.GetOrCreateCounter(observability.Series(observability.MetricPrefix+"oci_requests_total",
		slices.Concat(labels, []string{"code", code})...)).Inc()
	Metrics.GetOrCreatePrometheusHistogram(observability.Series(observability.MetricPrefix+"oci_request_duration_seconds",
		labels...)).Update(seconds)
	if status == http.StatusTooManyRequests {
		Metrics.GetOrCreateCounter(observability.Series(observability.MetricPrefix+"oci_throttled_total", labels...)).Inc()
	}
}

// APIOperations returns per-operation OCI API usage since process start.
func APIOperations() []observability.OCIOperationView {
	apiStats.mu.Lock()
	defer apiStats.mu.Unlock()
	operations := make([]observability.OCIOperationView, 0, len(apiStats.byKey))
	for _, operation := range apiStats.byKey {
		operations = append(operations, *operation)
	}
	slices.SortFunc(operations, func(a, b observability.OCIOperationView) int {
		return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Operation, b.Operation))
	})
	return operations
}

// operationTemplate turns "GET /20160918/instances/ocid1.instance...?page=x"
// into "GET /instances/{id}". The API version segment is dropped, resource
// identifiers become {id}, and only a bounded action query is kept.
func operationTemplate(request *http.Request) string {
	if request == nil || request.URL == nil {
		return "unknown"
	}
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(segments) > 0 && apiVersionSegment(segments[0]) {
		segments = segments[1:]
	}
	// Object Storage names have fixed positions; object names can contain slashes.
	if len(segments) > 1 && segments[0] == "n" {
		segments[1] = "{id}"
		if len(segments) > 3 {
			segments[3] = "{id}"
		}
		end := 5
		if len(segments) > 4 && segments[4] == "actions" {
			end = 6
		}
		if len(segments) > end {
			segments = append(segments[:end], "{id}")
		}
	}
	if len(segments) > 8 {
		segments = append(segments[:8], "...")
	}
	for index, segment := range segments {
		if identifierSegment(segment) {
			segments[index] = "{id}"
		}
	}
	template := request.Method + " /" + strings.Join(segments, "/")
	if action := request.URL.Query().Get("action"); action != "" {
		if !boundedAction(action) {
			action = "{action}"
		}
		template += "?action=" + action
	}
	return template
}

func apiVersionSegment(segment string) bool {
	if len(segment) != 8 {
		return false
	}
	for _, character := range segment {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func identifierSegment(segment string) bool {
	if strings.HasPrefix(segment, "ocid1.") || len(segment) > 40 || strings.ContainsAny(segment, ".:@%=") {
		return true
	}
	digits := 0
	for _, character := range segment {
		if character >= '0' && character <= '9' {
			digits++
		}
	}
	return digits > 0 && digits*2 >= len(segment)
}

func boundedAction(action string) bool {
	if len(action) > 32 {
		return false
	}
	for _, character := range action {
		if (character < 'A' || character > 'Z') && character != '_' {
			return false
		}
	}
	return true
}
