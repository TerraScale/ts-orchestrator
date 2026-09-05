// GlobalNatsRuntime is the production composition for the GRU global control
// plane.  Infrastructure owns creation of the JetStream resources; this file
// only opens and validates them before starting a controller.
package control

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	globalNatsRuntimeConnectTimeout = 15 * time.Second
	globalNatsRuntimeCheckTimeout   = 15 * time.Second
)

// GlobalNatsRuntimeComponent is the lifecycle owned by the global runtime
// for signed delivery and its required provider adapters.
type GlobalNatsRuntimeComponent interface {
	Completion() <-chan struct{}
	Close() error
}

// GlobalNatsRuntimeConfiguration describes one global-authority process.
// Authority is mandatory and must be the GRU global-authority identity.
// Directory and DirectoryService use their own identities and are optional.
type GlobalNatsRuntimeConfiguration struct {
	Authority *GlobalAuthorityNatsConfiguration
	Cell      string
	Instance  string

	Directory          *GlobalDirectoryNatsConfiguration
	DirectoryService   *GlobalDirectoryServiceNatsConfiguration
	Membership         func() RegionalRuntimeMembershipSnapshot
	DirectoryAuthority func() RegionalAuthoritySnapshot
	DirectoryPublish   bool

	Delivery                    *MasterDeliveryRuntimeConfig
	DeliveryEnabled             bool
	DesiredStateConsumerEnabled bool
}

type globalNatsRuntimeState struct {
	js       jetstream.JetStream
	leaders  jetstream.KeyValue
	cells    jetstream.KeyValue
	cellSpec jetstream.Consumer
}

// GlobalNatsRuntime owns the global authority connection and all components
// started from it.  Optional global-directory connectivity is deliberately
// supervised independently: a WAN failure degrades directory publication but
// does not revoke a regional controller's local authority.
type GlobalNatsRuntime struct {
	client    *nats.Conn
	topology  *GlobalNatsTopology
	authority *RegionalAuthorityCoordinator
	directory *GlobalCellDirectoryLifecycle
	delivery  GlobalNatsRuntimeComponent
	state     globalNatsRuntimeState

	cell         string
	instance     string
	startedAt    time.Time
	lifetime     context.Context
	cancel       context.CancelFunc
	complete     chan struct{}
	completeOnce sync.Once
	closeOnce    sync.Once
	closeErr     error
	closed       int32
}

// GlobalNatsRuntimeStartAsync starts the complete available global topology.
// Every stream, KV, object store, and enabled consumer must already exist and
// match its closed profile.  No resource is created or updated here.
func GlobalNatsRuntimeStartAsync(ctx context.Context, configuration *GlobalNatsRuntimeConfiguration) (*GlobalNatsRuntime, error) {
	if err := validateGlobalNatsRuntimeConfiguration(ctx, configuration); err != nil {
		return nil, err
	}

	lifetime, cancel := context.WithCancel(ctx)
	client, err := globalNatsRuntimeConnect(ctx, configuration.Authority.Url, configuration.Authority.Authentication, configuration.Authority.Tls)
	if err != nil {
		cancel()
		return nil, err
	}
	cleanup := func() {
		cancel()
		client.Close()
	}

	topology, err := NewGlobalNatsTopology(configuration.Authority.Replicas)
	if err != nil {
		cleanup()
		return nil, err
	}
	checkCtx, checkCancel := context.WithTimeout(lifetime, globalNatsRuntimeCheckTimeout)
	state, err := globalNatsRuntimeOpenAndValidate(checkCtx, client, topology, configuration.DesiredStateConsumerEnabled, configuration.Cell)
	checkCancel()
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return nil, err
	}

	authority, err := RegionalAuthorityCoordinatorStartGlobalAsync(lifetime, state.leaders, configuration.Cell, configuration.Instance)
	if err != nil {
		cleanup()
		return nil, err
	}
	if !authority.Snapshot().Ready() {
		authority.Dispose()
		cleanup()
		return nil, errors.New("The global authority did not reach a ready leader or follower state.")
	}

	runtime := &GlobalNatsRuntime{
		client: client, topology: topology, authority: authority, state: *state,
		cell: configuration.Cell, instance: configuration.Instance,
		startedAt: time.Now().UTC(), lifetime: lifetime, cancel: cancel,
		complete: make(chan struct{}),
	}
	if configuration.DeliveryEnabled {
		if err := runtime.startMasterDelivery(configuration.Delivery); err != nil {
			_ = runtime.Close()
			return nil, err
		}
	}

	if configuration.Directory != nil {
		if configuration.Membership == nil || configuration.DirectoryAuthority == nil {
			_ = runtime.Close()
			return nil, errors.New("global directory composition requires membership and authority snapshots")
		}
		runtime.directory, err = GlobalCellDirectoryLifecycleStart(
			configuration.Directory, configuration.DirectoryService, configuration.Membership,
			configuration.DirectoryAuthority, configuration.DirectoryPublish, lifetime, nil)
		if err != nil {
			_ = runtime.Close()
			return nil, err
		}
	}

	go runtime.watchCompletion()
	return runtime, nil
}

func validateGlobalNatsRuntimeConfiguration(ctx context.Context, configuration *GlobalNatsRuntimeConfiguration) error {
	if ctx == nil {
		return errors.New("a context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if configuration == nil || configuration.Authority == nil {
		return errors.New("complete global NATS authority configuration is required")
	}
	if configuration.Cell != "gru" || !GlobalNatsTopologyIsCellToken(configuration.Cell) {
		return errors.New("GlobalNatsRuntime is a GRU-only global-authority runtime.")
	}
	if configuration.Authority.Cell != configuration.Cell {
		return errors.New("the global authority configuration cell must match the startup cell")
	}
	if configuration.Authority.Authentication == nil || configuration.Authority.Tls == nil || strings.TrimSpace(configuration.Authority.Url) == "" {
		return errors.New("complete global NATS authority URL, authentication, and TLS credentials are required")
	}
	parsed, err := url.Parse(configuration.Authority.Url)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Scheme != "tls" {
		return errors.New("the global authority NATS URL must be an absolute tls:// URL")
	}
	if configuration.Authority.Replicas != 3 {
		return errors.New("global control state requires exactly three replicas")
	}
	if !GlobalNatsTopologyIsCellToken(configuration.Instance) || strings.TrimSpace(configuration.Instance) == "" {
		return errors.New("the global authority instance is invalid")
	}
	if configuration.DirectoryService != nil && configuration.Directory == nil {
		return errors.New("the global directory service requires a global directory configuration")
	}
	if configuration.Directory != nil {
		if configuration.Directory.Cell != configuration.Cell {
			return errors.New("the global directory configuration cell must match the startup cell")
		}
		if configuration.Directory.Authentication == nil || configuration.Directory.Tls == nil {
			return errors.New("complete global directory authentication and TLS credentials are required")
		}
	}
	if configuration.DirectoryService != nil {
		if configuration.DirectoryService.Cell != "gru" || configuration.DirectoryService.Authentication == nil || configuration.DirectoryService.Tls == nil {
			return errors.New("complete GRU global directory service authentication and TLS credentials are required")
		}
	}
	if configuration.DeliveryEnabled {
		if err := configuration.Delivery.Validate(); err != nil {
			return err
		}
	}
	if !configuration.DeliveryEnabled && configuration.Delivery != nil {
		return errors.New("global delivery configuration supplied while delivery is disabled")
	}
	type identity struct {
		name, public string
		tls          *NatsTlsFiles
	}
	identities := []identity{{"global authority", configuration.Authority.Authentication.PublicKey, configuration.Authority.Tls}}
	if configuration.Directory != nil {
		identities = append(identities, identity{"global directory", configuration.Directory.Authentication.PublicKey, configuration.Directory.Tls})
	}
	if configuration.DirectoryService != nil {
		identities = append(identities, identity{"global directory service", configuration.DirectoryService.Authentication.PublicKey, configuration.DirectoryService.Tls})
	}
	for i := range identities {
		if strings.TrimSpace(identities[i].public) == "" || identities[i].tls == nil {
			return errors.New("global NATS identities are incomplete")
		}
		for j := i + 1; j < len(identities); j++ {
			if identities[i].public == identities[j].public || identities[i].tls.SameIdentity(identities[j].tls) {
				return fmt.Errorf("%s and %s NATS identities must be distinct", identities[i].name, identities[j].name)
			}
		}
	}
	return nil
}

func globalNatsRuntimeConnect(ctx context.Context, rawURL string, authentication *NatsAuthenticationFiles, tlsFiles *NatsTlsFiles) (*nats.Conn, error) {
	options := []nats.Option{nats.Timeout(globalNatsRuntimeConnectTimeout), nats.MaxReconnects(-1), nats.ReconnectWait(2 * time.Second), nats.RetryOnFailedConnect(false), nats.ReconnectBufSize(-1)}
	options = append(options, authentication.Options()...)
	options = append(options, tlsFiles.Options()...)
	result := make(chan struct {
		client *nats.Conn
		err    error
	}, 1)
	go func() {
		client, err := nats.Connect(rawURL, options...)
		result <- struct {
			client *nats.Conn
			err    error
		}{client, err}
	}()
	select {
	case response := <-result:
		return response.client, response.err
	case <-ctx.Done():
		go func() {
			if response := <-result; response.client != nil {
				response.client.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func globalNatsRuntimeOpenAndValidate(ctx context.Context, client *nats.Conn, topology *GlobalNatsTopology, desiredStateConsumerEnabled bool, cell string) (*globalNatsRuntimeState, error) {
	if client == nil || topology == nil {
		return nil, errors.New("global NATS client and topology are required")
	}
	js, err := jetstream.New(client)
	if err != nil {
		return nil, err
	}
	for _, expected := range topology.Streams() {
		stream, err := js.Stream(ctx, expected.Name)
		if err != nil {
			return nil, err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return nil, err
		}
		if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(info.Config, expected); err != nil {
			return nil, err
		}
	}
	openKV := func(expected jetstream.KeyValueConfig) (jetstream.KeyValue, error) {
		store, err := js.KeyValue(ctx, expected.Bucket)
		if err != nil {
			return nil, err
		}
		stream, err := js.Stream(ctx, "KV_"+expected.Bucket)
		if err != nil {
			return nil, err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return nil, err
		}
		if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(info.Config, NatsOperationJournalStore.CanonicalKeyValueStream(expected)); err != nil {
			return nil, err
		}
		return store, nil
	}
	leaders, err := openKV(topology.Leaders())
	if err != nil {
		return nil, err
	}
	cells, err := openKV(topology.Cells())
	if err != nil {
		return nil, err
	}
	openConsumer := func(streamName string, expected jetstream.ConsumerConfig) (jetstream.Consumer, error) {
		stream, err := js.Stream(ctx, streamName)
		if err != nil {
			return nil, err
		}
		consumer, err := stream.Consumer(ctx, expected.Name)
		if err != nil {
			return nil, err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return nil, err
		}
		if !NatsConsumerProfileMatches(info, expected, streamName) {
			return nil, errors.New("an infrastructure-provisioned global NATS consumer does not match its closed profile")
		}
		return consumer, nil
	}
	var cellSpec jetstream.Consumer
	if desiredStateConsumerEnabled {
		expected, err := topology.CellSpecConsumer(cell)
		if err != nil {
			return nil, err
		}
		cellSpec, err = openConsumer(GlobalNatsTopologyCellSpecStream, expected)
		if err != nil {
			return nil, err
		}
	}
	return &globalNatsRuntimeState{js: js, leaders: leaders, cells: cells, cellSpec: cellSpec}, nil
}

func (r *GlobalNatsRuntime) watchCompletion() {
	channels := []<-chan struct{}{r.authority.Completion()}
	if r.directory != nil {
		channels = append(channels, r.directory.Completion())
	}
	if r.delivery != nil {
		channels = append(channels, r.delivery.Completion())
	}
	select {
	case <-r.lifetime.Done():
	case <-firstGlobalNatsCompletion(channels...):
	}
	// Completion is a lifecycle signal, not a substitute for disposal. The
	// authority coordinator owns a background context of its own, so merely
	// observing cancellation here would otherwise leave its election loop (and
	// the NATS connection) alive until an external caller happened to Close.
	_ = r.Close()
}

func firstGlobalNatsCompletion(channels ...<-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	var once sync.Once
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		go func(ch <-chan struct{}) { <-ch; once.Do(func() { close(done) }) }(channel)
	}
	return done
}

// Completion closes when the authority or an owned long-running optional
// component exits.  Directory lifecycle retry itself remains degraded state.
func (r *GlobalNatsRuntime) Completion() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.complete
}

func (r *GlobalNatsRuntime) AuthoritySnapshot() RegionalAuthoritySnapshot {
	if r == nil || r.authority == nil {
		return RegionalAuthoritySnapshot{}
	}
	return r.authority.Snapshot()
}
func (r *GlobalNatsRuntime) DirectorySnapshot() GlobalCellDirectorySnapshot {
	if r == nil || r.directory == nil {
		return GlobalCellDirectoryLifecycleUnavailableSnapshot()
	}
	return r.directory.Snapshot()
}

func (r *GlobalNatsRuntime) Directory() *GlobalCellDirectoryLifecycle {
	if r == nil {
		return nil
	}
	return r.directory
}

func (r *GlobalNatsRuntime) CellSpecConsumer() jetstream.Consumer {
	if r == nil {
		return nil
	}
	return r.state.cellSpec
}
func (r *GlobalNatsRuntime) Topology() *GlobalNatsTopology {
	if r == nil {
		return nil
	}
	return r.topology
}

// GlobalNatsRuntimeHealth is intentionally small: directory unavailability is
// degraded, while authority loss or an owned component completion is fatal.
type GlobalNatsRuntimeHealth string

const (
	GlobalNatsRuntimeHealthHealthy     GlobalNatsRuntimeHealth = "healthy"
	GlobalNatsRuntimeHealthDegraded    GlobalNatsRuntimeHealth = "degraded"
	GlobalNatsRuntimeHealthUnavailable GlobalNatsRuntimeHealth = "unavailable"
)

type GlobalNatsRuntimeSnapshot struct {
	SchemaVersion int                         `json:"SchemaVersion"`
	Cell          string                      `json:"Cell"`
	Instance      string                      `json:"Instance"`
	StartedAt     time.Time                   `json:"StartedAt"`
	ObservedAt    time.Time                   `json:"ObservedAt"`
	Authority     RegionalAuthoritySnapshot   `json:"Authority"`
	Directory     GlobalCellDirectorySnapshot `json:"Directory"`
	Health        GlobalNatsRuntimeHealth     `json:"Health"`
	Ready         bool                        `json:"Ready"`
	Error         *string                     `json:"Error,omitempty"`
}

func (r *GlobalNatsRuntime) Snapshot() GlobalNatsRuntimeSnapshot {
	if r == nil {
		return GlobalNatsRuntimeSnapshot{SchemaVersion: 1, Health: GlobalNatsRuntimeHealthUnavailable, ObservedAt: time.Now().UTC()}
	}
	authority := r.AuthoritySnapshot()
	directory := r.DirectorySnapshot()
	health := GlobalNatsRuntimeHealthHealthy
	if r.directory != nil && directory.Condition != GlobalCellDirectoryConditionHealthy {
		health = GlobalNatsRuntimeHealthDegraded
	}
	if globalNatsRuntimeComponentDone(r.delivery) || atomic.LoadInt32(&r.closed) != 0 {
		health = GlobalNatsRuntimeHealthUnavailable
	}
	ready := authority.Ready() && health != GlobalNatsRuntimeHealthUnavailable
	var problem *string
	if !ready {
		value := "global-authority-not-ready"
		if health == GlobalNatsRuntimeHealthUnavailable {
			value = "global-runtime-unavailable"
		}
		problem = &value
	}
	return GlobalNatsRuntimeSnapshot{SchemaVersion: 1, Cell: r.cell, Instance: r.instance, StartedAt: r.startedAt, ObservedAt: time.Now().UTC(), Authority: authority, Directory: directory, Health: health, Ready: ready, Error: problem}
}

func (r *GlobalNatsRuntime) Health() GlobalNatsRuntimeHealth {
	return r.Snapshot().Health
}

func globalNatsRuntimeComponentDone(component GlobalNatsRuntimeComponent) bool {
	if component == nil {
		return false
	}
	select {
	case <-component.Completion():
		return true
	default:
		return false
	}
}

// Close is deterministic and idempotent.  Components are stopped in reverse
// dependency order; optional disposal errors never expose secret material.
func (r *GlobalNatsRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.complete == nil {
			r.complete = make(chan struct{})
		}
		atomic.StoreInt32(&r.closed, 1)
		if r.cancel != nil {
			r.cancel()
		}
		if r.directory != nil {
			r.directory.Dispose()
		}
		if r.delivery != nil {
			if err := r.delivery.Close(); err != nil {
				r.closeErr = err
			}
		}
		if r.authority != nil {
			r.authority.Dispose()
		}
		if r.client != nil {
			r.client.Close()
		}
		r.completeOnce.Do(func() { close(r.complete) })
	})
	return r.closeErr
}

func (r *GlobalNatsRuntime) Dispose() error { return r.Close() }
