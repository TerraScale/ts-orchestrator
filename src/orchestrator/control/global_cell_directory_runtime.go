// Port of src/TerraScale.Orchestrator/Messaging/GlobalCellDirectoryRuntime.cs.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// GlobalCellDirectoryAdvertisementInterval mirrors the C# constant.
const GlobalCellDirectoryAdvertisementInterval = 5 * time.Second

// GlobalCellDirectoryAdvertisementLease mirrors the C# constant.
const GlobalCellDirectoryAdvertisementLease = GlobalCellAdvertisementSemanticLease

// GlobalCellDirectoryRuntime mirrors the C# class: publishes the local
// regional leader's renewable advertisement and watches the durable global KV
// projection. WAN failures are retried and never revoke local authority.
type GlobalCellDirectoryRuntime struct {
	store       jetstream.KeyValue
	cell        string
	membership  func() RegionalRuntimeMembershipSnapshot
	authority   func() RegionalAuthoritySnapshot
	endpoints   []string
	ownedClient *nats.Conn

	stoppingCtx context.Context
	stopping    context.CancelFunc
	directory   *GlobalCellDirectory
	watchDone   chan struct{}
	publishDone chan struct{}
	disposed    int32
}

// GlobalCellDirectoryRuntimeStart mirrors the C# Start.
func GlobalCellDirectoryRuntimeStart(
	store jetstream.KeyValue,
	cell string,
	membership func() RegionalRuntimeMembershipSnapshot,
	authority func() RegionalAuthoritySnapshot,
	publishEnabled bool,
	endpoints []string,
) (*GlobalCellDirectoryRuntime, error) {
	if store == nil {
		return nil, errors.New("(Parameter 'store')")
	}

	if !GlobalNatsTopologyIsCellToken(cell) {
		return nil, errors.New("The global directory cell is invalid. (Parameter 'cell')")
	}

	if membership == nil {
		return nil, errors.New("(Parameter 'membership')")
	}

	if authority == nil {
		return nil, errors.New("(Parameter 'authority')")
	}

	if publishEnabled && len(endpoints) == 0 {
		return nil, errors.New(
			"Publishing a cell advertisement requires the cell's advertised control endpoints. (Parameter 'endpoints')")
	}

	return newGlobalCellDirectoryRuntime(
		store, cell, membership, authority, endpoints, publishEnabled, nil), nil
}

func newGlobalCellDirectoryRuntime(
	store jetstream.KeyValue,
	cell string,
	membership func() RegionalRuntimeMembershipSnapshot,
	authority func() RegionalAuthoritySnapshot,
	endpoints []string,
	publishEnabled bool,
	ownedClient *nats.Conn,
) *GlobalCellDirectoryRuntime {
	stoppingCtx, stopping := context.WithCancel(context.Background())
	runtime := &GlobalCellDirectoryRuntime{
		store:       store,
		cell:        cell,
		membership:  membership,
		authority:   authority,
		endpoints:   append([]string(nil), endpoints...),
		ownedClient: ownedClient,
		stoppingCtx: stoppingCtx,
		stopping:    stopping,
		directory:   NewGlobalCellDirectory(),
		watchDone:   make(chan struct{}),
		publishDone: make(chan struct{}),
	}

	go runtime.watchLoop()

	if publishEnabled {
		go runtime.publishLoop()
	} else {
		close(runtime.publishDone)
	}

	return runtime
}

// GlobalCellDirectoryRuntimeStartAsync mirrors the C# StartAsync: a
// directory-only connection that reconciles only the GLOBAL_CELLS KV store.
func GlobalCellDirectoryRuntimeStartAsync(
	ctx context.Context,
	configuration *GlobalDirectoryNatsConfiguration,
	membership func() RegionalRuntimeMembershipSnapshot,
	authority func() RegionalAuthoritySnapshot,
	publishEnabled bool,
) (*GlobalCellDirectoryRuntime, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if configuration == nil {
		return nil, errors.New("(Parameter 'configuration')")
	}
	if configuration.Authentication == nil || configuration.Tls == nil {
		return nil, errors.New("(Parameter 'configuration')")
	}

	if membership == nil {
		return nil, errors.New("(Parameter 'membership')")
	}

	if authority == nil {
		return nil, errors.New("(Parameter 'authority')")
	}

	if publishEnabled && len(configuration.Endpoints) == 0 {
		return nil, errors.New(
			"Publishing a cell advertisement requires the cell's advertised control endpoints. (Parameter 'configuration')")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	client, err := nats.Connect(configuration.Url,
		append([]nats.Option{
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2 * time.Second),
			nats.Timeout(15 * time.Second),
		},
			append(configuration.Authentication.Options(), configuration.Tls.Options()...)...)...)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		client.Close()
		return nil, err
	}

	js, err := jetstream.New(client)
	if err != nil {
		client.Close()
		return nil, err
	}

	store, err := GlobalCellDirectoryRuntimeOpenExistingStore(ctx, js)
	if err != nil {
		client.Close()
		return nil, err
	}

	return newGlobalCellDirectoryRuntime(
		store,
		configuration.Cell,
		membership,
		authority,
		configuration.Endpoints,
		publishEnabled,
		client), nil
}

// GlobalCellDirectoryRuntimeOpenExistingStore mirrors the C#
// OpenExistingStoreAsync: it opens the infrastructure-provisioned directory
// bucket without a configuration object.
func GlobalCellDirectoryRuntimeOpenExistingStore(
	ctx context.Context,
	keyValue jetstream.JetStream,
) (jetstream.KeyValue, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if keyValue == nil {
		return nil, errors.New("(Parameter 'keyValue')")
	}
	return keyValue.KeyValue(ctx, GlobalNatsTopologyCellsBucket)
}

// Completion mirrors the C# Completion.
func (r *GlobalCellDirectoryRuntime) Completion() <-chan struct{} {
	if r == nil || r.watchDone == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-r.watchDone:
		case <-r.publishDone:
		}

		close(done)
	}()

	return done
}

// Snapshot mirrors the C# Snapshot.
func (r *GlobalCellDirectoryRuntime) Snapshot() GlobalCellDirectorySnapshot {
	if r == nil || r.directory == nil {
		return globalCellDirectoryLifecycleUnavailableSnapshot()
	}
	return r.directory.Snapshot(nil)
}

// Health mirrors the C# Health.
func (r *GlobalCellDirectoryRuntime) Health() GlobalCellDirectoryCondition {
	return r.Snapshot().Condition
}

// Dispose mirrors the C# DisposeAsync.
func (r *GlobalCellDirectoryRuntime) Dispose() error {
	if r == nil {
		return nil
	}
	if !casInt32(&r.disposed, 0, 1) {
		return nil
	}

	if r.stopping != nil {
		r.stopping()
	}
	if r.watchDone != nil {
		<-r.watchDone
	}
	if r.publishDone != nil {
		<-r.publishDone
	}
	if r.ownedClient != nil {
		r.ownedClient.Close()
	}

	return nil
}

func (r *GlobalCellDirectoryRuntime) publishLoop() {
	defer close(r.publishDone)

	ticker := time.NewTicker(GlobalCellDirectoryAdvertisementInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stoppingCtx.Done():
			return
		case <-ticker.C:
		}

		regionalAuthority := r.authority()
		if regionalAuthority.Ready() && regionalAuthority.IsLeader {
			err := r.publishOnce(regionalAuthority)
			if errors.Is(err, errGlobalCellAdvertisementNotPublishable) {
				// A temporarily empty or not-yet-converged local membership view
				// must not turn the global projection into a regional dependency.
				continue
			}

			if err != nil && isNatsTransientError(err) {
				// The regional control plane continues from its local R3 state.
				// The next tick retries and remote readers observe lease
				// staleness.
				continue
			}

			if err != nil {
				continue
			}
		}
	}
}

var errGlobalCellAdvertisementNotPublishable = errors.New(
	"The local global-cell advertisement is invalid.")

func (r *GlobalCellDirectoryRuntime) publishOnce(regionalAuthority RegionalAuthoritySnapshot) error {
	key, err := GlobalNatsTopologyCellAdvertisementKey(r.cell)
	if err != nil {
		return err
	}

	for attempt := 0; attempt < 5; attempt++ {
		var currentRevision uint64
		var currentValue []byte
		hasCurrent := false

		entry, err := r.store.Get(r.stoppingCtx, key)
		if err == nil {
			hasCurrent = true
			currentRevision = entry.Revision()
			currentValue = entry.Value()
		} else if !errors.Is(err, jetstream.ErrKeyNotFound) && !errors.Is(err, jetstream.ErrKeyDeleted) {
			return err
		}

		sequence := int64(1)
		if hasCurrent && currentValue != nil {
			var existing GlobalCellAdvertisement
			if err := json.Unmarshal(currentValue, &existing); err != nil {
				return nil
			}

			if !existing.IsValid(time.Now().UTC()) || existing.Cell != r.cell {
				return nil
			}

			authorityOrder := 0
			if regionalAuthority.Epoch != existing.AuthorityEpoch {
				if regionalAuthority.Epoch < existing.AuthorityEpoch {
					authorityOrder = -1
				} else {
					authorityOrder = 1
				}
			}

			if authorityOrder == 0 {
				if regionalAuthority.KvRevision != existing.AuthorityRevision {
					if regionalAuthority.KvRevision < existing.AuthorityRevision {
						authorityOrder = -1
					} else {
						authorityOrder = 1
					}
				}
			}

			if authorityOrder < 0 {
				return nil
			}

			if authorityOrder == 0 {
				sequence = existing.Sequence + 1
			}
		}

		advertisement, err := GlobalCellDirectoryCreateAdvertisement(
			r.membership(), regionalAuthority, sequence, r.endpoints)
		if err != nil {
			return err
		}

		if advertisement.Cell != r.cell || !advertisement.IsValid(time.Now().UTC()) {
			return errGlobalCellAdvertisementNotPublishable
		}

		value, err := json.Marshal(advertisement)
		if err != nil {
			return err
		}

		if !hasCurrent {
			if _, err := r.store.Create(r.stoppingCtx, key, value); err == nil ||
				errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
				if err == nil {
					return nil
				}
			} else {
				return err
			}
		} else {
			if _, err := r.store.Update(r.stoppingCtx, key, value, currentRevision); err == nil {
				return nil
			} else if !errors.Is(err, jetstream.ErrKeyExists) &&
				!errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
				return err
			}
		}
	}

	return nil
}

func (r *GlobalCellDirectoryRuntime) watchLoop() {
	defer close(r.watchDone)

	for {
		watcher, err := r.store.Watch(r.stoppingCtx, "cell.>")
		if err != nil {
			select {
			case <-r.stoppingCtx.Done():
				return
			case <-time.After(time.Second):
			}

			continue
		}

		for entry := range watcher.Updates() {
			if entry == nil {
				continue
			}

			advertisedCell := ""
			if strings.HasPrefix(entry.Key(), "cell.") {
				advertisedCell = entry.Key()[len("cell."):]
			}

			if !GlobalNatsTopologyIsCellToken(advertisedCell) {
				r.directory.Reject()
				continue
			}

			deleted := entry.Value() == nil || entry.Operation() != jetstream.KeyValuePut
			if deleted {
				r.directory.Remove(advertisedCell)
				continue
			}

			var advertisement GlobalCellAdvertisement
			if err := json.Unmarshal(entry.Value(), &advertisement); err != nil {
				r.directory.Reject()
				continue
			}

			_ = r.directory.Apply(entry.Key(), advertisement, nil)
		}

		watcher.Stop()

		select {
		case <-r.stoppingCtx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// GlobalCellDirectoryCreateAdvertisement mirrors the C# CreateAdvertisement.
func GlobalCellDirectoryCreateAdvertisement(
	membership RegionalRuntimeMembershipSnapshot,
	authority RegionalAuthoritySnapshot,
	sequence int64,
	endpoints []string,
) (GlobalCellAdvertisement, error) {
	if err := membership.Validate(membership.Cell); err != nil {
		return GlobalCellAdvertisement{}, err
	}

	if !authority.Ready() || !authority.IsLeader || authority.Epoch <= 0 || authority.KvRevision <= 0 {
		return GlobalCellAdvertisement{}, errors.New(
			"Only the current regional authority leader may advertise its cell.")
	}

	if sequence <= 0 {
		return GlobalCellAdvertisement{}, errors.New(
			"Specified argument was out of the range of valid values. (Parameter 'sequence')")
	}

	if len(endpoints) == 0 {
		return GlobalCellAdvertisement{}, errors.New(
			"A cell advertisement requires at least one valid control endpoint. (Parameter 'endpoints')")
	}

	for _, endpoint := range endpoints {
		if !GlobalCellAdvertisementIsControlEndpoint(endpoint) {
			return GlobalCellAdvertisement{}, errors.New(
				"A cell advertisement requires at least one valid control endpoint. (Parameter 'endpoints')")
		}
	}

	capabilitySet := map[string]struct{}{}
	for _, member := range membership.Members {
		for _, capability := range member.Capabilities {
			capabilitySet[capability] = struct{}{}
		}
	}

	capabilities := make([]string, 0, len(capabilitySet))
	for capability := range capabilitySet {
		capabilities = append(capabilities, capability)
	}

	sort.Strings(capabilities)

	orderedEndpoints := append([]string(nil), endpoints...)
	sort.Strings(orderedEndpoints)

	return GlobalCellAdvertisement{
		SchemaVersion:     1,
		Cell:              membership.Cell,
		Cluster:           "orchestrator-control-" + membership.Cell,
		AuthorityId:       membership.Cell + "-regional",
		AuthorityEpoch:    authority.Epoch,
		AuthorityRevision: authority.KvRevision,
		Sequence:          sequence,
		Capabilities:      capabilities,
		Membership:        membership.Health,
		ObservedAt:        membership.ObservedAt,
		LeaseExpiresAt:    membership.ObservedAt.Add(GlobalCellDirectoryAdvertisementLease),
		Endpoints:         orderedEndpoints,
	}, nil
}

func casInt32(target *int32, from, to int32) bool {
	return atomic.CompareAndSwapInt32(target, from, to)
}
