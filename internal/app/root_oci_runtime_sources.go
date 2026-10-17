package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootnetbird"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociread"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// A bound runtime keeps its original authenticated sources until root exits.
// Successor credentials or policies require a new supervised runtime.
type rootBoundRuntimeSources struct {
	*rootControllerSources
	cfg                 Config
	rootKV, channelKV   rootReleaseKV
	root, spec, channel jetstream.KeyValueEntry
	rootHead            string
	deadline            time.Time
}

var errRootRuntimeSourceBinding = errors.New("original root runtime source binding failed")

func bindRootRuntimeSources(ctx context.Context, cfg Config, factory *ociclient.Factory, ownhost *managedRuntimeHost,
	reader *rootociread.Backend, containers *rootrelease.Backend, channels *rootReleaseChannels, netbird *rootnetbird.Backend,
) (_ *rootBoundRuntimeSources, resultErr error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || factory == nil || ownhost == nil || reader == nil || containers == nil || channels == nil || netbird == nil {
		return nil, rootoci.ErrUnauthorized
	}
	ownhost.mu.RLock()
	node, authority, accepted := ownhost.node, ownhost.reader, ownhost.accepted.Clone()
	ownhost.mu.RUnlock()
	if node == nil || authority == nil {
		return nil, rootoci.ErrUnavailable
	}
	sources, err := openRootControllerSources(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			sources.conn.Close()
		}
	}()
	rootKV, err := sources.js.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return nil, err
	}
	channelKV, err := sources.js.KeyValue(ctx, releasechannel.Bucket)
	if err != nil {
		return nil, err
	}
	bound := &rootBoundRuntimeSources{rootControllerSources: sources, cfg: cfg,
		rootKV: rootReleaseKV{KeyValue: rootKV, js: sources.js}, channelKV: rootReleaseKV{KeyValue: channelKV, js: sources.js},
		rootHead: sources.specs.roots.reply("").Head}
	var ok bool
	bound.deadline, ok = sources.lease.Deadline()
	if !ok || sources.lease.Done() == nil {
		return nil, rootoci.ErrUnauthorized
	}
	bound.root, err = bound.rootKV.Get(ctx, rootChainKey)
	if err != nil {
		return nil, err
	}
	bound.spec, err = (rootReleaseKV{KeyValue: sources.specs.kv, js: sources.js}).Get(ctx, cellSpecKey)
	if err != nil {
		return nil, err
	}
	bound.channel, err = bound.channelKV.Get(ctx, releasechannel.ChannelKey(strings.ToUpper(cfg.NATS.Cell)))
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, err
	}
	if delegated := sources.policy.release.Load(); delegated != nil {
		bound.deadline = earlier(bound.deadline, delegated.expires)
	}
	if err := bound.guard(ctx); err != nil {
		return nil, err
	}
	intent, region, _, err := loadSignedManagedControllerConfig(cfg)
	if err != nil {
		return nil, err
	}
	journal, err := oci.OpenJournalReader(ctx, sources.js, cfg.NATS.Replicas)
	if err != nil {
		return nil, err
	}
	images, err := managedImageVerifierFor(cfg.Controller, sources.specs.hostImageSnapshot, sources.specs.holdLaunch)(ctx, region)
	if err != nil {
		return nil, err
	}
	fleet, err := oci.NewFleetObserver(region, intent, factory, journal, images)
	if err != nil {
		return nil, err
	}
	bindings := rootrelease.Sources{JS: sources.js, Fleet: fleet, Node: node, Intents: sources.intents,
		Specs: sources.specs.kv, Roots: rootKV, Leases: sources.mutations, Hosts: sources.hosts, Authority: authority, Accepted: accepted}
	if err := netbird.Bind(rootnetbird.Sources{JS: sources.js, Specs: sources.specs.kv, Roots: rootKV,
		Leases: sources.mutations, Authority: authority, Accepted: accepted, Credentials: sources.credentials}); err != nil {
		return nil, errors.Join(errRootRuntimeSourceBinding, err)
	}
	if err := reader.BindFleet(journal, images); err != nil {
		return nil, errors.Join(errRootRuntimeSourceBinding, err)
	}
	if err := containers.Bind(bindings); err != nil {
		return nil, errors.Join(errRootRuntimeSourceBinding, err)
	}
	if err := channels.Bind(ctx, sources.conn, bindings); err != nil {
		return nil, errors.Join(errRootRuntimeSourceBinding, err)
	}
	if err := bound.guard(ctx); err != nil {
		return nil, errors.Join(errRootRuntimeSourceBinding, err)
	}
	return bound, nil
}

func (bound *rootBoundRuntimeSources) guard(ctx context.Context) error {
	if err := bound.live(ctx); err != nil {
		return err
	}
	if _, _, _, err := loadSignedManagedControllerConfig(bound.cfg); err != nil {
		return err
	}
	if err := rootTrustChainCurrent(ctx, bound.js, bound.root); err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(bound.root.Value())
	if err != nil || !reflect.DeepEqual(chain, bound.specs.roots.reply("").Chain) {
		return rootoci.ErrUnauthorized
	}
	roots, err := trust.VerifyRootChain(bound.specs.roots.genesis, bound.specs.roots.identity, chain)
	if err != nil || roots.Head != bound.rootHead {
		return rootoci.ErrUnauthorized
	}
	if err := controllerHostSpecCurrent(ctx, bound.js, bound.specs, bound.spec, bound.rootHead); err != nil {
		return err
	}
	if _, err := cellspec.VerifyHistorical(bound.spec.Value(), roots.Current, bound.specs.identity); err != nil {
		return rootoci.ErrUnauthorized
	}
	current, err := bound.channelKV.Get(ctx, releasechannel.ChannelKey(strings.ToUpper(bound.cfg.NATS.Cell)))
	if bound.channel == nil {
		if !errors.Is(err, jetstream.ErrKeyNotFound) || bound.policy.release.Load() != nil {
			return rootoci.ErrUnauthorized
		}
		return bound.live(ctx)
	}
	if err != nil || current.Revision() != bound.channel.Revision() || !bytes.Equal(current.Value(), bound.channel.Value()) {
		return rootoci.ErrUnauthorized
	}
	delegated := bound.policy.release.Load()
	if delegated != nil {
		var channel releasechannel.Channel
		if protocol.DecodeStrict(current.Value(), &channel, releasechannel.MaxValueBytes) != nil {
			return rootoci.ErrUnauthorized
		}
		delegation, key, expires, err := release.VerifyReleaseDelegationCurrent(channel.Delegation, roots.Current, bound.specs.identity.Environment, time.Now())
		if err != nil || !reflect.DeepEqual(delegation, delegated.delegation) || !key.Equal(delegated.key) || !expires.Equal(delegated.expires) {
			return rootoci.ErrUnauthorized
		}
	}
	return bound.live(ctx)
}

func (bound *rootBoundRuntimeSources) live(ctx context.Context) error {
	if bound == nil || bound.rootControllerSources == nil || bound.credentials == nil || ctx == nil || ctx.Err() != nil || bound.lease.Err() != nil || bound.conn.IsClosed() ||
		!bound.deadline.IsZero() && !time.Now().Before(bound.deadline) {
		return rootoci.ErrUnauthorized
	}
	if err := bound.credentials.Guard(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || bound.lease.Err() != nil || bound.conn.IsClosed() || !time.Now().Before(bound.deadline) {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (bound *rootBoundRuntimeSources) wait(ctx context.Context) error {
	closed := bound.conn.StatusChanged(nats.CLOSED)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-bound.lease.Done():
			return errors.New("original root OCI credential lifetime ended")
		case <-closed:
			return errors.New("original root OCI source connection closed")
		case <-ticker.C:
			check, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := bound.guard(check)
			cancel()
			if err != nil {
				return errors.Join(errors.New("original root OCI source authority ended"), err)
			}
		}
	}
}
