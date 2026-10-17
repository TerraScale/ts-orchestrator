package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

type rootStatefulAuthorizer struct {
	cfg       Config
	authority *rootOCIAuthority
	factory   *ociclient.Factory
}

func newRootStatefulAuthorizer(cfg Config, authority *rootOCIAuthority, factory *ociclient.Factory) (*rootStatefulAuthorizer, error) {
	if os.Geteuid() != 0 || authority == nil || factory == nil || cfg.NATS.Cell != strings.ToLower(authority.accepted.Cell) ||
		factory.Region() != catalog.OCIRegion(authority.accepted.Cell) {
		return nil, errors.New("stateful scheduling requires the actual accepted root runtime")
	}
	return &rootStatefulAuthorizer{cfg: cfg, authority: authority, factory: factory}, nil
}

func (a *rootStatefulAuthorizer) WithStatefulService(ctx context.Context, spec *api.ServiceSpec, effect func(context.Context) error) error {
	if a == nil || ctx == nil || ctx.Err() != nil || spec == nil || effect == nil {
		return rootoci.ErrUnauthorized
	}
	pid, err := swarmruntime.ManagementPeerPID(ctx)
	if err != nil {
		return err
	}
	witness, err := rootoci.CaptureProcess(int(pid))
	if err != nil {
		return err
	}
	defer witness.Close()
	original, err := a.authority.authorizeRuntime(ctx, witness.Peer())
	if err != nil || original.Context == nil || original.Context.Done() == nil || original.RuntimeID == "" {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx, finish := context.WithDeadline(ctx, original.Deadline)
	defer finish()
	stop := context.AfterFunc(original.Context, cancel)
	defer stop()
	guardProcess := func(ctx context.Context) error {
		if witness.Verify() != nil || original.Context.Err() != nil || ctx.Err() != nil || !time.Now().Before(original.Deadline) {
			return rootoci.ErrUnauthorized
		}
		current, err := a.authority.authorizeRuntime(ctx, witness.Peer())
		if err != nil || current.Context != original.Context || current.Binding != original.Binding || current.RuntimeID != original.RuntimeID ||
			current.Deadline.Before(original.Deadline) || witness.Verify() != nil || ctx.Err() != nil ||
			original.Context.Err() != nil || !time.Now().Before(original.Deadline) {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if err := guardProcess(ctx); err != nil {
		return err
	}
	ctx = ociclient.WithRequestGuard(ctx, guardProcess)
	sources, err := openRootControllerSources(ctx, a.cfg)
	if err != nil {
		return err
	}
	defer sources.conn.Close()
	a.authority.ownhost.mu.RLock()
	node := a.authority.ownhost.node
	a.authority.ownhost.mu.RUnlock()
	if node == nil {
		return rootoci.ErrUnauthorized
	}
	client, err := node.ReadOnlyControlClient(ctx)
	if err != nil {
		return err
	}
	current, err := a.authority.ownhost.reader.ReadRuntimeAuthority(ctx, a.authority.accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	identity := current.Identity()
	rootKV, err := sources.js.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return err
	}
	rootEntry, err := rootKV.Get(ctx, rootChainKey)
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(rootEntry.Value())
	if err != nil || !reflect.DeepEqual(chain, sources.specs.roots.reply("").Chain) {
		return rootoci.ErrUnauthorized
	}
	profileEntry, err := sources.specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return err
	}
	rootHead := sources.specs.roots.reply("").Head
	var lease *authority.LeaseAdmission
	guard := func(ctx context.Context, epoch uint64) error {
		if err := guardProcess(ctx); err != nil {
			return err
		}
		if sources.conn.IsClosed() {
			return rootoci.ErrUnauthorized
		}
		if lease == nil {
			var err error
			lease, err = sources.mutations.AdmitCurrentLease(ctx, identity.DeploymentID, original.RuntimeID, epoch)
			if err != nil {
				return err
			}
		}
		if epoch != lease.Epoch() {
			return authority.ErrFenced
		}
		if err := lease.Guard(ctx); err != nil {
			return err
		}
		if err := rootTrustChainCurrent(ctx, sources.js, rootEntry); err != nil {
			return err
		}
		return controllerHostSpecCurrent(ctx, sources.js, sources.specs, profileEntry, rootHead)
	}
	intent, err := sources.intents.ContainerIntent(ctx, spec.Annotations.Labels[swarmruntime.LabelOperationID])
	if err != nil || intent.Role != terrabase.Role || intent.Cell != a.cfg.NATS.Cell || intent.Environment != identity.Environment || intent.Container == nil {
		return rootoci.ErrUnauthorized
	}
	if err := guard(ctx, intent.AuthorityEpoch); err != nil {
		return err
	}
	ctx, stopLease := context.WithDeadline(ctx, lease.Deadline())
	defer stopLease()
	ctx = ociclient.WithRequestGuard(ctx, func(ctx context.Context) error { return guard(ctx, intent.AuthorityEpoch) })
	location, err := instancePrincipalChannel(a.factory.Region(), identity.Cell).get(ctx)
	if err != nil {
		return err
	}
	verify, err := executionleader.NewServiceAuthorizer(executionleader.ServiceAuthorizerConfig{
		Client: client, Authority: sources.mutations, Members: sources.members, Delivery: sources.intents,
		Roots: sources.specs.roots.current(), Cell: a.cfg.NATS.Cell, Environment: identity.Environment, Guard: guard,
		Profile: func(ctx context.Context, intent delivery.Intent) error {
			if err := guard(ctx, intent.AuthorityEpoch); err != nil {
				return err
			}
			_, err := containermaterial.VerifyProfile(profileEntry.Value(), sources.specs.roots.current(), sources.specs.identity, intent)
			return err
		},
		Evidence: func(ctx context.Context, operationID, digest string) (io.ReadCloser, error) {
			if operationID != intent.OperationID {
				return nil, rootoci.ErrUnauthorized
			}
			if err := guard(ctx, intent.AuthorityEpoch); err != nil {
				return nil, err
			}
			return releasechannel.ReadContainerEvidence(ctx, location, terrabase.Role, digest)
		},
		Allocations: func(ctx context.Context, operationID string, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
			if operationID != intent.OperationID {
				return release.SequenceLocation{}, rootoci.ErrUnauthorized
			}
			if err := guard(ctx, intent.AuthorityEpoch); err != nil {
				return release.SequenceLocation{}, err
			}
			before, err := json.Marshal(*intent.Container, json.Deterministic(true))
			after, otherErr := json.Marshal(bundle, json.Deterministic(true))
			if err != nil || otherErr != nil || !bytes.Equal(before, after) {
				return release.SequenceLocation{}, rootoci.ErrUnauthorized
			}
			return currentContainerAllocations(ctx, a.factory, bundle, roots, target)
		},
	})
	if err != nil {
		return err
	}
	return verify.WithStatefulService(ctx, spec, func(effectCtx context.Context) error {
		if err := guard(effectCtx, intent.AuthorityEpoch); err != nil {
			return err
		}
		if err := effect(effectCtx); err != nil {
			return err
		}
		return guard(effectCtx, intent.AuthorityEpoch)
	})
}
