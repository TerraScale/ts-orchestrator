package rootfoundation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func (b *Backend) BeginPoolDrain(ctx context.Context, call rootoci.Call, child drainwire.PoolChild) (rootoci.PoolDrainView, error) {
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	snapshot, err := b.poolSnapshot(ctx, call)
	if err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if err := checkCall(ctx, call, rootoci.OperationBeginPoolDrain, rootoci.Expectations{Cell: b.cell, GrantSHA256: child.GrantSHA256, OperationID: child.RemovalOperationID, Epoch: snapshot.source.Epoch}); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	resolver, record, _, err := b.loadPoolChild(ctx, call, child)
	if err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if previous, exists := record.PoolDrains[child.RemovalOperationID]; exists {
		if previous.Child != child {
			return rootoci.PoolDrainView{}, ErrScope
		}
		if err := b.guardPoolReceipt(ctx, call, previous); err != nil {
			return rootoci.PoolDrainView{}, err
		}
		if err := b.poolSources.Node.FinishPoolDrainCapture(ctx, previous, b.poolSources.Leases, b.poolSources.Hosts); err != nil {
			return rootoci.PoolDrainView{}, err
		}
		return poolDrainView(previous)
	}
	if len(record.PoolDrains) >= drainwire.MaxPoolDrains {
		return rootoci.PoolDrainView{}, errors.New("protected pending drain limit reached")
	}
	for _, previous := range record.PoolDrains {
		if previous.Child.InstanceID == child.InstanceID {
			return rootoci.PoolDrainView{}, ErrScope
		}
	}
	receipt, err := b.poolSources.Node.CapturePoolDrain(ctx, child, snapshot.source, snapshot.specWire, snapshot.rootWire, b.poolSources.Leases, b.poolSources.Hosts)
	if err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if err := resolver.VerifyCurrentPoolDrainSource(ctx, receipt); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if err := b.commitPoolDrain(ctx, call, receipt); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	// A protected CAS and exact fresh readback precede every DRAIN update.
	if err := b.poolSources.Node.FinishPoolDrainCapture(ctx, receipt, b.poolSources.Leases, b.poolSources.Hosts); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	return poolDrainView(receipt)
}

func (b *Backend) RefreshPoolDrain(ctx context.Context, call rootoci.Call, child drainwire.PoolChild) (rootoci.PoolDrainView, error) {
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	_, record, _, err := b.loadPoolChild(ctx, call, child)
	if err != nil {
		return rootoci.PoolDrainView{}, err
	}
	receipt, exists := record.PoolDrains[child.RemovalOperationID]
	if !exists || receipt.Child != child {
		return rootoci.PoolDrainView{}, rootoci.ErrPending
	}
	if err := checkCall(ctx, call, rootoci.OperationRefreshPoolDrain, rootoci.Expectations{Cell: b.cell, GrantSHA256: child.GrantSHA256, OperationID: child.RemovalOperationID, Epoch: receipt.Source.Epoch}); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if err := b.guardPoolReceipt(ctx, call, receipt); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if err := b.poolSources.Node.VerifyPoolDrain(ctx, receipt, b.poolSources.Leases, b.poolSources.Hosts); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if err := b.verifyPoolProviderFences(ctx, call, record, receipt); err != nil {
		return rootoci.PoolDrainView{}, err
	}
	if receipt.Phase != drainwire.PoolStopped {
		now := time.Now().UTC()
		receipt.BackendsCheckedAt, receipt.DataCheckedAt, receipt.StoppedAt, receipt.Phase = now, now, now, drainwire.PoolStopped
		if err := b.commitPoolDrain(ctx, call, receipt); err != nil {
			return rootoci.PoolDrainView{}, err
		}
	}
	return poolDrainView(receipt)
}

func (b *Backend) loadPoolChild(ctx context.Context, call rootoci.Call, child drainwire.PoolChild) (region.FoundationResolver, region.FoundationRecord, string, error) {
	var empty region.FoundationRecord
	if child.Validate() != nil || child.Cell != b.cell {
		return region.FoundationResolver{}, empty, "", ErrScope
	}
	resolver, err := b.current(ctx, call)
	if err != nil {
		return resolver, empty, "", err
	}
	lifecycle, err := resolver.PoolLifecycle(ctx, b.cell, child.BirthOperationID, child.InstanceID)
	if err != nil {
		return resolver, empty, "", err
	}
	binding := lifecycle.Binding()
	if !lifecycle.IsVerified() || binding.PoolID != child.PoolID || binding.ConfigurationID != child.ConfigurationID || binding.RecipeSHA256 != child.RecipeSHA256 || binding.GrantSHA256 != child.GrantSHA256 || binding.Generation != child.Generation {
		return resolver, empty, "", ErrScope
	}
	record, etag, err := resolver.Store.Load(ctx, b.cell)
	if err != nil {
		return resolver, empty, "", err
	}
	protected, exists := record.PoolChildren[child.BirthOperationID]
	if !exists || protected.InstanceID != child.InstanceID || protected.Stage == region.PoolChildRetired ||
		protected.RemovalOperationID != "" && protected.RemovalOperationID != child.RemovalOperationID {
		return resolver, empty, "", ErrScope
	}
	return resolver, record, etag, lifecycle.Revalidate(ctx)
}

func (b *Backend) commitPoolDrain(ctx context.Context, call rootoci.Call, receipt drainwire.PoolReceipt) error {
	resolver, record, etag, err := b.loadPoolChild(ctx, call, receipt.Child)
	if err != nil {
		return err
	}
	if previous, exists := record.PoolDrains[receipt.Child.RemovalOperationID]; exists {
		if err := receipt.Retains(previous); err != nil {
			return err
		}
	} else {
		if len(record.PoolDrains) >= drainwire.MaxPoolDrains {
			return rootoci.ErrPending
		}
		for _, existing := range record.PoolDrains {
			if existing.Child.InstanceID == receipt.Child.InstanceID {
				return ErrScope
			}
		}
	}
	if err := b.guardPoolReceipt(ctx, call, receipt); err != nil {
		return err
	}
	if record.PoolDrains == nil {
		record.PoolDrains = make(map[string]drainwire.PoolReceipt)
	}
	record.PoolDrains[receipt.Child.RemovalOperationID] = receipt.Clone()
	record.UpdatedAt = time.Now().UTC()
	guard := func(check context.Context) error {
		if err := b.guardPoolReceipt(check, call, receipt); err != nil {
			return err
		}
		if receipt.Phase == drainwire.PoolStopped {
			if err := b.poolSources.Node.VerifyPoolDrain(check, receipt, b.poolSources.Leases, b.poolSources.Hosts); err != nil {
				return err
			}
			return b.verifyPoolProviderFences(check, call, record, receipt)
		}
		return nil
	}
	writeCtx := ociclient.WithRequestGuard(ociclient.CheckpointContext(ctx), func(check context.Context) error {
		return guard(b.poolLifetimeContext(check, call, receipt.ExpiresAt))
	})
	if _, err := resolver.Store.CompareAndSwap(writeCtx, record, etag); err != nil {
		return err
	}
	readback, readETag, err := resolver.Store.Load(ctx, b.cell)
	if err != nil {
		return err
	}
	got, exists := readback.PoolDrains[receipt.Child.RemovalOperationID]
	wantSHA, err := receipt.SHA256()
	if err != nil {
		return err
	}
	gotSHA, err := got.SHA256()
	if err != nil || !exists || readETag == "" || gotSHA != wantSHA {
		return errors.Join(ErrScope, err)
	}
	return b.guardPoolReceipt(ctx, call, receipt)
}

func poolDrainView(receipt drainwire.PoolReceipt) (rootoci.PoolDrainView, error) {
	digest, err := receipt.SHA256()
	return rootoci.PoolDrainView{Child: receipt.Child, Phase: receipt.Phase, SHA256: digest, ExpiresAt: receipt.ExpiresAt}, err
}

func (b *Backend) PoolDrainChallenges(ctx context.Context, call rootoci.Call, query rootoci.PoolDrainQuery) ([]drainwire.DrainStopChallenge, error) {
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	if _, err := b.poolSnapshot(ctx, call); err != nil {
		return nil, err
	}
	resolver, err := b.current(ctx, call)
	if err != nil {
		return nil, err
	}
	record, _, err := resolver.Store.Load(ctx, b.cell)
	if err != nil {
		return nil, err
	}
	var challenges []drainwire.DrainStopChallenge
	for _, receipt := range record.PoolDrains {
		if !time.Now().Before(receipt.ExpiresAt) {
			continue
		}
		if err := b.guardPoolReceipt(ctx, call, receipt); err != nil {
			return nil, err
		}
		for _, challenge := range receipt.Challenges {
			if slices.ContainsFunc(query.Executions, func(selector rootoci.PoolDrainSelector) bool {
				return selector.InstanceID == challenge.InstanceID && selector.ExecutionSessionID == challenge.ExecutionSessionID
			}) {
				challenges = append(challenges, challenge)
			}
		}
	}
	return challenges, call.Guard(ctx)
}

func (b *Backend) StorePoolDrainStop(ctx context.Context, call rootoci.Call, stop drainwire.SignedStop) error {
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	resolver, err := b.current(ctx, call)
	if err != nil {
		return err
	}
	record, _, err := resolver.Store.Load(ctx, b.cell)
	if err != nil {
		return err
	}
	receipt, exists := record.PoolDrains[stop.Challenge.RemovalOperationID]
	if !exists || receipt.Child.InstanceID != stop.Challenge.InstanceID || !slices.Contains(receipt.Challenges, stop.Challenge) {
		return ErrScope
	}
	if err := b.guardPoolReceipt(ctx, call, receipt); err != nil {
		return err
	}
	if err := drainwire.VerifySignedStop(stop, stop.Challenge, receipt.WorkerCertificate, receipt.ClusterCAPEM, receipt.ClusterID, time.Now().UTC()); err != nil {
		return err
	}
	for _, previous := range receipt.Stops {
		if previous.Challenge == stop.Challenge {
			return nil
		}
	}
	if receipt.Phase != drainwire.PoolCaptured {
		return ErrScope
	}
	receipt.Stops = append(receipt.Stops, stop)
	return b.commitPoolDrain(ctx, call, receipt)
}

// Every pending capture and every terminal transfer remains a permanent start
// fence, including expired captures and successor sessions or signed sources.
func (b *Backend) GuardPoolExecution(ctx context.Context, call rootoci.Call, hold drainwire.ExecutionHold) error {
	// The caller may hold the authority append mutex that capture's renewal
	// barrier needs. Refuse busy starts instead of waiting for that capture.
	if !b.poolMu.TryLock() {
		return rootoci.ErrPending
	}
	defer b.poolMu.Unlock()
	if hold.Validate() != nil {
		return ErrScope
	}
	snapshot, err := b.poolSnapshot(ctx, call)
	if err != nil {
		return err
	}
	if hold.Cell != strings.ToLower(b.cell) || hold.OriginalEpoch != snapshot.source.Epoch {
		return ErrScope
	}
	resolver, err := b.current(ctx, call)
	if err != nil {
		return err
	}
	record, _, err := resolver.Store.Load(ctx, b.cell)
	if err != nil {
		return err
	}
	for _, receipt := range record.PoolDrains {
		if receipt.Child.InstanceID == hold.InstanceID {
			return rootoci.ErrPending
		}
	}
	for _, child := range record.PoolChildren {
		if child.InstanceID == hold.InstanceID && (child.RetirementDrain != nil || child.RemovalOperationID != "") {
			return rootoci.ErrPending
		}
	}
	reader, err := b.poolSources.Node.ReadOnlyControlClient(ctx)
	if err != nil {
		return err
	}
	node, err := reader.GetNode(ctx, &api.GetNodeRequest{NodeID: hold.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return errors.Join(ErrScope, err)
	}
	actual := node.Node
	if actual.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != hold.InstanceID || actual.Spec.Annotations.Name != hold.RegistrationID ||
		actual.Role != api.NodeRoleWorker || actual.Spec.DesiredRole != api.NodeRoleWorker || actual.Spec.Availability != api.NodeAvailabilityActive || actual.Spec.Membership != api.NodeMembershipAccepted {
		return ErrScope
	}
	current, err := b.poolSources.Hosts.CurrentGenericExecutionSession(ctx, hold.HostNode)
	if err != nil || !current.SameIdentity(hold.HostSession) {
		return errors.Join(ErrScope, err)
	}
	task, err := reader.GetTask(ctx, &api.GetTaskRequest{TaskID: hold.TaskID})
	if err != nil || task == nil || task.Task == nil {
		return errors.Join(ErrScope, err)
	}
	hash, err := executionwire.TaskSHA256(task.Task)
	if err != nil || hash != hold.TaskSHA256 || task.Task.NodeID != hold.NodeID || task.Task.ServiceID != hold.ServiceID || task.Task.DesiredState != api.TaskStateRunning {
		return errors.Join(ErrScope, err)
	}
	return snapshot.lease.Guard(ctx)
}

var _ rootoci.PoolDrains = (*Backend)(nil)
