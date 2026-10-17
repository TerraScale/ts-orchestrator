package nodescale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// ChosenPool retains the original durable birth while the root independently
// resolves current signed authority and every provider mutation.
type ChosenPool struct {
	observed *OCIPool
	store    RecordStore
	root     *rootoci.Client
	current  func(context.Context, Record) (rootoci.PoolChildExpectation, error)
}

func NewChosenPool(observed *OCIPool, store RecordStore, client *rootoci.Client, current func(context.Context, Record) (rootoci.PoolChildExpectation, error)) (*ChosenPool, error) {
	if observed == nil || store == nil || client == nil || current == nil {
		return nil, errors.New("chosen capacity requires read-only OCI discovery, durable state and authenticated root lifecycle authority")
	}
	return &ChosenPool{observed: observed, store: store, root: client, current: current}, nil
}

func (pool *ChosenPool) selectors(ctx context.Context, record Record) (rootoci.PoolChildExpectation, error) {
	selected, err := pool.current(ctx, record)
	if err != nil {
		return rootoci.PoolChildExpectation{}, err
	}
	if !strings.EqualFold(selected.Cell, pool.observed.cell) || len(selected.GrantSHA256) != 64 || selected.Generation == 0 || selected.Epoch == 0 {
		return rootoci.PoolChildExpectation{}, fmt.Errorf("%w: current finite root capacity selectors are unavailable", ErrCapacityPending)
	}
	selected.Cell = strings.ToUpper(pool.observed.cell)
	return selected, nil
}

func (pool *ChosenPool) Observe(ctx context.Context) (PoolState, error) {
	state, err := pool.observed.Observe(ctx)
	if err != nil {
		return PoolState{}, err
	}
	for index := range state.Instances {
		instance := &state.Instances[index]
		proof, err := pool.root.VerifyPoolChild(ctx, rootoci.PoolChildObservation{Cell: strings.ToUpper(pool.observed.cell), InstanceID: instance.ID, PoolID: instance.PoolID})
		if err != nil {
			instance.Name = ""
			state.Pending = fmt.Sprintf("%s has no current authenticated original pool birth: %v", instance.ID, err)
			continue
		}
		view := proof.View()
		if view.CompartmentID != pool.observed.compartmentID || view.Role != instance.Capacity.Role || view.Architecture != instance.Capacity.Architecture || view.Shape != instance.Capacity.Shape || !naming.IsNode(view.Node, strings.ToUpper(pool.observed.cell)) {
			return PoolState{}, errors.New("root pool birth differs from observed regional capacity membership")
		}
		instance.Name, instance.PrivateIP, instance.ConfigurationID, instance.Birth = view.Node, view.PrivateIP, view.ConfigurationID, new(view)
	}
	return state, nil
}

func (pool *ChosenPool) TargetSize(ctx context.Context, recipe Recipe) (int, error) {
	if recipe.Cell != pool.observed.cell || recipe.Capacity.Validate() != nil {
		return 0, errors.New("selected capacity differs from the regional isolation role")
	}
	chosen := *pool.observed
	chosen.capacity = recipe.Capacity
	return chosen.TargetSize(ctx, recipe)
}

func (pool *ChosenPool) PrepareGrowth(ctx context.Context, record Record) (rootoci.PoolChildExpectation, error) {
	if record.Action == nil || record.Action.Kind != Up || !entityid.Valid(record.Action.ID) || record.Recipe == nil || record.Reservation == nil || record.Recipe.Validate() != nil || record.Recipe.Cell != pool.observed.cell ||
		record.Reservation.OperationID != record.Action.ID || record.Reservation.RecipeSHA256 != record.Recipe.SHA256() {
		return rootoci.PoolChildExpectation{}, fmt.Errorf("%w: exact original birth and reservation are not durable", ErrCapacityPending)
	}
	selected, err := pool.selectors(ctx, record)
	if err != nil {
		return rootoci.PoolChildExpectation{}, err
	}
	bundle, err := hostenroll.ParsePublicBundle([]byte(record.Recipe.Metadata[hostboot.EnrollmentMetadataKey]))
	if err != nil {
		return rootoci.PoolChildExpectation{}, err
	}
	if selected.OperationID != "" && selected.OperationID != record.Action.ID || selected.ReservationID != "" && selected.ReservationID != record.Reservation.OperationID || selected.RecipeSHA256 != "" && selected.RecipeSHA256 != record.Recipe.SHA256() ||
		len(selected.PublicCAPEM) != 0 && !bytes.Equal(selected.PublicCAPEM, []byte(bundle.CAPEM)) || len(selected.AvailabilityDomains) != 0 && !slices.Equal(selected.AvailabilityDomains, record.Recipe.AvailabilityDomains) {
		return rootoci.PoolChildExpectation{}, errors.New("current selectors cannot replace the original durable pool birth")
	}
	selected.OperationID, selected.ReservationID, selected.RecipeSHA256 = record.Action.ID, record.Reservation.OperationID, record.Recipe.SHA256()
	selected.PublicCAPEM, selected.AvailabilityDomains = []byte(bundle.CAPEM), slices.Clone(record.Recipe.AvailabilityDomains)
	return selected, nil
}

// Grow resumes only the root's original create/launch/attach, even while discovery is pending.
func (pool *ChosenPool) Grow(ctx context.Context, from int) error {
	record, _, err := pool.store.Load(ctx)
	if err != nil {
		return err
	}
	if from < 0 || from >= MaxPoolNodes || record.From != from || record.TargetFrom == nil || record.Child == nil {
		return fmt.Errorf("%w: exact original root birth is not durable", ErrCapacityPending)
	}
	current, err := pool.PrepareGrowth(ctx, record)
	if err != nil {
		return err
	}
	original := *record.Child
	if original.Cell != current.Cell || original.OperationID != current.OperationID || original.ReservationID != current.ReservationID || original.RecipeSHA256 != current.RecipeSHA256 || !bytes.Equal(original.PublicCAPEM, current.PublicCAPEM) || !slices.Equal(original.AvailabilityDomains, current.AvailabilityDomains) {
		return errors.New("durable root birth differs from its original recipe and reservation")
	}
	original.GrantSHA256, original.Generation, original.Epoch = current.GrantSHA256, current.Generation, current.Epoch
	view, err := pool.root.AdvancePoolChild(ctx, original)
	if err != nil {
		return errors.Join(ErrCapacityPending, err)
	}
	if view.Stage != "attached" || view.Cell != original.Cell || view.OperationID != original.OperationID || view.ReservationID != original.ReservationID || view.RecipeSHA256 != original.RecipeSHA256 || view.InstanceID == "" || !naming.IsNode(view.Node, original.Cell) {
		return errors.New("root advance did not return the exact original attached child")
	}
	return nil
}

func (pool *ChosenPool) PrepareRetirement(ctx context.Context, instanceID, removalOperationID string) (rootoci.PoolRetirementExpectation, error) {
	if !entityid.Valid(removalOperationID) {
		return rootoci.PoolRetirementExpectation{}, errors.New("pool retirement needs its original removal operation")
	}
	record, _, err := pool.store.Load(ctx)
	if err != nil {
		return rootoci.PoolRetirementExpectation{}, err
	}
	selected, err := pool.selectors(ctx, record)
	if err != nil {
		return rootoci.PoolRetirementExpectation{}, err
	}
	proof, err := pool.root.VerifyPoolChild(ctx, rootoci.PoolChildObservation{Cell: selected.Cell, InstanceID: instanceID})
	if err != nil {
		return rootoci.PoolRetirementExpectation{}, err
	}
	birth := proof.View()
	return rootoci.PoolRetirementExpectation{Child: rootoci.PoolChildExpectation{Cell: birth.Cell, OperationID: birth.OperationID, ReservationID: birth.ReservationID,
		RecipeSHA256: birth.RecipeSHA256, PoolID: birth.PoolID, ConfigurationID: birth.ConfigurationID,
		GrantSHA256: selected.GrantSHA256, Generation: selected.Generation, Epoch: selected.Epoch}, InstanceID: instanceID, RemovalOperationID: removalOperationID}, nil
}

func (pool *ChosenPool) Remove(ctx context.Context, instanceID string) error {
	record, _, err := pool.store.Load(ctx)
	if err != nil {
		return err
	}
	if record.Action == nil || record.Retirement == nil || record.Retirement.InstanceID != instanceID || record.Retirement.RemovalOperationID != removalOperation(record, instanceID) {
		return fmt.Errorf("%w: exact original root retirement is not durable", ErrCapacityPending)
	}
	selected, err := pool.selectors(ctx, record)
	if err != nil {
		return err
	}
	original := *record.Retirement
	original.Child.GrantSHA256, original.Child.Generation, original.Child.Epoch = selected.GrantSHA256, selected.Generation, selected.Epoch
	view, err := pool.root.RetirePoolChild(ctx, original)
	if err != nil {
		return errors.Join(ErrCapacityPending, err)
	}
	if view.Stage != "retired" || view.Cell != original.Child.Cell || view.InstanceID != original.InstanceID || view.RemovalOperationID != original.RemovalOperationID {
		return fmt.Errorf("%w: original instance and boot volume retirement is incomplete", ErrCapacityPending)
	}
	return nil
}

func removalOperation(record Record, instanceID string) string {
	if record.Action == nil {
		return ""
	}
	if record.Action.Kind == Down {
		return record.Action.ID
	}
	return entityid.Derive("expired-pool-child-removal", record.Action.ID, instanceID)
}

// Recover requests exact nonterminating quarantine; only the root's independently
// signed membership purpose can authorize detaching an unknown member.
func (pool *ChosenPool) Recover(ctx context.Context) error {
	record, _, err := pool.store.Load(ctx)
	if err != nil {
		return err
	}
	if record.Action != nil {
		return nil
	}
	state, err := pool.Observe(ctx)
	if err != nil {
		return err
	}
	for _, instance := range state.Instances {
		if instance.Birth != nil {
			continue
		}
		selected, err := pool.selectors(ctx, record)
		if err != nil {
			return err
		}
		operation := entityid.Derive("unknown-pool-member-quarantine", selected.Cell, instance.PoolID, instance.ID)
		view, err := pool.root.QuarantinePoolChild(ctx, rootoci.PoolQuarantineExpectation{Cell: selected.Cell, PoolID: instance.PoolID, InstanceID: instance.ID, OperationID: operation,
			GrantSHA256: selected.GrantSHA256, Generation: selected.Generation, Epoch: selected.Epoch})
		if err != nil {
			return errors.Join(ErrCapacityPending, err)
		}
		if view.Stage != "quarantined" || view.Cell != selected.Cell || view.PoolID != instance.PoolID || view.InstanceID != instance.ID || view.OperationID != operation {
			return fmt.Errorf("%w: original unknown-member quarantine is incomplete", ErrCapacityPending)
		}
		return nil
	}
	return nil
}

var _ Pool = (*ChosenPool)(nil)
