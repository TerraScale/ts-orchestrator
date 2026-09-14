// This file implements the persistent volume catalog of the stateful-first
// hosting lane: the canonical data-volume naming rule, the bounded in-memory
// (roleKind, allocationId) -> volume-binding catalog, and the
// PersistentVolumeStore seam a later NATS-backed store will implement.
package stateful

import (
	"fmt"
	"sort"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// CanonicalDataVolumeId builds the canonical data volume identity of one
// replica: terrascale-<roleKind>-<allocationId>-data. Both tokens are
// validated and the composed name is revalidated as a bounded canonical token.
func CanonicalDataVolumeId(roleKind string, allocationId string) (PersistentVolumeId, error) {
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return PersistentVolumeId{}, err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return PersistentVolumeId{}, err
	}
	return NewPersistentVolumeId(
		"terrascale-" + validatedRole + "-" + validatedAllocation + "-data")
}

// volumeBindingKey is the internal catalog key of one replica.
type volumeBindingKey struct {
	roleKind     string
	allocationId string
}

// PersistentVolumeCatalog is the deterministic in-memory catalog mapping each
// (roleKind, allocationId) replica to its volume binding set. The catalog
// enforces the one-data-volume-per-replica rule, the read-only-mounts-only-
// for-other-role-kinds rule, and the explicit total binding bound; a later
// NATS-backed store sits behind the PersistentVolumeStore seam and everything
// it loads is replayed through the same validation as live mutation.
type PersistentVolumeCatalog struct {
	maximumBindings  int
	bindings         map[volumeBindingKey][]VolumeBinding
	dataVolumeOwners map[string]volumeBindingKey
	totalBindings    int
}

// NewPersistentVolumeCatalog creates one empty catalog with the explicit total
// binding bound that every mutation and restore enforces.
func NewPersistentVolumeCatalog(maximumBindings int) (*PersistentVolumeCatalog, error) {
	if maximumBindings < 1 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "maximumBindings",
			Message: "The catalog binding bound must be at least one.",
		}
	}
	return &PersistentVolumeCatalog{
		maximumBindings:  maximumBindings,
		bindings:         make(map[volumeBindingKey][]VolumeBinding),
		dataVolumeOwners: make(map[string]volumeBindingKey),
	}, nil
}

// BindDataVolume binds the canonical data volume of one replica at one
// destination. Each replica may bind exactly one data volume and the
// destination must be unique among the replica's bindings.
func (c *PersistentVolumeCatalog) BindDataVolume(
	roleKind string,
	allocationId string,
	destination string,
) (VolumeBinding, error) {
	volumeId, err := CanonicalDataVolumeId(roleKind, allocationId)
	if err != nil {
		return VolumeBinding{}, err
	}
	binding, err := NewVolumeBinding(volumeId, roleKind, allocationId, destination, false)
	if err != nil {
		return VolumeBinding{}, err
	}
	key := volumeBindingKey{roleKind: binding.RoleKind, allocationId: binding.AllocationId}
	if _, hasData := c.dataVolumeOwners[binding.VolumeId.Value]; hasData {
		return VolumeBinding{}, &InvalidOperationError{
			Message: "A role allocation may bind only one data volume.",
		}
	}
	if err := c.reserveBinding(key, binding); err != nil {
		return VolumeBinding{}, err
	}
	c.dataVolumeOwners[binding.VolumeId.Value] = key
	return binding, nil
}

// BindReadOnlyMount binds one existing data volume read-only into a replica of
// a different role kind. Read-only mounts are reserved for non-data roles: the
// mounting role kind must differ from the role kind that owns the volume.
func (c *PersistentVolumeCatalog) BindReadOnlyMount(
	volumeId PersistentVolumeId,
	roleKind string,
	allocationId string,
	destination string,
) (VolumeBinding, error) {
	binding, err := NewVolumeBinding(volumeId, roleKind, allocationId, destination, true)
	if err != nil {
		return VolumeBinding{}, err
	}
	owner, owned := c.dataVolumeOwners[binding.VolumeId.Value]
	if !owned {
		return VolumeBinding{}, &InvalidOperationError{
			Message: "Read-only mounts may reference only bound data volumes.",
		}
	}
	if owner.roleKind == binding.RoleKind {
		return VolumeBinding{}, &InvalidOperationError{
			Message: "Read-only mounts are reserved for role kinds other than the data owner.",
		}
	}
	key := volumeBindingKey{roleKind: binding.RoleKind, allocationId: binding.AllocationId}
	if err := c.reserveBinding(key, binding); err != nil {
		return VolumeBinding{}, err
	}
	return binding, nil
}

// DataVolume returns the data volume binding of one replica.
func (c *PersistentVolumeCatalog) DataVolume(roleKind string, allocationId string) (VolumeBinding, error) {
	key, err := requireBindingKey(roleKind, allocationId)
	if err != nil {
		return VolumeBinding{}, err
	}
	for _, binding := range c.bindings[key] {
		if !binding.ReadOnly {
			return binding, nil
		}
	}
	return VolumeBinding{}, &InvalidOperationError{
		Message: "The role allocation binds no data volume.",
	}
}

// Bindings returns the deterministic volume binding set of one replica sorted
// by volume identity.
func (c *PersistentVolumeCatalog) Bindings(roleKind string, allocationId string) ([]VolumeBinding, error) {
	key, err := requireBindingKey(roleKind, allocationId)
	if err != nil {
		return nil, err
	}
	return append([]VolumeBinding(nil), c.bindings[key]...), nil
}

// Snapshot returns every catalog binding sorted by role kind, allocation ID,
// and volume identity.
func (c *PersistentVolumeCatalog) Snapshot() []VolumeBinding {
	snapshot := make([]VolumeBinding, 0, c.totalBindings)
	for _, bindings := range c.bindings {
		snapshot = append(snapshot, bindings...)
	}
	sortStatefulVolumeBindings(snapshot)
	return snapshot
}

// Persist writes the canonical catalog snapshot to one store.
func (c *PersistentVolumeCatalog) Persist(store PersistentVolumeStore) error {
	if store == nil {
		return &errs.Argument{
			Param:   "store",
			Message: "A persistent volume store is required.",
		}
	}
	return store.Save(c.Snapshot())
}

// PersistentVolumeStore is the storage seam of the volume catalog. The
// in-memory catalog is authoritative today; a later NATS-backed store
// implements Load and Save over the same validated binding set, and
// RestorePersistentVolumeCatalog revalidates everything it loads.
type PersistentVolumeStore interface {
	// Load returns the persisted binding set in any order.
	Load() ([]VolumeBinding, error)
	// Save replaces the persisted binding set with the given snapshot.
	Save(bindings []VolumeBinding) error
}

// RestorePersistentVolumeCatalog rebuilds one catalog from a store snapshot.
// Every loaded binding is revalidated and replayed through the same rules as
// live mutation: data volumes first, then read-only mounts, each in canonical
// order, so replay is independent of the store's ordering.
func RestorePersistentVolumeCatalog(
	store PersistentVolumeStore,
	maximumBindings int,
) (*PersistentVolumeCatalog, error) {
	if store == nil {
		return nil, &errs.Argument{
			Param:   "store",
			Message: "A persistent volume store is required.",
		}
	}
	catalog, err := NewPersistentVolumeCatalog(maximumBindings)
	if err != nil {
		return nil, err
	}
	loaded, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(loaded) > maximumBindings {
		return nil, &errs.Argument{
			Param:   "bindings",
			Message: fmt.Sprintf("Binding input exceeds the bound of %d entries.", maximumBindings),
		}
	}
	validated := make([]VolumeBinding, 0, len(loaded))
	seenVolumes := make(map[volumeBindingKey]map[string]struct{}, len(loaded))
	for _, binding := range loaded {
		revalidated, err := NewVolumeBinding(
			binding.VolumeId, binding.RoleKind, binding.AllocationId,
			binding.Destination, binding.ReadOnly)
		if err != nil {
			return nil, err
		}
		key := volumeBindingKey{roleKind: revalidated.RoleKind, allocationId: revalidated.AllocationId}
		volumes := seenVolumes[key]
		if volumes == nil {
			volumes = make(map[string]struct{}, 1)
			seenVolumes[key] = volumes
		}
		if _, duplicate := volumes[revalidated.VolumeId.Value]; duplicate {
			return nil, &InvalidDataError{
				Message: "A persisted volume may be bound only once per role allocation.",
			}
		}
		volumes[revalidated.VolumeId.Value] = struct{}{}
		validated = append(validated, revalidated)
	}
	dataVolumes := make([]VolumeBinding, 0, len(validated))
	readOnlyMounts := make([]VolumeBinding, 0, len(validated))
	for _, binding := range validated {
		if binding.ReadOnly {
			readOnlyMounts = append(readOnlyMounts, binding)
		} else {
			dataVolumes = append(dataVolumes, binding)
		}
	}
	sortStatefulVolumeBindings(dataVolumes)
	sortStatefulVolumeBindings(readOnlyMounts)
	for _, binding := range dataVolumes {
		canonical, err := CanonicalDataVolumeId(binding.RoleKind, binding.AllocationId)
		if err != nil {
			return nil, err
		}
		if binding.VolumeId.Value != canonical.Value {
			return nil, &InvalidDataError{
				Message: "A writable volume must use the canonical data volume name.",
			}
		}
		if _, err := catalog.BindDataVolume(
			binding.RoleKind, binding.AllocationId, binding.Destination); err != nil {
			return nil, err
		}
	}
	for _, binding := range readOnlyMounts {
		if _, err := catalog.BindReadOnlyMount(
			binding.VolumeId, binding.RoleKind, binding.AllocationId,
			binding.Destination); err != nil {
			return nil, err
		}
	}
	return catalog, nil
}

// reserveBinding validates the shared catalog invariants and inserts one
// binding: the total bound, one binding per volume per replica, and unique
// destinations per replica. The per-key slice stays sorted by volume identity
// so every listing is deterministic.
func (c *PersistentVolumeCatalog) reserveBinding(key volumeBindingKey, binding VolumeBinding) error {
	if c.totalBindings+1 > c.maximumBindings {
		return &errs.Argument{
			Param:   "bindings",
			Message: fmt.Sprintf("Binding input exceeds the bound of %d entries.", c.maximumBindings),
		}
	}
	existing := c.bindings[key]
	for _, present := range existing {
		if present.VolumeId.Value == binding.VolumeId.Value {
			return &InvalidOperationError{
				Message: "A volume may be bound only once per role allocation.",
			}
		}
		if present.Destination == binding.Destination {
			return &InvalidOperationError{
				Message: "Volume destinations must be unique per role allocation.",
			}
		}
	}
	updated := make([]VolumeBinding, 0, len(existing)+1)
	updated = append(updated, existing...)
	updated = append(updated, binding)
	sort.Slice(updated, func(left, right int) bool {
		return updated[left].VolumeId.Value < updated[right].VolumeId.Value
	})
	c.bindings[key] = updated
	c.totalBindings++
	return nil
}

// requireBindingKey validates one catalog key.
func requireBindingKey(roleKind string, allocationId string) (volumeBindingKey, error) {
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return volumeBindingKey{}, err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return volumeBindingKey{}, err
	}
	return volumeBindingKey{roleKind: validatedRole, allocationId: validatedAllocation}, nil
}

// sortStatefulVolumeBindings orders bindings by role kind, allocation ID, and
// volume identity.
func sortStatefulVolumeBindings(bindings []VolumeBinding) {
	sort.Slice(bindings, func(left, right int) bool {
		if bindings[left].RoleKind != bindings[right].RoleKind {
			return bindings[left].RoleKind < bindings[right].RoleKind
		}
		if bindings[left].AllocationId != bindings[right].AllocationId {
			return bindings[left].AllocationId < bindings[right].AllocationId
		}
		return bindings[left].VolumeId.Value < bindings[right].VolumeId.Value
	})
}
