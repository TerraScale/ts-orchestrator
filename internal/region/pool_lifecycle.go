package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// PoolLifecycleBinding identifies one original managed worker. It is unrelated
// to the permission to remove an unknown member and grants no new purchase.
type PoolLifecycleBinding struct {
	InstallationID      string `json:"installationId"`
	Cell                string `json:"cell"`
	Role                string `json:"role"`
	Architecture        string `json:"architecture"`
	Shape               string `json:"shape"`
	BirthOperationID    string `json:"birthOperationId"`
	InstanceID          string `json:"instanceId"`
	BootVolumeID        string `json:"bootVolumeId"`
	BootAttachmentID    string `json:"bootAttachmentId"`
	PoolID              string `json:"poolId"`
	ConfigurationID     string `json:"configurationId"`
	CompartmentID       string `json:"compartmentId"`
	RecipeSHA256        string `json:"recipeSha256"`
	ProfileSHA256       string `json:"profileSha256"`
	PoolBirthSHA256     string `json:"poolBirthSha256"`
	ConfigurationSHA256 string `json:"configurationSha256"`
	BirthSHA256         string `json:"birthSha256"`
	GrantSHA256         string `json:"grantSha256"`
	Generation          uint64 `json:"generation"`
}

// VerifiedPoolLifecycle retains the current signed profile and exact original
// protected birth. Destructive calls additionally require a genuine drain and
// fresh provider identity checks; this proof alone never authorizes deletion.
type VerifiedPoolLifecycle struct {
	ctx      context.Context
	resolver FoundationResolver
	binding  PoolLifecycleBinding
	expires  time.Time
}

func (v VerifiedPoolLifecycle) IsVerified() bool {
	reader, signed := v.resolver.Footprint.(*SignedFootprint)
	store, protected := v.resolver.Store.(*ObjectFoundationStore)
	return v.ctx != nil && v.ctx.Err() == nil && signed && protected && reader != nil && store != nil &&
		v.binding.BirthSHA256 != "" && time.Now().Before(v.expires)
}

func (v VerifiedPoolLifecycle) Binding() PoolLifecycleBinding { return v.binding }
func (v VerifiedPoolLifecycle) ExpiresAt() time.Time          { return v.expires }

func (v VerifiedPoolLifecycle) Revalidate(ctx context.Context) error {
	if !v.IsVerified() {
		return errors.New("known pool lifecycle authority is absent or expired")
	}
	current, err := v.resolver.PoolLifecycle(ctx, v.binding.Cell, v.binding.BirthOperationID, v.binding.InstanceID)
	if err != nil {
		return err
	}
	if !v.IsVerified() || current.binding != v.binding || current.expires.Before(v.expires) {
		return errors.New("known pool lifecycle changed its original birth or current signed profile")
	}
	return ctx.Err()
}

// PoolLifecycle independently selects the current signed managed-worker scope
// and its exact original birth. Historical image evidence remains in the birth;
// cleanup does not depend on the current image channel or spending allowance.
func (r FoundationResolver) PoolLifecycle(ctx context.Context, cell, birthOperationID, instanceID string) (VerifiedPoolLifecycle, error) {
	fail := func(err error) (VerifiedPoolLifecycle, error) { return VerifiedPoolLifecycle{}, err }
	reader, ok := r.Footprint.(*SignedFootprint)
	if ctx == nil || ctx.Err() != nil || !ok || reader == nil || reader.factory == nil ||
		!entityid.Valid(birthOperationID) || !capacityOCID(instanceID, "instance") {
		return fail(errors.New("known pool lifecycle requires original signed SDK discovery and birth selectors"))
	}
	if _, err := r.ProtectedCapacityStore(reader.factory); err != nil {
		return fail(err)
	}
	wire, err := reader.readGrant(ctx)
	if err != nil {
		return fail(err)
	}
	_, expires, err := reader.verifyGrant(wire)
	if err != nil {
		return fail(err)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return fail(err)
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return fail(err)
	}
	record, err := r.Resolve(ctx, cell)
	if err != nil {
		return fail(err)
	}
	if record.GrantSHA256 != reader.home.GrantSHA256 || record.Generation != grant.Generation {
		return fail(errors.New("known pool lifecycle differs from the current signed foundation"))
	}
	child, exists := record.PoolChildren[birthOperationID]
	if !exists || child.InstanceID != instanceID || poolChildRank(child.Stage) < poolChildRank(PoolChildReady) ||
		child.Launch == nil || child.Launch.AcceptedAt.IsZero() || child.Attach == nil || child.Attach.WorkCompletedAt.IsZero() ||
		child.BirthEpoch == 0 || !capacityOCID(child.BootVolumeID, "bootvolume") || !capacityOCID(child.BootAttachmentID, "bootvolumeattachment") {
		return fail(errors.New("known pool lifecycle lacks one exact positive original worker birth and attachment"))
	}
	pool, exists := record.CapacityPools[child.PoolID]
	create, created := record.CapacityCreates[pool.OperationID+":pool"]
	if !exists || !created || create.Kind != "pool" || create.ResourceID != child.PoolID || create.OperationID != pool.OperationID ||
		create.GrantSHA256 != pool.GrantSHA256 || create.Generation != pool.Generation || create.ProfileSHA256 != pool.ProfileSHA256 ||
		create.RecipeSHA256 != pool.RecipeSHA256 || !sameCapacityValue(create.Request, pool.Create) || create.Request.AcceptedAt.IsZero() ||
		pool.CompartmentID != record.ResourceIDs["workload_compartment"] {
		return fail(errors.New("known worker pool lacks its exact original accepted create"))
	}
	initial, err := protectedPoolConfiguration(record, pool, create.ConfigurationID)
	if err != nil || initial.ProfileSHA256 != pool.ProfileSHA256 || initial.RecipeSHA256 != pool.RecipeSHA256 || initial.ConfigurationSHA256 != create.ConfigurationSHA256 {
		return fail(errors.Join(err, errors.New("known worker pool inception lost its original signed configuration")))
	}
	configuration, err := protectedPoolConfiguration(record, pool, child.ConfigurationID)
	if err != nil || configuration.RecipeSHA256 != child.RecipeSHA256 {
		return fail(errors.Join(err, errors.New("known worker differs from its original protected recipe and configuration")))
	}
	var selected WorkerProfile
	matches := 0
	seen := map[string]bool{}
	for _, profile := range grant.WorkerProfiles {
		if err := ValidateWorkerProfile(grant, profile); err != nil {
			return fail(err)
		}
		identity := profile.Cell + "/" + profile.Role + "/" + profile.Architecture + "/" + profile.Shape
		if seen[identity] {
			return fail(errors.New("ambiguous current signed known-worker lifecycle profile"))
		}
		seen[identity] = true
		profileWire, err := json.Marshal(profile, json.Deterministic(true))
		if err != nil {
			return fail(err)
		}
		if profile.Cell == cell && profile.Role == pool.Role && profile.Architecture == pool.Architecture && profile.Shape == pool.Shape &&
			workerSHA256(profileWire) == configuration.ProfileSHA256 {
			selected, matches = profile, matches+1
		}
	}
	if matches != 1 {
		return fail(errors.New("known worker lacks its exact current signed original profile"))
	}
	hash := func(value any) (string, error) {
		wire, err := json.Marshal(value, json.Deterministic(true))
		return workerSHA256(wire), err
	}
	poolBirth, err := hash(create)
	if err != nil {
		return fail(err)
	}
	configurationBirth, err := hash(configuration)
	if err != nil {
		return fail(err)
	}
	birth, err := hash(struct {
		OperationID, RecipeSHA256, PoolID, ConfigurationID, InstanceID, BootVolumeID, BootAttachmentID, Descriptor string
		BirthEpoch                                                                                                 uint64
		BornAt                                                                                                     time.Time
		Launch, Attach                                                                                             *PoolWireRecord
	}{child.OperationID, child.RecipeSHA256, child.PoolID, child.ConfigurationID, child.InstanceID, child.BootVolumeID,
		child.BootAttachmentID, child.Descriptor, child.BirthEpoch, child.BornAt, child.Launch, child.Attach})
	if err != nil {
		return fail(err)
	}
	binding := PoolLifecycleBinding{InstallationID: grant.InstallationID, Cell: cell, Role: selected.Role, Architecture: selected.Architecture,
		Shape: selected.Shape, BirthOperationID: child.OperationID, InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID,
		BootAttachmentID: child.BootAttachmentID, PoolID: child.PoolID, ConfigurationID: child.ConfigurationID, CompartmentID: pool.CompartmentID,
		RecipeSHA256: child.RecipeSHA256, ProfileSHA256: configuration.ProfileSHA256, PoolBirthSHA256: poolBirth,
		ConfigurationSHA256: configurationBirth, BirthSHA256: birth, GrantSHA256: reader.home.GrantSHA256, Generation: grant.Generation}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if limit := time.Now().Add(2 * time.Minute); limit.Before(expires) {
		expires = limit
	}
	if ctx.Err() != nil || !time.Now().Before(expires) {
		return fail(errors.New("known worker lifecycle expired during independent observation"))
	}
	return VerifiedPoolLifecycle{ctx: ctx, resolver: r, binding: binding, expires: expires}, nil
}
