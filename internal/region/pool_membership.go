package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// PoolMembershipBinding describes only unknown-member quarantine authority.
// It grants no launch, enrollment, instance termination or volume deletion.
type PoolMembershipBinding struct {
	InstallationID      string               `json:"installationId"`
	Cell                string               `json:"cell"`
	Role                string               `json:"role"`
	Architecture        string               `json:"architecture"`
	Shape               string               `json:"shape"`
	PoolID              string               `json:"poolId"`
	ConfigurationID     string               `json:"configurationId"`
	GrantSHA256         string               `json:"grantSha256"`
	Generation          uint64               `json:"generation"`
	ProfileSHA256       string               `json:"profileSha256"`
	PoolProfileSHA256   string               `json:"poolProfileSha256"`
	PoolRecipeSHA256    string               `json:"poolRecipeSha256"`
	RecipeSHA256        string               `json:"recipeSha256"`
	PoolBirthSHA256     string               `json:"poolBirthSha256"`
	InitialConfigSHA256 string               `json:"initialConfigSha256"`
	ConfigBirthSHA256   string               `json:"configBirthSha256"`
	Permission          WorkerPoolMembership `json:"permission"`
}

// VerifiedPoolMembership is minted from the concrete signed source and its
// original protected home store. Public JSON cannot construct this proof.
type VerifiedPoolMembership struct {
	ctx      context.Context
	resolver FoundationResolver
	binding  PoolMembershipBinding
	digest   string
	expires  time.Time
}

func (v VerifiedPoolMembership) IsVerified() bool {
	reader, signed := v.resolver.Footprint.(*SignedFootprint)
	store, protected := v.resolver.Store.(*ObjectFoundationStore)
	return v.ctx != nil && v.ctx.Err() == nil && signed && protected && reader != nil && store != nil && v.digest != "" &&
		v.binding.Permission.Purpose == PoolMembershipQuarantineV1 &&
		v.binding.Permission.Provenance == PoolMembershipProvenanceV1 && time.Now().Before(v.expires)
}

func (v VerifiedPoolMembership) Binding() PoolMembershipBinding { return v.binding }
func (v VerifiedPoolMembership) PurposeSHA256() string          { return v.digest }
func (v VerifiedPoolMembership) ExpiresAt() time.Time           { return v.expires }

func (v VerifiedPoolMembership) Revalidate(ctx context.Context) error {
	if !v.IsVerified() {
		return errors.New("pool membership authority is absent or expired")
	}
	current, err := v.resolver.PoolMembership(ctx, v.binding.Cell, v.binding.PoolID, v.binding.ConfigurationID)
	if err != nil {
		return err
	}
	if !v.IsVerified() || current.binding != v.binding || current.digest != v.digest || current.expires.Before(v.expires) {
		return errors.New("pool membership permission or original provenance changed")
	}
	return ctx.Err()
}

// PoolMembership resolves a narrowing selector against current signed policy
// and retained positive original creates. It never adopts a discovered pool.
func (r FoundationResolver) PoolMembership(ctx context.Context, cell, poolID, configurationID string) (VerifiedPoolMembership, error) {
	fail := func(err error) (VerifiedPoolMembership, error) { return VerifiedPoolMembership{}, err }
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader == nil || reader.factory == nil || !capacityOCID(poolID, "instancepool") || !capacityOCID(configurationID, "instanceconfiguration") {
		return fail(errors.New("pool membership requires the original signed SDK source"))
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
		return fail(errors.New("pool membership differs from the current original signed foundation"))
	}
	pool, exists := record.CapacityPools[poolID]
	create, created := record.CapacityCreates[pool.OperationID+":pool"]
	if !exists || !created || pool.CurrentConfigurationID != configurationID ||
		create.Kind != "pool" || create.ResourceID != poolID || create.OperationID != pool.OperationID ||
		create.GrantSHA256 != pool.GrantSHA256 || create.Generation != pool.Generation ||
		create.ProfileSHA256 != pool.ProfileSHA256 || create.RecipeSHA256 != pool.RecipeSHA256 ||
		!sameCapacityValue(create.Request, pool.Create) || create.Request.AcceptedAt.IsZero() ||
		pool.CompartmentID != record.ResourceIDs["workload_compartment"] {
		return fail(errors.New("pool membership lacks the exact original accepted pool create"))
	}
	initial, err := protectedPoolConfiguration(record, pool, create.ConfigurationID)
	if err != nil || initial.ProfileSHA256 != pool.ProfileSHA256 || initial.RecipeSHA256 != pool.RecipeSHA256 || initial.ConfigurationSHA256 != create.ConfigurationSHA256 {
		return fail(errors.Join(err, errors.New("pool inception differs from its original signed configuration")))
	}
	configuration, err := protectedPoolConfiguration(record, pool, configurationID)
	if err != nil {
		return fail(err)
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
			return fail(errors.New("ambiguous signed pool membership profile"))
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
		return fail(errors.New("original pool configuration lacks its exact current signed membership purpose"))
	}
	digestValue := func(value any) (string, error) {
		wire, err := json.Marshal(value, json.Deterministic(true))
		if err != nil {
			return "", err
		}
		return workerSHA256(wire), nil
	}
	poolBirth, err := digestValue(create)
	if err != nil {
		return fail(err)
	}
	initialBirth, err := digestValue(initial)
	if err != nil {
		return fail(err)
	}
	configBirth, err := digestValue(configuration)
	if err != nil {
		return fail(err)
	}
	binding := PoolMembershipBinding{InstallationID: grant.InstallationID, Cell: cell, Role: selected.Role, Architecture: selected.Architecture,
		Shape: selected.Shape, PoolID: poolID, ConfigurationID: configurationID, GrantSHA256: reader.home.GrantSHA256, Generation: grant.Generation,
		ProfileSHA256: configuration.ProfileSHA256, PoolProfileSHA256: pool.ProfileSHA256, PoolRecipeSHA256: pool.RecipeSHA256,
		RecipeSHA256: configuration.RecipeSHA256, PoolBirthSHA256: poolBirth, InitialConfigSHA256: initialBirth, ConfigBirthSHA256: configBirth,
		Permission: selected.PoolMembership}
	// Current authorization is rechecked separately; the durable selector keeps
	// the same finite permission and original births across compatible grants.
	purpose := binding
	purpose.GrantSHA256, purpose.Generation = "", 0
	digest, err := digestValue(purpose)
	if err != nil {
		return fail(err)
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if limit := time.Now().Add(2 * time.Minute); limit.Before(expires) {
		expires = limit
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if !time.Now().Before(expires) {
		return fail(errors.New("pool membership authority expired during observation"))
	}
	return VerifiedPoolMembership{ctx: ctx, resolver: r, binding: binding, digest: digest, expires: expires}, nil
}

func protectedPoolConfiguration(record FoundationRecord, pool PoolResourceRecord, id string) (PoolConfigurationRecord, error) {
	configuration, exists := pool.Configurations[id]
	create, created := record.CapacityCreates[configuration.OperationID+":configuration"]
	if !exists || !created || create.Kind != "configuration" || create.ResourceID != id || configuration.ConfigurationID != id ||
		create.OperationID != configuration.OperationID || create.ProfileSHA256 != configuration.ProfileSHA256 || create.RecipeSHA256 != configuration.RecipeSHA256 ||
		create.ConfigurationSHA256 != configuration.ConfigurationSHA256 || create.GrantSHA256 != configuration.GrantSHA256 || create.Generation != configuration.Generation ||
		create.Request.AcceptedAt.IsZero() || !sameCapacityValue(create.Request, configuration.Create) {
		return PoolConfigurationRecord{}, errors.New("pool configuration lacks its exact original accepted create")
	}
	return configuration, nil
}
