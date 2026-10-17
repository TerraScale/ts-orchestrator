package foundationbinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const recordLimit = 128 << 10

// Authority contains the exact grant and protected home storage identity from
// the caller's currently verified bootstrap anchor. It conveys no resource IDs.
type Authority struct {
	Scope          trust.Scope
	Roots          trust.Keyring
	Policy         trust.Policy
	GrantSHA256    string
	Generation     uint64
	InstallationID string
	TenancyID      string
	Namespace      string
	Bucket         string
	Prefix         string
	Cell           string
	Keys           []string
}

// VerifiedBindings has no public constructor from observed IDs or maps.
type VerifiedBindings struct {
	factory              *ociclient.Factory
	authority            Authority
	wire                 []byte
	expires              time.Time
	ids                  map[string]string
	capacityLedger       *capacityledger.Ledger
	capacityCompartments []string
	capacityCurrency     string
	capacityChildren     jsontext.Value
	observedAt           time.Time
}

func (v VerifiedBindings) GrantSHA256() string  { return v.authority.GrantSHA256 }
func (v VerifiedBindings) Generation() uint64   { return v.authority.Generation }
func (v VerifiedBindings) Cell() string         { return v.authority.Cell }
func (v VerifiedBindings) ExpiresAt() time.Time { return v.expires }

// ForCell independently verifies another approved cell under the same exact
// root grant. Query narrowing belongs to the selected cell, not the root scope.
func (v VerifiedBindings) ForCell(ctx context.Context, cell string) (VerifiedBindings, error) {
	if v.factory == nil {
		return VerifiedBindings{}, errors.New("foundation bindings are unverified")
	}
	authority := v.authority
	authority.Cell, authority.Keys = cell, nil
	return Verify(ctx, v.factory, authority, v.wire)
}

// Resolve accepts only the verified cell's finite logical roles.
func (v VerifiedBindings) Resolve(reference string) (string, error) {
	cell, key, err := Parse(reference)
	if err != nil || v.factory == nil || !time.Now().Before(v.expires) || cell != v.authority.Cell || v.ids[key] == "" {
		return "", errors.New("foundation reference has no current independently verified binding")
	}
	return v.ids[key], nil
}

// Revalidate repeats authentication, durable record reads and all OCI Get calls.
func (v VerifiedBindings) Revalidate(ctx context.Context) error {
	if v.factory == nil {
		return errors.New("foundation bindings are unverified")
	}
	current, err := Verify(ctx, v.factory, v.authority, v.wire)
	if err != nil {
		return err
	}
	if !maps.Equal(v.ids, current.ids) {
		return errors.New("foundation bindings changed after verification")
	}
	return nil
}

type grant struct {
	WorkerProfiles      jsontext.Value   `json:"workerProfiles,omitempty"`
	ReleaseAuthorities  jsontext.Value   `json:"releaseAuthorities,omitempty"`
	InstallationID      string           `json:"installationId"`
	SchemaVersion       int              `json:"schemaVersion"`
	Generation          uint64           `json:"generation"`
	TenancyID           string           `json:"tenancyId"`
	ParentCompartmentID string           `json:"parentCompartmentId"`
	SharedCompartmentID string           `json:"sharedCompartmentId"`
	Currency            string           `json:"currency"`
	MonthlyLimitMinor   int64            `json:"monthlyLimitMinor"`
	CleanupOwner        string           `json:"cleanupOwner"`
	Regions             []jsontext.Value `json:"regions"`
	InfrastructureSpend jsontext.Value   `json:"infrastructureSpend,omitempty"`
	OCIRIssuances       jsontext.Value   `json:"ocirIssuances,omitempty"`
}

type intent struct {
	Generation        uint64         `json:"generation"`
	Plan              map[string]any `json:"plan"`
	BootstrapMaterial jsontext.Value `json:"bootstrapMaterial,omitempty"`
	ReadAccess        jsontext.Value `json:"readAccess,omitempty"`
	NetBirdManager    jsontext.Value `json:"netbirdManager,omitempty"`
}

type createRequest struct {
	Key           string `json:"key"`
	Region        string `json:"region"`
	RequestDigest string `json:"requestDigest"`
	RetryToken    string `json:"retryToken,omitempty"`
}

type pendingCreate struct {
	OperationID    string        `json:"operationId"`
	IntentDigest   string        `json:"intentDigest"`
	Request        createRequest `json:"request"`
	FirstAttemptAt time.Time     `json:"firstAttemptAt"`
}

type provenance struct {
	Create      pendingCreate `json:"create"`
	ResourceID  string        `json:"resourceId"`
	Generation  uint64        `json:"generation"`
	GrantSHA256 string        `json:"grantSha256"`
}

// These private wire views avoid importing the region/bootstrap packages:
// their consumers must be able to call this verifier without an import cycle.
type record struct {
	FoundationWriter    jsontext.Value           `json:"foundationWriter,omitempty"`
	CapacityLedger      *capacityledger.Ledger   `json:"capacityLedger,omitempty"`
	PoolChildren        jsontext.Value           `json:"poolChildren,omitempty"`
	CapacityPools       jsontext.Value           `json:"capacityPools,omitempty"`
	CapacityCreates     jsontext.Value           `json:"capacityCreates,omitempty"`
	PoolQuarantines     jsontext.Value           `json:"poolQuarantines,omitempty"`
	WorkerPolicyIDs     jsontext.Value           `json:"workerPolicyIds,omitempty"`
	SourcePolicyIDs     jsontext.Value           `json:"sourcePolicyIds,omitempty"`
	NetBirdManager      jsontext.Value           `json:"netbirdManager,omitempty"`
	SchemaVersion       int                      `json:"schemaVersion"`
	Cell                string                   `json:"cell"`
	OCIRegion           string                   `json:"ociRegion"`
	TenancyID           string                   `json:"tenancyId"`
	ParentCompartmentID string                   `json:"parentCompartmentId"`
	SharedCompartmentID string                   `json:"sharedCompartmentId"`
	Generation          uint64                   `json:"generation"`
	GrantSHA256         string                   `json:"grantSha256"`
	IntentDigest        string                   `json:"intentDigest"`
	OperationID         string                   `json:"operationId"`
	Epoch               uint64                   `json:"epoch"`
	LeaseID             string                   `json:"leaseId,omitempty"`
	ExpiresAt           time.Time                `json:"expiresAt,omitzero"`
	Stage               string                   `json:"stage"`
	BlockedReason       string                   `json:"blockedReason,omitempty"`
	StartedAt           time.Time                `json:"startedAt"`
	UpdatedAt           time.Time                `json:"updatedAt"`
	CompletedAt         time.Time                `json:"completedAt,omitzero"`
	ResourceIDs         map[string]string        `json:"resourceIds"`
	AuxiliaryIDs        map[string]string        `json:"auxiliaryIds,omitempty"`
	PendingCreates      map[string]pendingCreate `json:"pendingCreates,omitempty"`
	ResourceProvenance  map[string]provenance    `json:"resourceProvenance,omitempty"`
}

// Verify authenticates the root-signed wire before reading its protected
// regional record, then checks each owned role through fresh real OCI clients.
func Verify(ctx context.Context, factory *ociclient.Factory, authority Authority, grantWire []byte) (VerifiedBindings, error) {
	observedAt := time.Now()
	if factory == nil || !catalog.IsCell(authority.Cell) || !canonicalDigest(authority.GrantSHA256) || authority.Generation == 0 ||
		!entityid.Valid(authority.InstallationID) || !resourceID(authority.TenancyID, "tenancy", "") ||
		authority.Namespace == "" || authority.Bucket == "" || authority.Prefix == "" || strings.ContainsAny(authority.Prefix, "\\\r\n\x00") || strings.ContainsAny(authority.Namespace+authority.Bucket, "/\\\r\n\x00") ||
		authority.Scope.Domain != "terrascale.foundation.scope" || authority.Scope.Cell != "GRU" || authority.Scope.Role != "foundation" {
		return VerifiedBindings{}, errors.New("foundation binding authority is incomplete or outside its root scope")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != authority.TenancyID {
		return VerifiedBindings{}, errors.New("foundation binding tenancy differs from authenticated OCI identity")
	}
	if digest(grantWire) != authority.GrantSHA256 {
		return VerifiedBindings{}, errors.New("foundation grant differs from root-pinned exact wire")
	}
	envelope, err := trust.DecodeEnvelope(grantWire)
	if err != nil {
		return VerifiedBindings{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, authority.Scope, authority.Roots, time.Now(), authority.Policy)
	if err != nil {
		return VerifiedBindings{}, err
	}
	if err := verifyCurrentGrant(ctx, factory, authority, grantWire); err != nil {
		return VerifiedBindings{}, err
	}
	var approved grant
	if err := json.Unmarshal(payload, &approved, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedBindings{}, fmt.Errorf("foundation grant schema: %w", err)
	}
	if approved.SchemaVersion != 2 || approved.Generation != authority.Generation || approved.InstallationID != authority.InstallationID || approved.TenancyID != tenancy ||
		!resourceID(approved.ParentCompartmentID, "compartment", "") || !resourceID(approved.SharedCompartmentID, "compartment", "") ||
		approved.MonthlyLimitMinor <= 0 || approved.Currency != "USD" && approved.Currency != "BRL" || approved.CleanupOwner == "" || len(approved.CleanupOwner) > 128 ||
		len(approved.Regions) == 0 || len(approved.Regions) > catalog.Len {
		return VerifiedBindings{}, errors.New("foundation grant lacks current schema-2 scope or spend authority")
	}
	var selected intent
	var selectedDigest string
	seen := map[string]bool{}
	for _, raw := range approved.Regions {
		var region intent
		if err := json.Unmarshal(raw, &region, json.RejectUnknownMembers(true)); err != nil {
			return VerifiedBindings{}, fmt.Errorf("foundation region intent schema: %w", err)
		}
		cell, _ := region.Plan["cell"].(string)
		if !catalog.IsCell(cell) || seen[cell] || region.Generation != approved.Generation || region.Plan["region"] != catalog.OCIRegion(cell) ||
			region.Plan["tenancy_id"] != tenancy || region.Plan["parent_compartment_id"] != approved.ParentCompartmentID || region.Plan["shared_compartment_id"] != approved.SharedCompartmentID {
			return VerifiedBindings{}, errors.New("foundation region intent differs from signed scope or repeats a cell")
		}
		if _, ok := region.Plan["resource_ids"].(map[string]any); !ok {
			return VerifiedBindings{}, errors.New("foundation region intent lacks resource roles")
		}
		seen[cell] = true
		if cell == authority.Cell {
			selected = region
			wire, err := json.Marshal(region, json.Deterministic(true))
			if err != nil {
				return VerifiedBindings{}, err
			}
			// Decode optional signed documents before canonicalizing their maps.
			var canonical map[string]any
			if err := json.Unmarshal(wire, &canonical); err != nil {
				return VerifiedBindings{}, err
			}
			wire, err = json.Marshal(canonical, json.Deterministic(true))
			if err != nil {
				return VerifiedBindings{}, err
			}
			selectedDigest = digest(wire)
		}
	}
	if !seen[authority.Cell] {
		return VerifiedBindings{}, errors.New("foundation cell is outside the signed grant")
	}
	requested := map[string]bool{}
	var signed map[string]any
	if err := json.Unmarshal(payload, &signed); err != nil {
		return VerifiedBindings{}, err
	}
	if err := collectReferences(signed, authority.Cell, requested); err != nil {
		return VerifiedBindings{}, err
	}
	if len(approved.InfrastructureSpend) != 0 && string(approved.InfrastructureSpend) != "null" {
		pins := selected.Plan["resource_ids"].(map[string]any)
		for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment"} {
			if pins[key] == nil || pins[key] == "" {
				requested[key] = true
			}
		}
	}
	if len(selected.BootstrapMaterial) != 0 && string(selected.BootstrapMaterial) != "null" {
		pins := selected.Plan["resource_ids"].(map[string]any)
		for _, key := range []string{"control_compartment", "vault", "key"} {
			if pins[key] == nil || pins[key] == "" {
				requested[key] = true
			}
		}
	}
	if len(authority.Keys) != 0 {
		narrowed := map[string]bool{}
		for _, key := range authority.Keys {
			if !requested[key] || narrowed[key] {
				return VerifiedBindings{}, errors.New("requested foundation roles are outside the signed reference set or repeated")
			}
			narrowed[key] = true
		}
		requested = narrowed
	}
	if len(requested) == 0 {
		return VerifiedBindings{}, errors.New("signed grant contains no logical references for this cell")
	}
	current, err := loadRecord(ctx, factory, authority)
	if err != nil {
		return VerifiedBindings{}, err
	}
	if err := validateRecord(current, approved, authority, selectedDigest, selected.Plan, requested); err != nil {
		return VerifiedBindings{}, err
	}
	var financial *capacityledger.Ledger
	if current.CapacityLedger != nil {
		if err := current.CapacityLedger.Validate(); err != nil {
			return VerifiedBindings{}, fmt.Errorf("protected capacity ledger: %w", err)
		}
		financial = new(current.CapacityLedger.Clone())
	}
	compartments := []string{approved.ParentCompartmentID, approved.SharedCompartmentID}
	for key, id := range current.ResourceIDs {
		if strings.HasSuffix(key, "_compartment") {
			compartments = append(compartments, id)
		}
	}
	slices.Sort(compartments)
	compartments = slices.Compact(compartments)
	needed := dependencyClosure(requested)
	current.ResourceIDs = maps.Clone(current.ResourceIDs)
	maps.DeleteFunc(current.ResourceIDs, func(key, _ string) bool { return !needed[key] })
	if err := observe(ctx, factory, selected.Plan, current); err != nil {
		return VerifiedBindings{}, err
	}
	authority.Keys = slices.Clone(authority.Keys)
	authority.Roots = maps.Clone(authority.Roots)
	for key, public := range authority.Roots {
		authority.Roots[key] = ed25519.PublicKey(bytes.Clone(public))
	}
	maps.DeleteFunc(current.ResourceIDs, func(key, _ string) bool { return !requested[key] })
	expires := envelope.ExpiresAt
	if current.Stage == "foundation" && current.ExpiresAt.Before(expires) {
		expires = current.ExpiresAt
	}
	return VerifiedBindings{factory: factory, authority: authority, wire: bytes.Clone(grantWire), expires: expires, ids: current.ResourceIDs,
		capacityLedger: financial, capacityCompartments: compartments, capacityCurrency: approved.Currency,
		capacityChildren: bytes.Clone(current.PoolChildren), observedAt: observedAt}, nil
}

func verifyCurrentGrant(ctx context.Context, factory *ociclient.Factory, authority Authority, expected []byte) error {
	home, err := factory.ForRegion(catalog.OCIRegion("GRU"))
	if err != nil {
		return err
	}
	objects, err := home.ObjectStorage()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	name := strings.TrimSuffix(authority.Prefix, "/") + "/foundation-scope-v1.json"
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(authority.Namespace), BucketName: new(authority.Bucket), ObjectName: new(name)})
	if err != nil {
		return fmt.Errorf("read current protected foundation grant: %w", err)
	}
	if response.Content == nil {
		return errors.New("current foundation grant has no content")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, trust.MaxEnvelopeBytes+1))
	if err != nil || len(wire) > trust.MaxEnvelopeBytes || !bytes.Equal(wire, expected) {
		return errors.New("active foundation grant differs from exact root-pinned wire")
	}
	return nil
}

func loadRecord(ctx context.Context, factory *ociclient.Factory, authority Authority) (record, error) {
	home, err := factory.ForRegion(catalog.OCIRegion("GRU"))
	if err != nil {
		return record{}, err
	}
	objects, err := home.ObjectStorage()
	if err != nil {
		return record{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{
		NamespaceName: new(authority.Namespace), BucketName: new(authority.Bucket), ObjectName: new("orchestrator/regions/v1/" + authority.Cell + ".json")})
	if err != nil {
		return record{}, fmt.Errorf("read protected foundation record: %w", err)
	}
	if response.Content == nil {
		return record{}, errors.New("foundation record has no content")
	}
	defer response.Content.Close()
	if response.ETag == nil || *response.ETag == "" {
		return record{}, errors.New("foundation record has no conditional-write ETag")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Content, recordLimit+1))
	if err != nil || len(wire) > recordLimit {
		return record{}, errors.New("foundation record is unreadable or oversized")
	}
	var current record
	if err := json.Unmarshal(wire, &current, json.RejectUnknownMembers(true)); err != nil {
		return record{}, fmt.Errorf("foundation record schema: %w", err)
	}
	return current, nil
}

func validateRecord(current record, approved grant, authority Authority, intentDigest string, plan map[string]any, requested map[string]bool) error {
	if current.SchemaVersion != 1 || current.Cell != authority.Cell || current.OCIRegion != catalog.OCIRegion(authority.Cell) ||
		current.TenancyID != authority.TenancyID || current.ParentCompartmentID != approved.ParentCompartmentID || current.SharedCompartmentID != approved.SharedCompartmentID ||
		current.Generation != authority.Generation || current.GrantSHA256 != authority.GrantSHA256 || current.IntentDigest != intentDigest ||
		current.OperationID != entityid.Derive("regional-foundation", authority.TenancyID, authority.Cell, fmt.Sprint(authority.Generation)) ||
		current.Epoch == 0 || current.StartedAt.IsZero() || current.UpdatedAt.Before(current.StartedAt) || current.BlockedReason != "" ||
		len(current.ResourceIDs) > 128 || len(current.ResourceProvenance) > 128 || len(current.PendingCreates) > 64 {
		return errors.New("foundation record lacks the current signed operation")
	}
	switch current.Stage {
	case "reconciled":
		if current.LeaseID != "" || !current.ExpiresAt.IsZero() || current.CompletedAt.Before(current.StartedAt) || current.CompletedAt.After(current.UpdatedAt) || len(current.PendingCreates) != 0 {
			return errors.New("foundation record has an invalid reconciled outcome")
		}
	case "foundation":
		if !entityid.Valid(current.LeaseID) || !current.ExpiresAt.After(time.Now()) || !current.ExpiresAt.After(current.UpdatedAt) || !current.CompletedAt.IsZero() {
			return errors.New("foundation record has no current scoped create lease")
		}
	default:
		return errors.New("foundation record is neither active nor reconciled")
	}
	needed := dependencyClosure(requested)
	pins := plan["resource_ids"].(map[string]any)
	for key := range needed {
		if _, pending := current.PendingCreates[key]; pending {
			return fmt.Errorf("foundation %s create is still pending", key)
		}
		id := current.ResourceIDs[key]
		if id == "" {
			return fmt.Errorf("foundation record lacks required %s", key)
		}
		// An exact root-signed dependency needs no new create, but never
		// becomes a resolvable logical reference without birth provenance.
		if !requested[key] && pins[key] == id {
			continue
		}
		proof, ok := current.ResourceProvenance[key]
		birth := proof.Create
		if !ok || proof.ResourceID != id || proof.Generation == 0 || proof.Generation > current.Generation || !canonicalDigest(proof.GrantSHA256) ||
			birth.OperationID != entityid.Derive("regional-foundation", authority.TenancyID, authority.Cell, fmt.Sprint(proof.Generation)) || !canonicalDigest(birth.IntentDigest) ||
			birth.Request.Key != key || !catalog.IsOCIRegion(birth.Request.Region) || !canonicalDigest(birth.Request.RequestDigest) ||
			birth.Request.RetryToken != "" && !canonicalDigest(birth.Request.RetryToken) || birth.FirstAttemptAt.IsZero() || birth.FirstAttemptAt.After(current.UpdatedAt) {
			return fmt.Errorf("foundation %s lacks persisted create provenance", key)
		}
		if proof.Generation == current.Generation && (proof.GrantSHA256 != current.GrantSHA256 || birth.IntentDigest != current.IntentDigest || birth.FirstAttemptAt.Before(current.StartedAt)) {
			return fmt.Errorf("foundation %s create differs from its signed generation", key)
		}
		if !strings.HasSuffix(key, "_compartment") && birth.Request.Region != current.OCIRegion {
			return fmt.Errorf("foundation %s create belongs to another OCI region", key)
		}
	}
	return nil
}

func observe(ctx context.Context, factory *ociclient.Factory, plan map[string]any, current record) error {
	regional, err := factory.ForRegion(current.OCIRegion)
	if err != nil {
		return err
	}
	ids := current.ResourceIDs
	pins := plan["resource_ids"].(map[string]any)
	for key, id := range ids {
		if !referenceKey(key) && key != "vcn" {
			continue
		}
		kind, region := key, current.OCIRegion
		switch key {
		case "control_compartment", "network_compartment", "workload_compartment":
			kind, region = "compartment", ""
		case "network_security_group", "workload_network_security_group":
			kind = "networksecuritygroup"
		}
		if !resourceID(id, kind, region) || pins[key] != nil && pins[key] != "" && pins[key] != id {
			return fmt.Errorf("foundation %s differs from its signed resource role", key)
		}
	}
	iam, err := regional.Identity()
	if err != nil {
		return err
	}
	for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment"} {
		if ids[key] == "" {
			continue
		}
		response, err := iam.GetCompartment(ociclient.RequestContext(ctx), identity.GetCompartmentRequest{CompartmentId: new(ids[key])})
		if err != nil {
			return fmt.Errorf("read foundation %s: %w", key, err)
		}
		if value(response.Id) != ids[key] || value(response.CompartmentId) != current.ParentCompartmentID || response.LifecycleState != identity.CompartmentLifecycleStateActive {
			return fmt.Errorf("foundation %s live parent or lifecycle differs from signed role", key)
		}
	}
	if sameID(ids, "control_compartment", "network_compartment") || sameID(ids, "control_compartment", "workload_compartment") || sameID(ids, "network_compartment", "workload_compartment") ||
		sameID(ids, "network_security_group", "workload_network_security_group") {
		return errors.New("foundation roles share an OCI resource identity")
	}
	network, err := regional.Network()
	if err != nil {
		return err
	}
	if ids["vcn"] != "" {
		vcn, err := network.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(ids["vcn"])})
		if err != nil {
			return fmt.Errorf("read foundation VCN: %w", err)
		}
		networkCIDR, _ := plan["network_cidr"].(string)
		subnetCIDR, _ := plan["subnet_cidr"].(string)
		if _, err := netip.ParsePrefix(networkCIDR); err != nil {
			return errors.New("signed foundation lacks a network CIDR")
		}
		if _, err := netip.ParsePrefix(subnetCIDR); err != nil {
			return errors.New("signed foundation lacks a subnet CIDR")
		}
		if value(vcn.Id) != ids["vcn"] || value(vcn.CompartmentId) != ids["network_compartment"] || value(vcn.CidrBlock) != networkCIDR || vcn.LifecycleState != core.VcnLifecycleStateAvailable {
			return errors.New("foundation VCN differs from signed network role")
		}
	}
	if ids["subnet"] != "" {
		subnetCIDR, _ := plan["subnet_cidr"].(string)
		subnet, err := network.GetSubnet(ociclient.RequestContext(ctx), core.GetSubnetRequest{SubnetId: new(ids["subnet"])})
		if err != nil {
			return fmt.Errorf("read foundation subnet: %w", err)
		}
		if value(subnet.Id) != ids["subnet"] || value(subnet.CompartmentId) != ids["network_compartment"] || value(subnet.VcnId) != ids["vcn"] || value(subnet.CidrBlock) != subnetCIDR ||
			subnet.ProhibitPublicIpOnVnic == nil || !*subnet.ProhibitPublicIpOnVnic || subnet.LifecycleState != core.SubnetLifecycleStateAvailable {
			return errors.New("foundation subnet differs from signed private network role")
		}
	}
	for _, key := range []string{"network_security_group", "workload_network_security_group"} {
		if ids[key] == "" {
			continue
		}
		response, err := network.GetNetworkSecurityGroup(ociclient.RequestContext(ctx), core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: new(ids[key])})
		if err != nil {
			return fmt.Errorf("read foundation %s: %w", key, err)
		}
		if value(response.Id) != ids[key] || value(response.CompartmentId) != ids["network_compartment"] || value(response.VcnId) != ids["vcn"] || response.LifecycleState != core.NetworkSecurityGroupLifecycleStateAvailable {
			return fmt.Errorf("foundation %s differs from signed network role", key)
		}
	}
	if ids["vault"] == "" {
		return nil
	}
	vaults, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(regional.Provider())
	if err != nil {
		return err
	}
	vaults.SetRegion(current.OCIRegion)
	regional.Configure(&vaults.BaseClient, ociclient.ServiceKMS)
	vault, err := vaults.GetVault(ociclient.RequestContext(ctx), keymanagement.GetVaultRequest{VaultId: new(ids["vault"])})
	if err != nil {
		return fmt.Errorf("read foundation vault: %w", err)
	}
	if value(vault.Id) != ids["vault"] || value(vault.CompartmentId) != ids["control_compartment"] || vault.LifecycleState != keymanagement.VaultLifecycleStateActive || vault.VaultType != keymanagement.VaultVaultTypeDefault {
		return errors.New("foundation vault differs from signed control role")
	}
	if ids["key"] == "" {
		return nil
	}
	endpoint, err := url.Parse(value(vault.ManagementEndpoint))
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Port() != "" || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		!strings.HasSuffix(endpoint.Hostname(), ".oraclecloud.com") || !strings.Contains(endpoint.Hostname(), "."+current.OCIRegion+".") {
		return errors.New("foundation vault has an invalid regional KMS endpoint")
	}
	keys, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(regional.Provider(), endpoint.String())
	if err != nil {
		return err
	}
	regional.Configure(&keys.BaseClient, ociclient.ServiceKMS)
	key, err := keys.GetKey(ociclient.RequestContext(ctx), keymanagement.GetKeyRequest{KeyId: new(ids["key"])})
	if err != nil {
		return fmt.Errorf("read foundation key: %w", err)
	}
	if value(key.Id) != ids["key"] || value(key.CompartmentId) != ids["control_compartment"] || value(key.VaultId) != ids["vault"] || key.LifecycleState != keymanagement.KeyLifecycleStateEnabled ||
		key.ProtectionMode != keymanagement.KeyProtectionModeHsm || key.KeyShape == nil || key.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmAes || key.KeyShape.Length == nil || *key.KeyShape.Length != 32 {
		return errors.New("foundation key differs from signed vault/control role")
	}
	return nil
}

func digest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func canonicalDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func resourceID(id, kind, region string) bool {
	parts := strings.Split(id, ".")
	if len(parts) < 5 || len(id) > 512 || parts[0] != "ocid1" || parts[1] != kind || parts[2] != "oc1" ||
		parts[3] != region && !(region == "us-phoenix-1" && parts[3] == "phx") && !(region == "us-ashburn-1" && parts[3] == "iad") {
		return false
	}
	for _, part := range parts[4:] {
		if part == "" {
			return false
		}
		for _, character := range part {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}

func sameID(ids map[string]string, left, right string) bool {
	return ids[left] != "" && ids[left] == ids[right]
}

func dependencyClosure(requested map[string]bool) map[string]bool {
	needed := maps.Clone(requested)
	for key := range requested {
		switch key {
		case "subnet", "network_security_group", "workload_network_security_group":
			needed["network_compartment"], needed["vcn"] = true, true
		case "vault":
			needed["control_compartment"] = true
		case "key":
			needed["control_compartment"], needed["vault"] = true, true
		}
	}
	return needed
}

func collectReferences(value any, cell string, requested map[string]bool) error {
	switch value := value.(type) {
	case string:
		if !strings.HasPrefix(value, "foundation:") {
			return nil
		}
		target, key, err := Parse(value)
		if err != nil {
			return err
		}
		if target == cell {
			requested[key] = true
		}
	case map[string]any:
		for _, child := range value {
			if err := collectReferences(child, cell, requested); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := collectReferences(child, cell, requested); err != nil {
				return err
			}
		}
	}
	return nil
}
