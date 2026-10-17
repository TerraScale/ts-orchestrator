package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const NetBirdAccountJournalPurpose = "netbird-account-journal-v1"

// NetBirdJournalAllocation names an approved logical birth, before native IDs exist.
type NetBirdJournalAllocation struct {
	SlotID        string `json:"slotId"`
	OperationID   string `json:"operationId"`
	ProfileSHA256 string `json:"profileSha256"`
	RecipeSHA256  string `json:"recipeSha256"`
}

// NetBirdJournalUnderlayRecipe binds only the fixed private GRU journal route.
// Its logical keys resolve through protected native births and fresh SDK reads.
type NetBirdJournalUnderlayRecipe struct {
	ManagerVCNKey        string `json:"managerVcnKey"`
	ManagerSubnetKey     string `json:"managerSubnetKey"`
	ManagerRouteTableKey string `json:"managerRouteTableKey"`
	ManagerGatewayKey    string `json:"managerGatewayKey"`
	ManagerSecurityKey   string `json:"managerSecurityKey"`
	ManagerNSGKey        string `json:"managerNsgKey"`
	WriterVCNKey         string `json:"writerVcnKey"`
	WriterSubnetKey      string `json:"writerSubnetKey"`
	WriterRouteTableKey  string `json:"writerRouteTableKey"`
	WriterGatewayKey     string `json:"writerGatewayKey"`
	WriterSecurityKey    string `json:"writerSecurityKey"`
	WriterNSGKey         string `json:"writerNsgKey"`
	ManagerNetworkCIDR   string `json:"managerNetworkCidr"`
	WriterNetworkCIDR    string `json:"writerNetworkCidr"`
	WriterSubnetCIDR     string `json:"writerSubnetCidr"`
	ManagerPrivateIP     string `json:"managerPrivateIp"`
	WriterPrivateIP      string `json:"writerPrivateIp"`
	Protocol             string `json:"protocol"`
	Port                 int    `json:"port"`
}

func (recipe NetBirdJournalUnderlayRecipe) Validate() error {
	if recipe.ManagerVCNKey != "netbird_manager_vcn" || recipe.ManagerSubnetKey != "netbird_manager_subnet" ||
		recipe.ManagerRouteTableKey != "netbird_manager_route" || recipe.ManagerGatewayKey != "netbird_manager_local_peering_gateway" ||
		recipe.ManagerSecurityKey != "netbird_manager_security_list" || recipe.ManagerNSGKey != "netbird_manager_nsg" ||
		recipe.WriterVCNKey != "vcn" || recipe.WriterSubnetKey != "subnet" || recipe.WriterRouteTableKey != "route_table" ||
		recipe.WriterGatewayKey != "netbird_writer_local_peering_gateway" || recipe.WriterSecurityKey != "security_list" || recipe.WriterNSGKey != "network_security_group" ||
		recipe.Protocol != "6" || recipe.Port != 443 {
		return errors.New("NetBird journal underlay differs from its fixed logical private route")
	}
	manager, managerErr := netip.ParsePrefix(recipe.ManagerNetworkCIDR)
	writer, writerErr := netip.ParsePrefix(recipe.WriterNetworkCIDR)
	subnet, subnetErr := netip.ParsePrefix(recipe.WriterSubnetCIDR)
	canonical := func(prefix netip.Prefix, value string) bool {
		return prefix.IsValid() && prefix.Addr().Is4() && prefix.Addr().IsPrivate() && prefix.Masked().String() == value
	}
	if managerErr != nil || writerErr != nil || subnetErr != nil || !canonical(manager, recipe.ManagerNetworkCIDR) ||
		!canonical(writer, recipe.WriterNetworkCIDR) || !canonical(subnet, recipe.WriterSubnetCIDR) ||
		manager.Bits() != 24 || manager.Overlaps(writer) || subnet.Bits() < writer.Bits() || !writer.Contains(subnet.Addr()) {
		return errors.New("NetBird journal underlay requires separate canonical private networks")
	}
	usable := func(value string, network netip.Prefix) bool {
		address, err := netip.ParseAddr(value)
		return err == nil && address.Is4() && address.IsPrivate() && address.String() == value && network.Contains(address) &&
			address != network.Addr() && address != network.Addr().Next() && network.Contains(address.Next())
	}
	if !usable(recipe.ManagerPrivateIP, manager) || !usable(recipe.WriterPrivateIP, subnet) {
		return errors.New("NetBird journal endpoints differ from their signed private networks")
	}
	return nil
}

// NetBirdJournalPurpose is public signed intent, never a verified capability.
// It grants no OCI, NATS, native identity, listener or journal mutation authority.
type NetBirdJournalPurpose struct {
	Purpose          string                       `json:"purpose"`
	InstallationID   string                       `json:"installationId"`
	DeploymentID     string                       `json:"deploymentId"`
	ClusterID        string                       `json:"clusterId"`
	Environment      string                       `json:"environment"`
	Cell             string                       `json:"cell"`
	SourcePlanSHA256 string                       `json:"sourcePlanSha256"`
	SourceGeneration uint64                       `json:"sourceGeneration"`
	Manager          NetBirdJournalAllocation     `json:"manager"`
	Writer           NetBirdJournalAllocation     `json:"writer"`
	Storage          StorageDomain                `json:"storage"`
	Object           string                       `json:"object"`
	Actions          []string                     `json:"actions"`
	Underlay         NetBirdJournalUnderlayRecipe `json:"underlay"`
	ExpiresAt        time.Time                    `json:"expiresAt"`
}

func (purpose NetBirdJournalPurpose) Validate() error {
	digest := func(value string) bool {
		wire, err := hex.DecodeString(value)
		return err == nil && len(wire) == sha256.Size && hex.EncodeToString(wire) == value
	}
	if purpose.Purpose != NetBirdAccountJournalPurpose || !entityid.Valid(purpose.InstallationID) || !entityid.Valid(purpose.DeploymentID) ||
		!entityid.Valid(purpose.ClusterID) || purpose.Environment != "production" || purpose.Cell != "GRU" || !digest(purpose.SourcePlanSHA256) ||
		purpose.SourceGeneration == 0 || purpose.Storage.Validate() != nil || purpose.Storage.HeadBucket != "gru-1-head" ||
		purpose.Object != "orchestrator/regions/v1/GRU.json" || !slices.Equal(purpose.Actions, []string{"reserve", "complete"}) || purpose.ExpiresAt.IsZero() {
		return errors.New("NetBird journal purpose lacks its exact signed source, object, actions or finite cap")
	}
	for _, allocation := range []NetBirdJournalAllocation{purpose.Manager, purpose.Writer} {
		if !entityid.Valid(allocation.SlotID) || !entityid.Valid(allocation.OperationID) || !digest(allocation.ProfileSHA256) || !digest(allocation.RecipeSHA256) {
			return errors.New("NetBird journal purpose lacks its exact logical allocations")
		}
	}
	managerSlot := entityid.Derive("foundation-host-slot", purpose.InstallationID, "GRU", "netbird-manager", "netbird-manager")
	writerSlot := entityid.Derive("foundation-host-slot", purpose.InstallationID, "GRU", "controller", "controller-a")
	if purpose.Manager.SlotID != managerSlot || purpose.Writer.SlotID != writerSlot ||
		purpose.Manager.OperationID != entityid.Derive("foundation-host-operation", purpose.InstallationID, managerSlot) ||
		purpose.Writer.OperationID != entityid.Derive("foundation-host-operation", purpose.InstallationID, writerSlot) {
		return errors.New("NetBird journal purpose does not name the original manager and GRU writer allocations")
	}
	return purpose.Underlay.Validate()
}

func (purpose NetBirdJournalPurpose) Digest() (string, error) {
	if err := purpose.Validate(); err != nil {
		return "", err
	}
	wire, err := json.Marshal(purpose, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

func (purpose NetBirdJournalPurpose) Clone() NetBirdJournalPurpose {
	purpose.Actions = slices.Clone(purpose.Actions)
	return purpose
}

// VerifiedNetBirdJournalPurpose proves signed intent only. Native births,
// underlay readiness, issuer custody and each journal effect need their own proofs.
type VerifiedNetBirdJournalPurpose struct {
	original  context.Context
	enclosing []context.Context
	startup   VerifiedStartupTemplate
	purpose   NetBirdJournalPurpose
	digest    string
	expires   time.Time
}

func (proof VerifiedNetBirdJournalPurpose) IsVerified() bool {
	return proof.original != nil && proof.startup.IsVerified() && proof.digest != "" && !proof.expires.IsZero()
}
func (proof VerifiedNetBirdJournalPurpose) Purpose() NetBirdJournalPurpose {
	return proof.purpose.Clone()
}
func (proof VerifiedNetBirdJournalPurpose) Digest() string      { return proof.digest }
func (proof VerifiedNetBirdJournalPurpose) GrantDigest() string { return proof.startup.GrantDigest() }
func (proof VerifiedNetBirdJournalPurpose) TemplateDigest() string {
	return proof.startup.TemplateDigest()
}
func (proof VerifiedNetBirdJournalPurpose) ExpiresAt() time.Time { return proof.expires }

func (startup VerifiedStartupTemplate) NetBirdJournalPurpose(ctx context.Context) (VerifiedNetBirdJournalPurpose, error) {
	return startup.NetBirdJournalPurposeForOperation(ctx, ctx)
}

// NetBirdJournalPurposeForOperation separates acquisition waits from the genuine
// original lifecycle; a canceled operation child cannot become retained custody.
func (startup VerifiedStartupTemplate) NetBirdJournalPurposeForOperation(ctx, original context.Context) (VerifiedNetBirdJournalPurpose, error) {
	if ctx == nil || original == nil || original.Err() != nil || !startup.IsVerified() {
		return VerifiedNetBirdJournalPurpose{}, ErrManifestInvalid
	}
	expires := startup.ExpiresAt()
	if deadline, ok := original.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	stop := context.AfterFunc(original, cancel)
	defer stop()
	purpose, err := startup.currentNetBirdJournalPurpose(ctx)
	if err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	if purpose.ExpiresAt.Before(expires) {
		expires = purpose.ExpiresAt
	}
	digest, err := purpose.Digest()
	if err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	proof := VerifiedNetBirdJournalPurpose{original: original, startup: startup, purpose: purpose.Clone(), digest: digest, expires: expires}
	if err := proof.Revalidate(ctx); err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	return proof, nil
}

func (proof VerifiedNetBirdJournalPurpose) Revalidate(ctx context.Context) error {
	if ctx == nil || !proof.IsVerified() || proof.originalError() != nil || !time.Now().Before(proof.expires) {
		return ErrManifestInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, proof.expires)
	defer cancel()
	stop := context.AfterFunc(proof.original, cancel)
	defer stop()
	for _, original := range proof.enclosing {
		stop := context.AfterFunc(original, cancel)
		defer stop()
	}
	purpose, err := proof.startup.currentNetBirdJournalPurpose(ctx)
	if err != nil {
		return err
	}
	digest, err := purpose.Digest()
	if err != nil || digest != proof.digest {
		return ErrManifestInvalid
	}
	if err := proof.originalError(); err != nil {
		return err
	}
	return ociclient.LimitAdmission(ctx, proof.expires)
}

func (proof VerifiedNetBirdJournalPurpose) originalError() error {
	if proof.original == nil {
		return ErrManifestInvalid
	}
	if err := proof.original.Err(); err != nil {
		return err
	}
	for _, original := range proof.enclosing {
		if err := original.Err(); err != nil {
			return err
		}
	}
	return nil
}

// Limit preserves genuine provenance while carrying a shorter enclosing cap.
func (proof VerifiedNetBirdJournalPurpose) Limit(ctx context.Context, deadline time.Time) (VerifiedNetBirdJournalPurpose, error) {
	if deadline.IsZero() || !proof.IsVerified() {
		return VerifiedNetBirdJournalPurpose{}, ErrManifestInvalid
	}
	if deadline.Before(proof.expires) {
		proof.expires = deadline
	}
	if err := proof.Revalidate(ctx); err != nil {
		return VerifiedNetBirdJournalPurpose{}, err
	}
	return proof, nil
}

// LimitForOperation also retains an enclosing original lifecycle, never a
// temporary read context, without dropping the purpose's existing cancellation.
func (proof VerifiedNetBirdJournalPurpose) LimitForOperation(ctx, original context.Context, deadline time.Time) (VerifiedNetBirdJournalPurpose, error) {
	if ctx == nil || original == nil || original.Err() != nil || deadline.IsZero() || !proof.IsVerified() {
		return VerifiedNetBirdJournalPurpose{}, ErrManifestInvalid
	}
	if enclosing, ok := original.Deadline(); ok && enclosing.Before(deadline) {
		deadline = enclosing
	}
	proof.enclosing = append(slices.Clone(proof.enclosing), original)
	return proof.Limit(ctx, deadline)
}

// MatchesStartup binds issuance to the genuine original writer's installed
// source; sharing a cell or signer is insufficient.
func (proof VerifiedNetBirdJournalPurpose) MatchesStartup(ctx context.Context, authority DerivedStartupAuthority) error {
	if ctx == nil || !proof.IsVerified() || !authority.IsVerified() || authority.TemplateDigest() != proof.TemplateDigest() ||
		!bytes.Equal(authority.GrantWire(), proof.startup.GrantWire()) || authority.Manifest().Slot != "controller-a" ||
		authority.Manifest().Cell != "GRU" || authority.StorageDomain() != proof.purpose.Storage {
		return ErrManifestInvalid
	}
	expires := proof.expires
	if authority.ExpiresAt().Before(expires) {
		expires = authority.ExpiresAt()
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	stop := context.AfterFunc(proof.original, cancel)
	defer stop()
	for _, original := range proof.enclosing {
		stop := context.AfterFunc(original, cancel)
		defer stop()
	}
	if err := proof.Revalidate(ctx); err != nil {
		return err
	}
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	return proof.Revalidate(ctx)
}

func (startup VerifiedStartupTemplate) currentNetBirdJournalPurpose(ctx context.Context) (NetBirdJournalPurpose, error) {
	envelope, err := trust.DecodeEnvelope(startup.grantWire)
	if err != nil {
		return NetBirdJournalPurpose{}, err
	}
	// Project the already verified retained bytes to bound live checks by their purpose.
	var grant struct {
		InstallationID      string `json:"installationId"`
		Generation          uint64 `json:"generation"`
		InfrastructureSpend struct {
			Bootstrap struct {
				Slots []struct {
					SlotID        string `json:"slotId"`
					Cell          string `json:"cell"`
					Role          string `json:"role"`
					Slot          string `json:"slot"`
					ProfileSHA256 string `json:"profileSha256"`
					RecipeSHA256  string `json:"recipeSha256"`
				} `json:"slots"`
			} `json:"bootstrap"`
		} `json:"infrastructureSpend"`
		Regions []struct {
			Plan struct {
				Cell string `json:"cell"`
			} `json:"plan"`
			NetBirdManager *struct {
				JournalPurpose jsontext.Value `json:"journalPurpose"`
			} `json:"netbirdManager"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(envelope.Payload, &grant); err != nil {
		return NetBirdJournalPurpose{}, err
	}
	var purpose NetBirdJournalPurpose
	found := false
	for _, regional := range grant.Regions {
		if regional.Plan.Cell != "GRU" {
			if regional.NetBirdManager != nil {
				return NetBirdJournalPurpose{}, ErrManifestInvalid
			}
			continue
		}
		if found || regional.NetBirdManager == nil {
			return NetBirdJournalPurpose{}, ErrManifestInvalid
		}
		if err := json.Unmarshal(regional.NetBirdManager.JournalPurpose, &purpose, json.RejectUnknownMembers(true)); err != nil {
			return NetBirdJournalPurpose{}, err
		}
		found = true
	}
	identity := startup.startupIdentity()
	if !found || purpose.Validate() != nil || identity.Cell != "GRU" || purpose.InstallationID != startup.InstallationID() ||
		purpose.InstallationID != grant.InstallationID || purpose.DeploymentID != identity.DeploymentID || purpose.ClusterID != identity.ClusterID ||
		purpose.Environment != identity.Environment || purpose.SourcePlanSHA256 != startup.PlanDigest() || purpose.SourceGeneration != grant.Generation ||
		purpose.SourceGeneration != startup.Generation() || purpose.Storage != identity.StorageDomain || purpose.ExpiresAt.After(envelope.ExpiresAt) ||
		!time.Now().Before(purpose.ExpiresAt) {
		return NetBirdJournalPurpose{}, ErrManifestInvalid
	}
	for index, allocation := range []NetBirdJournalAllocation{purpose.Manager, purpose.Writer} {
		role, name := "netbird-manager", "netbird-manager"
		if index == 1 {
			role, name = "controller", "controller-a"
		}
		matches := 0
		for _, slot := range grant.InfrastructureSpend.Bootstrap.Slots {
			if slot.SlotID == allocation.SlotID {
				if slot.Cell != "GRU" || slot.Role != role || slot.Slot != name || slot.ProfileSHA256 != allocation.ProfileSHA256 || slot.RecipeSHA256 != allocation.RecipeSHA256 {
					return NetBirdJournalPurpose{}, ErrManifestInvalid
				}
				matches++
			}
		}
		if matches != 1 {
			return NetBirdJournalPurpose{}, ErrManifestInvalid
		}
	}
	ctx, cancel := context.WithDeadline(ctx, purpose.ExpiresAt)
	defer cancel()
	if err := startup.VerifyCurrentContext(ctx, time.Now().UTC()); err != nil {
		return NetBirdJournalPurpose{}, err
	}
	if err := ctx.Err(); err != nil {
		return NetBirdJournalPurpose{}, err
	}
	return purpose.Clone(), nil
}
