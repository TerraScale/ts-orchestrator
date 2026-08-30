// Port of src/TerraScale.Orchestrator/Contracts/Resources/AdmittedRoles.cs.
package contracts

import (
	"errors"
	"fmt"
	"strconv"
)

// RoleKind mirrors the RoleKind enum.
type RoleKind int

const (
	RoleKindUnspecified            RoleKind = 0
	RoleKindPlatform               RoleKind = 1
	RoleKindAuthentication         RoleKind = 2
	RoleKindCustomerDashboard      RoleKind = 3
	RoleKindTerraBaseMember        RoleKind = 4
	RoleKindOrchestrator           RoleKind = 5
	RoleKindControlNatsServer      RoleKind = 6
	RoleKindProductNatsServer      RoleKind = 7
	RoleKindGrafana                RoleKind = 8
	RoleKindMetricsStore           RoleKind = 9
	RoleKindLoki                   RoleKind = 10
	RoleKindTempo                  RoleKind = 11
	RoleKindAlertmanager           RoleKind = 12
	RoleKindOtlpIngest             RoleKind = 13
	RoleKindSyntheticCheck         RoleKind = 14
	RoleKindRegionalTelemetryAgent RoleKind = 15
	RoleKindVpnCoordinationRelay   RoleKind = 16
	RoleKindRoutePolicyController  RoleKind = 17
	RoleKindCiRunner               RoleKind = 18
)

func (k RoleKind) String() string {
	switch k {
	case RoleKindPlatform:
		return "Platform"
	case RoleKindAuthentication:
		return "Authentication"
	case RoleKindCustomerDashboard:
		return "CustomerDashboard"
	case RoleKindTerraBaseMember:
		return "TerraBaseMember"
	case RoleKindOrchestrator:
		return "Orchestrator"
	case RoleKindControlNatsServer:
		return "ControlNatsServer"
	case RoleKindProductNatsServer:
		return "ProductNatsServer"
	case RoleKindGrafana:
		return "Grafana"
	case RoleKindMetricsStore:
		return "MetricsStore"
	case RoleKindLoki:
		return "Loki"
	case RoleKindTempo:
		return "Tempo"
	case RoleKindAlertmanager:
		return "Alertmanager"
	case RoleKindOtlpIngest:
		return "OtlpIngest"
	case RoleKindSyntheticCheck:
		return "SyntheticCheck"
	case RoleKindRegionalTelemetryAgent:
		return "RegionalTelemetryAgent"
	case RoleKindVpnCoordinationRelay:
		return "VpnCoordinationRelay"
	case RoleKindRoutePolicyController:
		return "RoutePolicyController"
	case RoleKindCiRunner:
		return "CiRunner"
	default:
		return strconv.Itoa(int(k))
	}
}

func roleKindIsDefined(k RoleKind) bool {
	return k >= RoleKindPlatform && k <= RoleKindCiRunner
}

// ImplementationDomain mirrors the ImplementationDomain enum.
type ImplementationDomain int

const (
	ImplementationDomainUnspecified       ImplementationDomain = 0
	ImplementationDomainMetricsStore      ImplementationDomain = 1
	ImplementationDomainRegionalTelemetry ImplementationDomain = 2
	ImplementationDomainVpn               ImplementationDomain = 3
)

func (d ImplementationDomain) String() string {
	switch d {
	case ImplementationDomainMetricsStore:
		return "MetricsStore"
	case ImplementationDomainRegionalTelemetry:
		return "RegionalTelemetry"
	case ImplementationDomainVpn:
		return "Vpn"
	default:
		return strconv.Itoa(int(d))
	}
}

func implementationDomainIsDefined(d ImplementationDomain) bool {
	return d >= ImplementationDomainMetricsStore && d <= ImplementationDomainVpn
}

// ApprovedImplementationCatalogKey names one owner-selected implementation of
// an unresolved (multi-vendor) role.
type ApprovedImplementationCatalogKey struct {
	Domain         ImplementationDomain
	CatalogEntryId ResourceId
}

// NewApprovedImplementationCatalogKey mirrors the constructor; the domain must
// be a defined enum value and the catalog entry must be present.
func NewApprovedImplementationCatalogKey(domain ImplementationDomain, catalogEntryId ResourceId) (ApprovedImplementationCatalogKey, error) {
	if !implementationDomainIsDefined(domain) {
		return ApprovedImplementationCatalogKey{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'domain', actual value %d)", int(domain))
	}

	if catalogEntryId.Value == "" {
		return ApprovedImplementationCatalogKey{}, errors.New("Value cannot be null. (Parameter 'catalogEntryId')")
	}

	return ApprovedImplementationCatalogKey{Domain: domain, CatalogEntryId: catalogEntryId}, nil
}

func (k ApprovedImplementationCatalogKey) String() string {
	return k.Domain.String() + ":" + k.CatalogEntryId.String()
}

// AdmittedRole is the closed v1 role union for INV-017. The C# sealed class
// hierarchy (PlatformRole, MetricsStoreRole, ...) flattens onto one struct
// discriminated by Kind; construct instances only through the New*Role
// constructors so the union stays closed.
type AdmittedRole struct {
	kind RoleKind

	// implementation is set only for MetricsStore, RegionalTelemetryAgent and
	// VpnCoordinationRelay, mirroring the three implementation-carrying C# subclasses.
	implementation ApprovedImplementationCatalogKey
}

// Kind returns the role kind of this admitted role.
func (r AdmittedRole) Kind() RoleKind { return r.kind }

// Projection mirrors the internal AdmittedRole.Projection: the canonical
// per-role string used by the RoleDescriptor projection.
func (r AdmittedRole) Projection() string {
	switch r.kind {
	case RoleKindMetricsStore, RoleKindRegionalTelemetryAgent, RoleKindVpnCoordinationRelay:
		return r.kind.String() + ":" + r.implementation.CatalogEntryId.String()
	default:
		return r.kind.String()
	}
}

func newPlainRole(kind RoleKind) AdmittedRole { return AdmittedRole{kind: kind} }

// NewPlatformRole mirrors PlatformRole.
func NewPlatformRole() AdmittedRole { return newPlainRole(RoleKindPlatform) }

// NewAuthenticationRole mirrors AuthenticationRole.
func NewAuthenticationRole() AdmittedRole { return newPlainRole(RoleKindAuthentication) }

// NewCustomerDashboardRole mirrors CustomerDashboardRole.
func NewCustomerDashboardRole() AdmittedRole { return newPlainRole(RoleKindCustomerDashboard) }

// NewTerraBaseMemberRole mirrors TerraBaseMemberRole.
func NewTerraBaseMemberRole() AdmittedRole { return newPlainRole(RoleKindTerraBaseMember) }

// NewOrchestratorRole mirrors OrchestratorRole.
func NewOrchestratorRole() AdmittedRole { return newPlainRole(RoleKindOrchestrator) }

// NewControlNatsServerRole mirrors ControlNatsServerRole.
func NewControlNatsServerRole() AdmittedRole { return newPlainRole(RoleKindControlNatsServer) }

// NewProductNatsServerRole mirrors ProductNatsServerRole.
func NewProductNatsServerRole() AdmittedRole { return newPlainRole(RoleKindProductNatsServer) }

// NewGrafanaRole mirrors GrafanaRole.
func NewGrafanaRole() AdmittedRole { return newPlainRole(RoleKindGrafana) }

// NewLokiRole mirrors LokiRole.
func NewLokiRole() AdmittedRole { return newPlainRole(RoleKindLoki) }

// NewTempoRole mirrors TempoRole.
func NewTempoRole() AdmittedRole { return newPlainRole(RoleKindTempo) }

// NewAlertmanagerRole mirrors AlertmanagerRole.
func NewAlertmanagerRole() AdmittedRole { return newPlainRole(RoleKindAlertmanager) }

// NewOtlpIngestRole mirrors OtlpIngestRole.
func NewOtlpIngestRole() AdmittedRole { return newPlainRole(RoleKindOtlpIngest) }

// NewSyntheticCheckRole mirrors SyntheticCheckRole.
func NewSyntheticCheckRole() AdmittedRole { return newPlainRole(RoleKindSyntheticCheck) }

// NewRoutePolicyControllerRole mirrors RoutePolicyControllerRole.
func NewRoutePolicyControllerRole() AdmittedRole { return newPlainRole(RoleKindRoutePolicyController) }

// NewCiRunnerRole mirrors CiRunnerRole.
func NewCiRunnerRole() AdmittedRole { return newPlainRole(RoleKindCiRunner) }

func newImplementationRole(
	kind RoleKind,
	implementation ApprovedImplementationCatalogKey,
	expected ImplementationDomain,
	domainMessage string,
) (AdmittedRole, error) {
	if implementation.CatalogEntryId.Value == "" || implementation.Domain == ImplementationDomainUnspecified {
		return AdmittedRole{}, errors.New("Value cannot be null. (Parameter 'implementation')")
	}

	if implementation.Domain != expected {
		return AdmittedRole{}, errors.New(domainMessage + " (Parameter 'implementation')")
	}

	return AdmittedRole{kind: kind, implementation: implementation}, nil
}

// NewMetricsStoreRole mirrors MetricsStoreRole.
func NewMetricsStoreRole(implementation ApprovedImplementationCatalogKey) (AdmittedRole, error) {
	return newImplementationRole(RoleKindMetricsStore, implementation,
		ImplementationDomainMetricsStore, "Implementation must belong to MetricsStore.")
}

// NewRegionalTelemetryAgentRole mirrors RegionalTelemetryAgentRole.
func NewRegionalTelemetryAgentRole(implementation ApprovedImplementationCatalogKey) (AdmittedRole, error) {
	return newImplementationRole(RoleKindRegionalTelemetryAgent, implementation,
		ImplementationDomainRegionalTelemetry, "A regional telemetry implementation is required.")
}

// NewVpnCoordinationRelayRole mirrors VpnCoordinationRelayRole.
func NewVpnCoordinationRelayRole(implementation ApprovedImplementationCatalogKey) (AdmittedRole, error) {
	return newImplementationRole(RoleKindVpnCoordinationRelay, implementation,
		ImplementationDomainVpn, "A VPN implementation is required.")
}
