// Package runtime ports TerraScale.Orchestrator.Runtime (the Runtime folder of
// src/TerraScale.Orchestrator, including Runtime/Mcp).
//
// This file ports Runtime/AdmittedRoleCatalog.cs.
package runtime

import (
	"fmt"
	"slices"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// InvalidOperationError mirrors System.InvalidOperationException.
type InvalidOperationError struct {
	Message string
}

func (e *InvalidOperationError) Error() string { return e.Message }

// InvalidDataError mirrors System.IO.InvalidDataException.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

// AdmittedRole is the closed workload role vocabulary.
type AdmittedRole int

const (
	AdmittedRoleCustomerDashboard AdmittedRole = iota
	AdmittedRoleTerraBaseMember
	AdmittedRoleOrchestrator
	AdmittedRoleControlNatsServer
	AdmittedRoleProductNatsServer
	AdmittedRoleGrafana
	AdmittedRoleMetricsStore
	AdmittedRoleLoki
	AdmittedRoleTempo
	AdmittedRoleAlertmanager
	AdmittedRoleOtlpIngest
	AdmittedRoleSyntheticCheck
	AdmittedRoleRegionalTelemetryAgent
	AdmittedRoleVpnCoordinationRelay
	AdmittedRoleRoutePolicyController
	AdmittedRoleCiRunner
	AdmittedRoleJournalWriter
)

func (r AdmittedRole) defined() bool {
	return r >= AdmittedRoleCustomerDashboard && r <= AdmittedRoleJournalWriter
}

func (r AdmittedRole) String() string {
	names := [...]string{
		"CustomerDashboard", "TerraBaseMember", "Orchestrator", "ControlNatsServer",
		"ProductNatsServer", "Grafana", "MetricsStore", "Loki", "Tempo", "Alertmanager",
		"OtlpIngest", "SyntheticCheck", "RegionalTelemetryAgent", "VpnCoordinationRelay",
		"RoutePolicyController", "CiRunner", "JournalWriter",
	}
	if r >= 0 && int(r) < len(names) {
		return names[r]
	}
	return fmt.Sprintf("AdmittedRole(%d)", int(r))
}

// AllAdmittedRoles lists every role in declared order.
var AllAdmittedRoles = []AdmittedRole{
	AdmittedRoleCustomerDashboard, AdmittedRoleTerraBaseMember, AdmittedRoleOrchestrator,
	AdmittedRoleControlNatsServer, AdmittedRoleProductNatsServer, AdmittedRoleGrafana,
	AdmittedRoleMetricsStore, AdmittedRoleLoki, AdmittedRoleTempo, AdmittedRoleAlertmanager,
	AdmittedRoleOtlpIngest, AdmittedRoleSyntheticCheck, AdmittedRoleRegionalTelemetryAgent,
	AdmittedRoleVpnCoordinationRelay, AdmittedRoleRoutePolicyController, AdmittedRoleCiRunner,
	AdmittedRoleJournalWriter,
}

// RuntimeDriver is the closed runtime driver vocabulary.
type RuntimeDriver int

const (
	RuntimeDriverNativeSystemd RuntimeDriver = iota
	RuntimeDriverOciContainer
)

func (d RuntimeDriver) defined() bool {
	return d == RuntimeDriverNativeSystemd || d == RuntimeDriverOciContainer
}

func (d RuntimeDriver) String() string {
	switch d {
	case RuntimeDriverNativeSystemd:
		return "NativeSystemd"
	case RuntimeDriverOciContainer:
		return "OciContainer"
	default:
		return fmt.Sprintf("RuntimeDriver(%d)", int(d))
	}
}

// RoleCapability is the closed capability vocabulary.
type RoleCapability int

const (
	RoleCapabilityPublicHttp RoleCapability = iota
	RoleCapabilityProductDatabase
	RoleCapabilityControlAuthority
	RoleCapabilityControlMessaging
	RoleCapabilityProductMessaging
	RoleCapabilityTelemetryQuery
	RoleCapabilityTelemetryIngest
	RoleCapabilityAlerting
	RoleCapabilitySyntheticProbe
	RoleCapabilityNetworkCoordination
	RoleCapabilityRoutePolicy
	RoleCapabilityIsolatedBuild
)

func (c RoleCapability) String() string {
	names := [...]string{
		"PublicHttp", "ProductDatabase", "ControlAuthority", "ControlMessaging",
		"ProductMessaging", "TelemetryQuery", "TelemetryIngest", "Alerting",
		"SyntheticProbe", "NetworkCoordination", "RoutePolicy", "IsolatedBuild",
	}
	if c >= 0 && int(c) < len(names) {
		return names[c]
	}
	return fmt.Sprintf("RoleCapability(%d)", int(c))
}

// AdmittedRoleDescriptor is the catalog entry of one workload role.
type AdmittedRoleDescriptor struct {
	Role            AdmittedRole
	ArtifactKey     string
	DefaultDriver   RuntimeDriver
	AllowedDrivers  []RuntimeDriver
	Capabilities    []RoleCapability
	OnePerHost      bool
	MinimumReplicas int
}

// AdmittedRoleCatalog ports the static AdmittedRoleCatalog class; call it as
// runtime.AdmittedRoleCatalog.Get(role) to mirror the C# call site.
var AdmittedRoleCatalog admittedRoleCatalog

type admittedRoleCatalog struct{}

var admittedRoleDescriptors = map[AdmittedRole]AdmittedRoleDescriptor{}

// All returns every descriptor ordered by role.
func (admittedRoleCatalog) All() []AdmittedRoleDescriptor {
	all := make([]AdmittedRoleDescriptor, 0, len(admittedRoleDescriptors))
	for _, descriptor := range admittedRoleDescriptors {
		all = append(all, descriptor)
	}
	slices.SortFunc(all, func(left, right AdmittedRoleDescriptor) int {
		return int(left.Role) - int(right.Role)
	})
	return all
}

// Get returns the descriptor of one admitted role.
func (admittedRoleCatalog) Get(role AdmittedRole) (AdmittedRoleDescriptor, error) {
	if descriptor, present := admittedRoleDescriptors[role]; present {
		return descriptor, nil
	}
	return AdmittedRoleDescriptor{}, &errs.ArgumentOutOfRangeError{
		Param:   "role",
		Message: "The workload role is not admitted.",
	}
}

// Admit returns the descriptor when the driver is admitted for the role.
func (c admittedRoleCatalog) Admit(role AdmittedRole, driver RuntimeDriver) (AdmittedRoleDescriptor, error) {
	descriptor, err := c.Get(role)
	if err != nil {
		return AdmittedRoleDescriptor{}, err
	}
	admitted := false
	for _, allowed := range descriptor.AllowedDrivers {
		if allowed == driver {
			admitted = true
			break
		}
	}
	if !admitted {
		return AdmittedRoleDescriptor{}, &InvalidOperationError{
			Message: fmt.Sprintf("%s is not admitted on the %s runtime.", role, driver),
		}
	}
	return descriptor, nil
}

func init() {
	native := func(role AdmittedRole, artifactKey string, onePerHost bool, minimumReplicas int, capabilities ...RoleCapability) AdmittedRoleDescriptor {
		return AdmittedRoleDescriptor{
			Role:            role,
			ArtifactKey:     artifactKey,
			DefaultDriver:   RuntimeDriverNativeSystemd,
			AllowedDrivers:  []RuntimeDriver{RuntimeDriverNativeSystemd},
			Capabilities:    capabilities,
			OnePerHost:      onePerHost,
			MinimumReplicas: minimumReplicas,
		}
	}
	oci := func(role AdmittedRole, artifactKey string, capabilities ...RoleCapability) AdmittedRoleDescriptor {
		return AdmittedRoleDescriptor{
			Role:            role,
			ArtifactKey:     artifactKey,
			DefaultDriver:   RuntimeDriverOciContainer,
			AllowedDrivers:  []RuntimeDriver{RuntimeDriverOciContainer},
			Capabilities:    capabilities,
			OnePerHost:      false,
			MinimumReplicas: 1,
		}
	}
	both := func(role AdmittedRole, artifactKey string, defaultDriver RuntimeDriver, onePerHost bool, minimumReplicas int, capabilities ...RoleCapability) AdmittedRoleDescriptor {
		return AdmittedRoleDescriptor{
			Role:            role,
			ArtifactKey:     artifactKey,
			DefaultDriver:   defaultDriver,
			AllowedDrivers:  []RuntimeDriver{RuntimeDriverNativeSystemd, RuntimeDriverOciContainer},
			Capabilities:    capabilities,
			OnePerHost:      onePerHost,
			MinimumReplicas: minimumReplicas,
		}
	}
	for _, descriptor := range []AdmittedRoleDescriptor{
		oci(AdmittedRoleCustomerDashboard, "terrascale-dashboard", RoleCapabilityPublicHttp),
		both(AdmittedRoleTerraBaseMember, "terrabase-server", RuntimeDriverNativeSystemd, true, 3, RoleCapabilityProductDatabase),
		native(AdmittedRoleOrchestrator, "terrascale-orchestrator", true, 3, RoleCapabilityControlAuthority),
		native(AdmittedRoleControlNatsServer, "nats-server-control", true, 3, RoleCapabilityControlMessaging),
		native(AdmittedRoleProductNatsServer, "nats-server-product", true, 3, RoleCapabilityProductMessaging),
		oci(AdmittedRoleGrafana, "grafana", RoleCapabilityTelemetryQuery),
		oci(AdmittedRoleMetricsStore, "victoriametrics", RoleCapabilityTelemetryQuery),
		oci(AdmittedRoleLoki, "loki", RoleCapabilityTelemetryQuery),
		oci(AdmittedRoleTempo, "tempo", RoleCapabilityTelemetryQuery),
		oci(AdmittedRoleAlertmanager, "alertmanager", RoleCapabilityAlerting),
		oci(AdmittedRoleOtlpIngest, "alloy-gru", RoleCapabilityTelemetryIngest),
		oci(AdmittedRoleSyntheticCheck, "terrascale-synthetic-check", RoleCapabilitySyntheticProbe),
		oci(AdmittedRoleRegionalTelemetryAgent, "alloy-regional", RoleCapabilityTelemetryIngest),
		oci(AdmittedRoleVpnCoordinationRelay, "netbird-relay", RoleCapabilityNetworkCoordination),
		native(AdmittedRoleRoutePolicyController, "terrascale-route-policy", false, 1, RoleCapabilityRoutePolicy),
		oci(AdmittedRoleCiRunner, "terrascale-ci-runner", RoleCapabilityIsolatedBuild),
		native(AdmittedRoleJournalWriter, "terrascale-orchestrator", true, 3, RoleCapabilityControlMessaging),
	} {
		admittedRoleDescriptors[descriptor.Role] = descriptor
	}
}
