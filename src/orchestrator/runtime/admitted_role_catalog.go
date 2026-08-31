// Package runtime defines workload admission and host execution plans.
package runtime

import (
	"fmt"

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
	// Retained roles keep their v1 persisted values. New roles use values after
	// the retired v1 range so old checkpoints cannot acquire a new meaning.
	AdmittedRoleDashboard       AdmittedRole = 0
	AdmittedRoleDatabaseAPI     AdmittedRole = 17
	AdmittedRoleTerraBaseMember AdmittedRole = 1
	AdmittedRoleNats            AdmittedRole = 3
	AdmittedRoleAutoscaler      AdmittedRole = 2
	AdmittedRoleJournalWriter   AdmittedRole = 16
)

func (r AdmittedRole) defined() bool {
	switch r {
	case AdmittedRoleDashboard, AdmittedRoleDatabaseAPI, AdmittedRoleTerraBaseMember,
		AdmittedRoleNats, AdmittedRoleAutoscaler, AdmittedRoleJournalWriter:
		return true
	default:
		return false
	}
}

func (r AdmittedRole) String() string {
	switch r {
	case AdmittedRoleDashboard:
		return "Dashboard"
	case AdmittedRoleDatabaseAPI:
		return "DatabaseAPI"
	case AdmittedRoleTerraBaseMember:
		return "TerraBaseMember"
	case AdmittedRoleNats:
		return "Nats"
	case AdmittedRoleAutoscaler:
		return "Autoscaler"
	case AdmittedRoleJournalWriter:
		return "JournalWriter"
	default:
		return fmt.Sprintf("AdmittedRole(%d)", int(r))
	}
}

// AllAdmittedRoles lists every role in declared order.
var AllAdmittedRoles = []AdmittedRole{
	AdmittedRoleDashboard,
	AdmittedRoleDatabaseAPI,
	AdmittedRoleTerraBaseMember,
	AdmittedRoleNats,
	AdmittedRoleAutoscaler,
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
)

func (c RoleCapability) String() string {
	names := [...]string{
		"PublicHttp", "ProductDatabase", "ControlAuthority", "ControlMessaging",
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

// AdmittedRoleCatalog exposes the closed descriptor catalog.
var AdmittedRoleCatalog admittedRoleCatalog

type admittedRoleCatalog struct{}

var admittedRoleDescriptors = map[AdmittedRole]AdmittedRoleDescriptor{}

// All returns every descriptor in declared catalog order.
func (admittedRoleCatalog) All() []AdmittedRoleDescriptor {
	all := make([]AdmittedRoleDescriptor, 0, len(AllAdmittedRoles))
	for _, role := range AllAdmittedRoles {
		all = append(all, admittedRoleDescriptors[role])
	}
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
	oci := func(role AdmittedRole, artifactKey string, minimumReplicas int, capabilities ...RoleCapability) AdmittedRoleDescriptor {
		return AdmittedRoleDescriptor{
			Role:            role,
			ArtifactKey:     artifactKey,
			DefaultDriver:   RuntimeDriverOciContainer,
			AllowedDrivers:  []RuntimeDriver{RuntimeDriverOciContainer},
			Capabilities:    capabilities,
			OnePerHost:      false,
			MinimumReplicas: minimumReplicas,
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
		oci(AdmittedRoleDashboard, "terrascale-dashboard", 1, RoleCapabilityPublicHttp),
		oci(AdmittedRoleDatabaseAPI, "terrascale-database", 2, RoleCapabilityPublicHttp),
		both(AdmittedRoleTerraBaseMember, "terrabase-server", RuntimeDriverNativeSystemd, true, 2, RoleCapabilityProductDatabase),
		native(AdmittedRoleNats, "nats-server", true, 3, RoleCapabilityControlMessaging),
		native(AdmittedRoleAutoscaler, "terrascale-orchestrator", true, 3, RoleCapabilityControlAuthority),
		native(AdmittedRoleJournalWriter, "terrascale-orchestrator", true, 3, RoleCapabilityControlMessaging),
	} {
		admittedRoleDescriptors[descriptor.Role] = descriptor
	}
}
