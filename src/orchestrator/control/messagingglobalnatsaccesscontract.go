// Port of src/TerraScale.Orchestrator/Messaging/GlobalNatsAccessContract.cs.
package control

import (
	"errors"
	"fmt"
	"strconv"
)

// GlobalNatsCapability mirrors the C# enum: the capability selected by a
// global-control identity. The account is derived from the capability, not
// from a credential supplied by a caller.
type GlobalNatsCapability int

const (
	GlobalNatsCapabilityCellDirectoryPublisher GlobalNatsCapability = 0
	GlobalNatsCapabilityCellDirectoryReader    GlobalNatsCapability = 1
	GlobalNatsCapabilityCellDirectoryService   GlobalNatsCapability = 2
	GlobalNatsCapabilityGlobalAuthority        GlobalNatsCapability = 3
)

func (c GlobalNatsCapability) String() string {
	switch c {
	case GlobalNatsCapabilityCellDirectoryPublisher:
		return "CellDirectoryPublisher"
	case GlobalNatsCapabilityCellDirectoryReader:
		return "CellDirectoryReader"
	case GlobalNatsCapabilityCellDirectoryService:
		return "CellDirectoryService"
	case GlobalNatsCapabilityGlobalAuthority:
		return "GlobalAuthority"
	default:
		return strconv.Itoa(int(c))
	}
}

// GlobalNatsAccountKind mirrors the C# enum.
type GlobalNatsAccountKind int

const (
	GlobalNatsAccountKindGlobalAuthority GlobalNatsAccountKind = 0
	GlobalNatsAccountKindGlobalDirectory GlobalNatsAccountKind = 1
	GlobalNatsAccountKindRegionalControl GlobalNatsAccountKind = 2
)

func (k GlobalNatsAccountKind) String() string {
	switch k {
	case GlobalNatsAccountKindGlobalAuthority:
		return "GlobalAuthority"
	case GlobalNatsAccountKindGlobalDirectory:
		return "GlobalDirectory"
	case GlobalNatsAccountKindRegionalControl:
		return "RegionalControl"
	default:
		return strconv.Itoa(int(k))
	}
}

// GlobalNatsAccountDescriptor mirrors the C# record.
type GlobalNatsAccountDescriptor struct {
	Kind GlobalNatsAccountKind
	Name string
}

// GlobalNatsServiceExportScope mirrors the C# GlobalNatsServiceExport record.
type GlobalNatsServiceExportScope struct {
	Subject string
}

// GlobalNatsServiceImportScope mirrors the C# GlobalNatsServiceImport record.
type GlobalNatsServiceImportScope struct {
	Subject        string
	SourceAccount  string
}

// GlobalNatsAccessPlan mirrors the C# sealed class.
type GlobalNatsAccessPlan struct {
	Cell         string
	Capability   GlobalNatsCapability
	Account      GlobalNatsAccountDescriptor
	Permissions  *GlobalNatsPermissionPlan
	Imports      []GlobalNatsServiceImportScope
	Exports      []GlobalNatsServiceExportScope
}

// Publish mirrors the C# passthrough property.
func (p *GlobalNatsAccessPlan) Publish() []string { return p.Permissions.Publish }

// Subscribe mirrors the C# passthrough property.
func (p *GlobalNatsAccessPlan) Subscribe() []string { return p.Permissions.Subscribe }

// GlobalNatsAccessContract mirrors the C# static class: pure account and
// cross-account access policy for the global directory. It returns names and
// allowlists only.
var GlobalNatsAccessContract globalNatsAccessContract

type globalNatsAccessContract struct{}

// Create mirrors GlobalNatsAccessContract.Create.
func (globalNatsAccessContract) Create(
	cell string,
	capability GlobalNatsCapability,
) (*GlobalNatsAccessPlan, error) {
	if !messagingCellTokenIsValid(cell) {
		return nil, errors.New(
			"The global NATS access cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	if capability == GlobalNatsCapabilityCellDirectoryService && cell != "gru" {
		return nil, errors.New("The global directory service capability is GRU-only. (Parameter 'cell')")
	}

	if capability == GlobalNatsCapabilityGlobalAuthority {
		if err := GlobalNatsConfigurationValidateLegacyAuthorityAlias(cell); err != nil {
			return nil, err
		}
	}

	var role GlobalNatsRole
	switch capability {
	case GlobalNatsCapabilityCellDirectoryPublisher:
		role = GlobalNatsRoleCellDirectoryPublisher
	case GlobalNatsCapabilityCellDirectoryReader:
		role = GlobalNatsRoleCellDirectoryReader
	case GlobalNatsCapabilityCellDirectoryService:
		role = GlobalNatsRoleCellDirectoryService
	case GlobalNatsCapabilityGlobalAuthority:
		role = GlobalNatsRoleGlobalAuthority
	default:
		return nil, fmt.Errorf(
			"Unknown global NATS capability. (Parameter 'capability')\nActual value was %d.", int(capability))
	}

	account, err := globalNatsAccountFor(cell, capability)
	if err != nil {
		return nil, err
	}

	permissions, err := GlobalNatsPermissionsCreate(cell, role)
	if err != nil {
		return nil, err
	}

	imports := []GlobalNatsServiceImportScope{}
	if capability == GlobalNatsCapabilityCellDirectoryReader {
		imports = append(imports, GlobalNatsServiceImportScope{
			Subject:       GlobalNatsTopologyCellDirectorySubject(),
			SourceAccount: GlobalNatsAccountNamesGlobalDirectory,
		})
	}

	exports := []GlobalNatsServiceExportScope{}
	if capability == GlobalNatsCapabilityCellDirectoryService {
		exports = append(exports, GlobalNatsServiceExportScope{
			Subject: GlobalNatsTopologyCellDirectorySubject(),
		})
	}

	return &GlobalNatsAccessPlan{
		Cell:        cell,
		Capability:  capability,
		Account:     account,
		Permissions: permissions,
		Imports:     imports,
		Exports:     exports,
	}, nil
}

// CreateForRole mirrors the GlobalNatsAccessContract.Create(role) overload.
func (globalNatsAccessContract) CreateForRole(cell string, role GlobalNatsRole) (*GlobalNatsAccessPlan, error) {
	var capability GlobalNatsCapability
	switch role {
	case GlobalNatsRoleCellDirectoryPublisher:
		capability = GlobalNatsCapabilityCellDirectoryPublisher
	case GlobalNatsRoleCellDirectoryReader:
		capability = GlobalNatsCapabilityCellDirectoryReader
	case GlobalNatsRoleCellDirectoryService:
		capability = GlobalNatsCapabilityCellDirectoryService
	case GlobalNatsRoleGlobalAuthority:
		capability = GlobalNatsCapabilityGlobalAuthority
	default:
		return nil, fmt.Errorf(
			"Unknown global NATS role. (Parameter 'role')\nActual value was %d.", int(role))
	}

	return GlobalNatsAccessContract.Create(cell, capability)
}

func globalNatsAccountFor(cell string, capability GlobalNatsCapability) (GlobalNatsAccountDescriptor, error) {
	switch capability {
	case GlobalNatsCapabilityGlobalAuthority:
		return GlobalNatsAccountDescriptor{
			Kind: GlobalNatsAccountKindGlobalAuthority,
			Name: GlobalNatsAccountNamesGlobalAuthority,
		}, nil
	case GlobalNatsCapabilityCellDirectoryPublisher, GlobalNatsCapabilityCellDirectoryService:
		return GlobalNatsAccountDescriptor{
			Kind: GlobalNatsAccountKindGlobalDirectory,
			Name: GlobalNatsAccountNamesGlobalDirectory,
		}, nil
	case GlobalNatsCapabilityCellDirectoryReader:
		name, err := GlobalNatsAccountNamesRegionalControl(cell)
		if err != nil {
			return GlobalNatsAccountDescriptor{}, err
		}

		return GlobalNatsAccountDescriptor{
			Kind: GlobalNatsAccountKindRegionalControl,
			Name: name,
		}, nil
	default:
		return GlobalNatsAccountDescriptor{}, fmt.Errorf(
			"Unknown global NATS capability. (Parameter 'capability')\nActual value was %d.", int(capability))
	}
}

const (
	GlobalNatsAccountNamesGlobalAuthority = "ts-orch-global-authority"
	GlobalNatsAccountNamesGlobalDirectory = "ts-orch-global-directory"
)

// GlobalNatsAccountNamesRegionalControl mirrors the C# RegionalControl
// factory.
func GlobalNatsAccountNamesRegionalControl(cell string) (string, error) {
	if !messagingCellTokenIsValid(cell) {
		return "", errors.New(
			"The regional NATS account cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	account := "ts-orch-regional-control-" + cell
	if !GlobalNatsAccountNamesIsValid(account) {
		return "", errors.New("The generated regional NATS account name is invalid.")
	}

	return account, nil
}

// GlobalNatsAccountNamesIsValid mirrors the C# IsValid.
func GlobalNatsAccountNamesIsValid(account string) bool {
	if len(account) < 1 || len(account) > 128 {
		return false
	}

	if account[0] == '-' || account[len(account)-1] == '-' {
		return false
	}

	for index := 0; index < len(account); index++ {
		character := account[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}

		return false
	}

	return true
}
