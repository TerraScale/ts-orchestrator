package contracts

import "strconv"

// RoleKind mirrors the RoleKind enum.
type RoleKind int

const (
	RoleKindUnspecified     RoleKind = 0
	RoleKindDashboard       RoleKind = 1
	RoleKindDatabaseAPI     RoleKind = 2
	RoleKindTerraBaseMember RoleKind = 3
	RoleKindNats            RoleKind = 4
	RoleKindAutoscaler      RoleKind = 5
	RoleKindJournalWriter   RoleKind = 6
)

func (k RoleKind) String() string {
	switch k {
	case RoleKindDashboard:
		return "Dashboard"
	case RoleKindDatabaseAPI:
		return "DatabaseAPI"
	case RoleKindTerraBaseMember:
		return "TerraBaseMember"
	case RoleKindNats:
		return "Nats"
	case RoleKindAutoscaler:
		return "Autoscaler"
	case RoleKindJournalWriter:
		return "JournalWriter"
	default:
		return strconv.Itoa(int(k))
	}
}

func roleKindIsDefined(k RoleKind) bool {
	return k >= RoleKindDashboard && k <= RoleKindJournalWriter
}

// AdmittedRole is the closed workload-role union.
type AdmittedRole struct {
	kind RoleKind
}

// Kind returns the role kind of this admitted role.
func (r AdmittedRole) Kind() RoleKind { return r.kind }

// Projection returns the canonical per-role string used by RoleDescriptor.
func (r AdmittedRole) Projection() string { return r.kind.String() }

func newPlainRole(kind RoleKind) AdmittedRole { return AdmittedRole{kind: kind} }

func NewDashboardRole() AdmittedRole { return newPlainRole(RoleKindDashboard) }

func NewDatabaseAPIRole() AdmittedRole { return newPlainRole(RoleKindDatabaseAPI) }

func NewTerraBaseMemberRole() AdmittedRole { return newPlainRole(RoleKindTerraBaseMember) }

func NewNatsRole() AdmittedRole { return newPlainRole(RoleKindNats) }

func NewAutoscalerRole() AdmittedRole { return newPlainRole(RoleKindAutoscaler) }

func NewJournalWriterRole() AdmittedRole { return newPlainRole(RoleKindJournalWriter) }
