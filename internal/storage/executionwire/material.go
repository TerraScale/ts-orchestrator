package executionwire

import (
	"encoding/json/jsontext"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
)

type RetainedData struct {
	DatabaseID           string `json:"database_id"`
	PartitionID          string `json:"partition_id"`
	VolumeID             string `json:"volume_id"`
	FileSystemUUID       string `json:"filesystem_uuid"`
	FileSystemType       string `json:"filesystem_type"`
	DiskFormatSHA256     string `json:"disk_format_sha256"`
	SourceArtifactSHA256 string `json:"source_artifact_sha256"`
	SourceTreeSHA256     string `json:"source_tree_sha256"`
	SourceArchitecture   string `json:"source_architecture"`
}

// WorkerGrantMaterial is signed by the current manager only after deriving the
// task assignment from its authenticated registration, placement and OCI state.
// The wire value alone carries no authority; WorkerSession seals verified grants.
type WorkerGrantMaterial struct {
	Desired              jsontext.Value               `json:"desired"`
	Registration         jsontext.Value               `json:"registration"`
	RuntimeRoot          string                       `json:"runtime_root"`
	BootDescriptorSHA256 string                       `json:"boot_descriptor_sha256"`
	Scope                memberstatus.Scope           `json:"scope"`
	MemberAuthority      memberstatus.Authority       `json:"member_authority"`
	Volume               oci.VolumeInitializationPins `json:"volume"`
	Mount                hostvolume.MountPins         `json:"mount"`
	Container            release.ContainerBundle      `json:"container"`
	RetainedContainer    release.ContainerBundle      `json:"retained_container"`
	Retained             RetainedData                 `json:"retained"`
	DesiredGeneration    uint64                       `json:"desired_generation"`
	PlacementGeneration  uint64                       `json:"placement_generation"`
	MemberRevision       uint64                       `json:"member_revision"`
	HostAttempt          uint64                       `json:"host_attempt"`
	PlacementSHA256      string                       `json:"placement_sha256"`
	RosterSHA256         string                       `json:"roster_sha256"`
	MemberSHA256         string                       `json:"member_sha256"`
	OperationID          string                       `json:"operation_id"`
	Survivor             memberstatus.Survivor        `json:"survivor"`
}
