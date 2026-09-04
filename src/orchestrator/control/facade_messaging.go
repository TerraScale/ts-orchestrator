// Facade aliases keep the historical control.* identifiers working after the
// messaging extraction. New code should import the sub-package directly.
package control

import "terrascale.tech/orchestrator/src/orchestrator/control/messaging"

const (
	GlobalNatsTopologyCellSpecStream             = messaging.GlobalNatsTopologyCellSpecStream
	GlobalNatsTopologyCiStream                   = messaging.GlobalNatsTopologyCiStream
	GlobalNatsTopologyCellsBucket                = messaging.GlobalNatsTopologyCellsBucket
	GlobalNatsTopologyRunnerJobsBucket           = messaging.GlobalNatsTopologyRunnerJobsBucket
	GlobalNatsTopologyRunnerBundlesBucket        = messaging.GlobalNatsTopologyRunnerBundlesBucket
	GlobalNatsTopologyCiRunnerJournalKeyPrefix   = messaging.GlobalNatsTopologyCiRunnerJournalKeyPrefix
	NatsServiceStatsDocumentCurrentSchemaVersion = messaging.NatsServiceStatsDocumentCurrentSchemaVersion
	NatsMessageIdDeduplicationDefaultCapacity    = messaging.NatsMessageIdDeduplicationDefaultCapacity
	MessagingGroupAny                            = messaging.MessagingGroupAny
	MessagingOtherAny                            = messaging.MessagingOtherAny
)

const (
	GlobalNatsRoleCellDirectoryPublisher = messaging.GlobalNatsRoleCellDirectoryPublisher
	GlobalNatsRoleCellDirectoryReader    = messaging.GlobalNatsRoleCellDirectoryReader
	GlobalNatsRoleCellDirectoryService   = messaging.GlobalNatsRoleCellDirectoryService
	GlobalNatsRoleGlobalAuthority        = messaging.GlobalNatsRoleGlobalAuthority
)

var (
	NatsProtocolPackageBytes                   = messaging.NatsProtocolPackageBytes
	NewNatsMessageIdentity                     = messaging.NewNatsMessageIdentity
	NewNatsTopology                            = messaging.NewNatsTopology
	NewGlobalNatsTopology                      = messaging.NewGlobalNatsTopology
	GlobalNatsTopologyCiSubject                = messaging.GlobalNatsTopologyCiSubject
	GlobalNatsTopologyCiJobSubjectPrefix       = messaging.GlobalNatsTopologyCiJobSubjectPrefix
	GlobalNatsTopologyCiRuntimeProofSubject    = messaging.GlobalNatsTopologyCiRuntimeProofSubject
	GlobalNatsTopologyCellDirectorySubject     = messaging.GlobalNatsTopologyCellDirectorySubject
	GlobalNatsTopologyCellSpecSubjectPrefix    = messaging.GlobalNatsTopologyCellSpecSubjectPrefix
	GlobalNatsTopologyCiJobSubject             = messaging.GlobalNatsTopologyCiJobSubject
	GlobalNatsTopologyCellSpecSubject          = messaging.GlobalNatsTopologyCellSpecSubject
	GlobalNatsTopologyIsCellToken              = messaging.GlobalNatsTopologyIsCellToken
	GlobalNatsTopologyCellAdvertisementKey     = messaging.GlobalNatsTopologyCellAdvertisementKey
	GlobalNatsTopologyCiRunnerJournalPrefix    = messaging.GlobalNatsTopologyCiRunnerJournalPrefix
	GlobalNatsTopologyCiRunnerIdentityHash     = messaging.GlobalNatsTopologyCiRunnerIdentityHash
	GlobalNatsTopologyBucketName               = messaging.GlobalNatsTopologyBucketName
	NewCiRunnerNatsPermissionPlan              = messaging.NewCiRunnerNatsPermissionPlan
	CiRunnerNatsPermissions                    = messaging.CiRunnerNatsPermissions
	GlobalNatsPermissions                      = messaging.GlobalNatsPermissions
	NewGlobalNatsPermissionPlan                = messaging.NewGlobalNatsPermissionPlan
	GlobalNatsPermissionsCreate                = messaging.GlobalNatsPermissionsCreate
	NewNatsCommandReplayStore                  = messaging.NewNatsCommandReplayStore
	NewNatsServiceEndpointStats                = messaging.NewNatsServiceEndpointStats
	NatsServiceStatsDocumentCreate             = messaging.NatsServiceStatsDocumentCreate
	NatsServiceEndpointMeasurementEmpty        = messaging.NatsServiceEndpointMeasurementEmpty
	NatsAuthenticationFilesResolve             = messaging.NatsAuthenticationFilesResolve
	NatsAuthenticationFilesFromCredentialsFile = messaging.NatsAuthenticationFilesFromCredentialsFile
	NatsAuthenticationFilesFromNKeyFile        = messaging.NatsAuthenticationFilesFromNKeyFile
	NatsTlsFilesResolve                        = messaging.NatsTlsFilesResolve
	NatsNkeyOption                             = messaging.NatsNkeyOption
	NatsConnect                                = messaging.NatsConnect
	MessagingUnixFileMode                      = messaging.MessagingUnixFileMode
	NkeySeed                                   = messaging.NkeySeed
	NewNatsMessageIdDeduplication              = messaging.NewNatsMessageIdDeduplication
)

type (
	GlobalNatsTopology                 = messaging.GlobalNatsTopology
	CiRunnerNatsPermissionPlan         = messaging.CiRunnerNatsPermissionPlan
	GlobalNatsRole                     = messaging.GlobalNatsRole
	GlobalNatsPermissionPlan           = messaging.GlobalNatsPermissionPlan
	NatsTlsFiles                       = messaging.NatsTlsFiles
	NatsConnectionConfiguration        = messaging.NatsConnectionConfiguration
	NatsServiceEndpointName            = messaging.NatsServiceEndpointName
	NatsServiceRequestResult           = messaging.NatsServiceRequestResult
	NatsServiceEndpointMeasurement     = messaging.NatsServiceEndpointMeasurement
	NatsServiceEndpointStats           = messaging.NatsServiceEndpointStats
	NatsServiceStatsDocument           = messaging.NatsServiceStatsDocument
	NatsAuthenticationFiles            = messaging.NatsAuthenticationFiles
	NatsMessageIdDeduplication         = messaging.NatsMessageIdDeduplication
	NatsMessageIdDeduplicationSnapshot = messaging.NatsMessageIdDeduplicationSnapshot
	NatsCommandReplayStore             = messaging.NatsCommandReplayStore
	NatsTopology                       = messaging.NatsTopology
)

// Value-typed package members whose types are unexported are aliased as values.
var (
	NatsCredentialFile = messaging.NatsCredentialFile
)
