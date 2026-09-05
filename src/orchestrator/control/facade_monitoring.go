// Facade aliases keep the historical control.* identifiers working after the
// New code should import the sub-package directly.
package control

import "terrascale.tech/orchestrator/src/orchestrator/control/monitoring"

const (
	NatsAdvisoryKindAuthenticationFailure                     = monitoring.NatsAdvisoryKindAuthenticationFailure
	NatsAdvisoryKindLeaderChange                              = monitoring.NatsAdvisoryKindLeaderChange
	NatsAdvisoryKindMaxDeliveries                             = monitoring.NatsAdvisoryKindMaxDeliveries
	NatsAdvisoryKindResourceExhausted                         = monitoring.NatsAdvisoryKindResourceExhausted
	NatsAdvisoryKindSlowConsumer                              = monitoring.NatsAdvisoryKindSlowConsumer
	NatsAdvisoryKindUnclassified                              = monitoring.NatsAdvisoryKindUnclassified
	NatsCertificateClassGatewayLink                           = monitoring.NatsCertificateClassGatewayLink
	NatsCertificateClassMonitoringClient                      = monitoring.NatsCertificateClassMonitoringClient
	NatsCertificateClassServerListener                        = monitoring.NatsCertificateClassServerListener
	NatsClusterRoleGlobalAuthority                            = monitoring.NatsClusterRoleGlobalAuthority
	NatsClusterRoleRegional                                   = monitoring.NatsClusterRoleRegional
	NatsConsumerClassCellSpec                                 = monitoring.NatsConsumerClassCellSpec
	NatsConsumerClassEphemeralWatch                           = monitoring.NatsConsumerClassEphemeralWatch
	NatsConsumerClassStartupEvent                             = monitoring.NatsConsumerClassStartupEvent
	NatsConsumerClassUnknown                                  = monitoring.NatsConsumerClassUnknown
	NatsMeshCellStateConflicting                              = monitoring.NatsMeshCellStateConflicting
	NatsMeshCellStateDisconnected                             = monitoring.NatsMeshCellStateDisconnected
	NatsMeshCellStateHealthy                                  = monitoring.NatsMeshCellStateHealthy
	NatsMeshCellStateMissing                                  = monitoring.NatsMeshCellStateMissing
	NatsMeshCellStateStale                                    = monitoring.NatsMeshCellStateStale
	NatsMeshHealthCurrentSchemaVersion                        = monitoring.NatsMeshHealthCurrentSchemaVersion
	NatsMonitoringAggregateCurrentSchemaVersion               = monitoring.NatsMonitoringAggregateCurrentSchemaVersion
	NatsMonitoringAlertSeverityCritical                       = monitoring.NatsMonitoringAlertSeverityCritical
	NatsMonitoringAlertSeverityWarning                        = monitoring.NatsMonitoringAlertSeverityWarning
	NatsMonitoringAvailabilityAvailable                       = monitoring.NatsMonitoringAvailabilityAvailable
	NatsMonitoringAvailabilityDegraded                        = monitoring.NatsMonitoringAvailabilityDegraded
	NatsMonitoringAvailabilityUnavailable                     = monitoring.NatsMonitoringAvailabilityUnavailable
	NatsMonitoringInstrumentKindCounter                       = monitoring.NatsMonitoringInstrumentKindCounter
	NatsMonitoringInstrumentKindGauge                         = monitoring.NatsMonitoringInstrumentKindGauge
	NatsMonitoringInstrumentKindHistogram                     = monitoring.NatsMonitoringInstrumentKindHistogram
	NatsMonitoringParsersMaximumReplyBytes                    = monitoring.NatsMonitoringParsersMaximumReplyBytes
	NatsMonitoringPlaneControl                                = monitoring.NatsMonitoringPlaneControl
	NatsMonitoringPlaneProduct                                = monitoring.NatsMonitoringPlaneProduct
	NatsMonitoringRedactionRedactedPlaceholder                = monitoring.NatsMonitoringRedactionRedactedPlaceholder
	NatsMonitoringSnapshotCurrentSchemaVersion                = monitoring.NatsMonitoringSnapshotCurrentSchemaVersion
	NatsMonitoringSnapshotEntryMaximumLabelValueLength        = monitoring.NatsMonitoringSnapshotEntryMaximumLabelValueLength
	NatsMonitoringSubjectsAccountAdvisories                   = monitoring.NatsMonitoringSubjectsAccountAdvisories
	NatsMonitoringSubjectsAccounts                            = monitoring.NatsMonitoringSubjectsAccounts
	NatsMonitoringSubjectsConnections                         = monitoring.NatsMonitoringSubjectsConnections
	NatsMonitoringSubjectsGateways                            = monitoring.NatsMonitoringSubjectsGateways
	NatsMonitoringSubjectsJetStream                           = monitoring.NatsMonitoringSubjectsJetStream
	NatsMonitoringSubjectsJetStreamAdvisories                 = monitoring.NatsMonitoringSubjectsJetStreamAdvisories
	NatsMonitoringSubjectsRoutes                              = monitoring.NatsMonitoringSubjectsRoutes
	NatsMonitoringSubjectsServer                              = monitoring.NatsMonitoringSubjectsServer
	NatsMonitoringSupervisionActionContinue                   = monitoring.NatsMonitoringSupervisionActionContinue
	NatsMonitoringSupervisionActionMarkDegraded               = monitoring.NatsMonitoringSupervisionActionMarkDegraded
	NatsMonitoringSupervisionActionMarkUnavailable            = monitoring.NatsMonitoringSupervisionActionMarkUnavailable
	NatsMonitoringSupervisionDegradedAfterConsecutiveFailures = monitoring.NatsMonitoringSupervisionDegradedAfterConsecutiveFailures
	NatsStoreClassKeyValue                                    = monitoring.NatsStoreClassKeyValue
	NatsStoreClassObjectStore                                 = monitoring.NatsStoreClassObjectStore
	NatsStreamClassCellEvents                                 = monitoring.NatsStreamClassCellEvents
	NatsStreamClassCellOperations                             = monitoring.NatsStreamClassCellOperations
	NatsStreamClassCellSpec                                   = monitoring.NatsStreamClassCellSpec
	NatsStreamClassGlobalSpec                                 = monitoring.NatsStreamClassGlobalSpec
	NatsStreamClassKeyValue                                   = monitoring.NatsStreamClassKeyValue
	NatsStreamClassObjectStore                                = monitoring.NatsStreamClassObjectStore
	NatsStreamClassUnknown                                    = monitoring.NatsStreamClassUnknown
)

var (
	NatsAccountsObserve                       = monitoring.NatsAccountsObserve
	NatsCertificateObserve                    = monitoring.NatsCertificateObserve
	NatsConnectionsObserve                    = monitoring.NatsConnectionsObserve
	NatsGatewaysObserve                       = monitoring.NatsGatewaysObserve
	NatsJetStreamObserve                      = monitoring.NatsJetStreamObserve
	NatsMeshHealthEvaluate                    = monitoring.NatsMeshHealthEvaluate
	NatsMonitoringPermissionsGrants           = monitoring.NatsMonitoringPermissionsGrants
	NatsMonitoringSnapshotFrom                = monitoring.NatsMonitoringSnapshotFrom
	NatsRoutesObserve                         = monitoring.NatsRoutesObserve
	NatsServerResourceObserve                 = monitoring.NatsServerResourceObserve
	NewNatsMonitoringAlertRule                = monitoring.NewNatsMonitoringAlertRule
	NewNatsMonitoringCorrelation              = monitoring.NewNatsMonitoringCorrelation
	NewNatsMonitoringInstrument               = monitoring.NewNatsMonitoringInstrument
	NewNatsMonitoringPermissionPlan           = monitoring.NewNatsMonitoringPermissionPlan
	NewNatsMonitoringSnapshotEntry            = monitoring.NewNatsMonitoringSnapshotEntry
	NatsAlertCatalog                          = monitoring.NatsAlertCatalog
	NatsMonitoringClassifier                  = monitoring.NatsMonitoringClassifier
	NatsMonitoringInstrumentCatalog           = monitoring.NatsMonitoringInstrumentCatalog
	NatsMonitoringLabels                      = monitoring.NatsMonitoringLabels
	NatsMonitoringParsers                     = monitoring.NatsMonitoringParsers
	NatsMonitoringPermissions                 = monitoring.NatsMonitoringPermissions
	NatsMonitoringPermissionsForbidden        = monitoring.NatsMonitoringPermissionsForbidden
	NatsMonitoringRedaction                   = monitoring.NatsMonitoringRedaction
	NatsMonitoringSubjects                    = monitoring.NatsMonitoringSubjects
	NatsMonitoringSupervision                 = monitoring.NatsMonitoringSupervision
	NatsMonitoringSupervisionDegradedAfter    = monitoring.NatsMonitoringSupervisionDegradedAfter
	NatsMonitoringSupervisionUnavailableAfter = monitoring.NatsMonitoringSupervisionUnavailableAfter
)

type (
	INatsMonitoringObservation      = monitoring.INatsMonitoringObservation
	NatsAccountsObservation         = monitoring.NatsAccountsObservation
	NatsAdvisoryCount               = monitoring.NatsAdvisoryCount
	NatsAdvisoryKind                = monitoring.NatsAdvisoryKind
	NatsCertificateClass            = monitoring.NatsCertificateClass
	NatsCertificateObservation      = monitoring.NatsCertificateObservation
	NatsClusterRole                 = monitoring.NatsClusterRole
	NatsConnectionsObservation      = monitoring.NatsConnectionsObservation
	NatsConsumerClass               = monitoring.NatsConsumerClass
	NatsConsumerClassState          = monitoring.NatsConsumerClassState
	NatsGatewaysObservation         = monitoring.NatsGatewaysObservation
	NatsJetStreamObservation        = monitoring.NatsJetStreamObservation
	NatsMeshCell                    = monitoring.NatsMeshCell
	NatsMeshCellState               = monitoring.NatsMeshCellState
	NatsMeshHealth                  = monitoring.NatsMeshHealth
	NatsMonitoringAggregate         = monitoring.NatsMonitoringAggregate
	NatsMonitoringAlertRule         = monitoring.NatsMonitoringAlertRule
	NatsMonitoringAlertSeverity     = monitoring.NatsMonitoringAlertSeverity
	NatsMonitoringAvailability      = monitoring.NatsMonitoringAvailability
	NatsMonitoringCorrelation       = monitoring.NatsMonitoringCorrelation
	NatsMonitoringInstrument        = monitoring.NatsMonitoringInstrument
	NatsMonitoringInstrumentKind    = monitoring.NatsMonitoringInstrumentKind
	NatsMonitoringJetStreamDetail   = monitoring.NatsMonitoringJetStreamDetail
	NatsMonitoringPermissionPlan    = monitoring.NatsMonitoringPermissionPlan
	NatsMonitoringPlane             = monitoring.NatsMonitoringPlane
	NatsMonitoringSnapshot          = monitoring.NatsMonitoringSnapshot
	NatsMonitoringSnapshotEntry     = monitoring.NatsMonitoringSnapshotEntry
	NatsMonitoringSupervisionAction = monitoring.NatsMonitoringSupervisionAction
	NatsRoutesObservation           = monitoring.NatsRoutesObservation
	NatsServerResourceObservation   = monitoring.NatsServerResourceObservation
	NatsStoreClass                  = monitoring.NatsStoreClass
	NatsStoreClassState             = monitoring.NatsStoreClassState
	NatsStreamClass                 = monitoring.NatsStreamClass
	NatsStreamClassState            = monitoring.NatsStreamClassState
)
