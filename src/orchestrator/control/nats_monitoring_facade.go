package control

// This file preserves the historical control-package API while monitoring
// owns the implementation. New code should import orchestrator/monitoring.
import (
	"terrascale.tech/orchestrator/src/orchestrator/monitoring"
	"time"
)

type NatsMonitoringInstrumentKind = monitoring.NatsMonitoringInstrumentKind
type NatsMonitoringAlertSeverity = monitoring.NatsMonitoringAlertSeverity
type NatsMonitoringInstrument = monitoring.NatsMonitoringInstrument
type NatsMonitoringAlertRule = monitoring.NatsMonitoringAlertRule
type NatsMonitoringSnapshotEntry = monitoring.NatsMonitoringSnapshotEntry
type NatsMonitoringSnapshot = monitoring.NatsMonitoringSnapshot
type NatsMonitoringPlane = monitoring.NatsMonitoringPlane
type NatsClusterRole = monitoring.NatsClusterRole
type NatsStreamClass = monitoring.NatsStreamClass
type NatsConsumerClass = monitoring.NatsConsumerClass
type NatsStoreClass = monitoring.NatsStoreClass
type NatsCertificateClass = monitoring.NatsCertificateClass
type NatsAdvisoryKind = monitoring.NatsAdvisoryKind
type NatsConnectionsObservation = monitoring.NatsConnectionsObservation
type NatsRoutesObservation = monitoring.NatsRoutesObservation
type NatsGatewaysObservation = monitoring.NatsGatewaysObservation
type NatsAccountsObservation = monitoring.NatsAccountsObservation
type NatsJetStreamObservation = monitoring.NatsJetStreamObservation
type NatsStreamClassState = monitoring.NatsStreamClassState
type NatsConsumerClassState = monitoring.NatsConsumerClassState
type NatsStoreClassState = monitoring.NatsStoreClassState
type NatsServerResourceObservation = monitoring.NatsServerResourceObservation
type NatsCertificateObservation = monitoring.NatsCertificateObservation
type NatsAdvisoryCount = monitoring.NatsAdvisoryCount
type NatsMeshCellState = monitoring.NatsMeshCellState
type NatsMeshCell = monitoring.NatsMeshCell
type NatsMeshHealth = monitoring.NatsMeshHealth
type NatsMonitoringAvailability = monitoring.NatsMonitoringAvailability
type NatsMonitoringAggregate = monitoring.NatsMonitoringAggregate
type INatsMonitoringObservation = monitoring.INatsMonitoringObservation
type NatsMonitoringJetStreamDetail = monitoring.NatsMonitoringJetStreamDetail
type NatsMonitoringSupervisionAction = monitoring.NatsMonitoringSupervisionAction
type NatsMonitoringCorrelation = monitoring.NatsMonitoringCorrelation
type NatsMonitoringPermissionPlan = monitoring.NatsMonitoringPermissionPlan

type natsMonitoringSupervisionFacade struct{}

const (
	NatsMonitoringInstrumentKindCounter                       = monitoring.NatsMonitoringInstrumentKindCounter
	NatsMonitoringInstrumentKindGauge                         = monitoring.NatsMonitoringInstrumentKindGauge
	NatsMonitoringInstrumentKindHistogram                     = monitoring.NatsMonitoringInstrumentKindHistogram
	NatsMonitoringAlertSeverityWarning                        = monitoring.NatsMonitoringAlertSeverityWarning
	NatsMonitoringAlertSeverityCritical                       = monitoring.NatsMonitoringAlertSeverityCritical
	NatsMonitoringSnapshotEntryMaximumLabelValueLength        = monitoring.NatsMonitoringSnapshotEntryMaximumLabelValueLength
	NatsMonitoringSnapshotCurrentSchemaVersion                = monitoring.NatsMonitoringSnapshotCurrentSchemaVersion
	NatsMonitoringPlaneControl                                = monitoring.NatsMonitoringPlaneControl
	NatsMonitoringPlaneProduct                                = monitoring.NatsMonitoringPlaneProduct
	NatsClusterRoleRegional                                   = monitoring.NatsClusterRoleRegional
	NatsClusterRoleGlobalAuthority                            = monitoring.NatsClusterRoleGlobalAuthority
	NatsStreamClassCellSpec                                   = monitoring.NatsStreamClassCellSpec
	NatsStreamClassCellOperations                             = monitoring.NatsStreamClassCellOperations
	NatsStreamClassCellEvents                                 = monitoring.NatsStreamClassCellEvents
	NatsStreamClassGlobalSpec                                 = monitoring.NatsStreamClassGlobalSpec
	NatsStreamClassGlobalCi                                   = monitoring.NatsStreamClassGlobalCi
	NatsStreamClassKeyValue                                   = monitoring.NatsStreamClassKeyValue
	NatsStreamClassObjectStore                                = monitoring.NatsStreamClassObjectStore
	NatsStreamClassUnknown                                    = monitoring.NatsStreamClassUnknown
	NatsConsumerClassStartupEvent                             = monitoring.NatsConsumerClassStartupEvent
	NatsConsumerClassCellSpec                                 = monitoring.NatsConsumerClassCellSpec
	NatsConsumerClassGlobalCi                                 = monitoring.NatsConsumerClassGlobalCi
	NatsConsumerClassEphemeralWatch                           = monitoring.NatsConsumerClassEphemeralWatch
	NatsConsumerClassUnknown                                  = monitoring.NatsConsumerClassUnknown
	NatsStoreClassKeyValue                                    = monitoring.NatsStoreClassKeyValue
	NatsStoreClassObjectStore                                 = monitoring.NatsStoreClassObjectStore
	NatsCertificateClassServerListener                        = monitoring.NatsCertificateClassServerListener
	NatsCertificateClassGatewayLink                           = monitoring.NatsCertificateClassGatewayLink
	NatsCertificateClassMonitoringClient                      = monitoring.NatsCertificateClassMonitoringClient
	NatsAdvisoryKindSlowConsumer                              = monitoring.NatsAdvisoryKindSlowConsumer
	NatsAdvisoryKindLeaderChange                              = monitoring.NatsAdvisoryKindLeaderChange
	NatsAdvisoryKindAuthenticationFailure                     = monitoring.NatsAdvisoryKindAuthenticationFailure
	NatsAdvisoryKindMaxDeliveries                             = monitoring.NatsAdvisoryKindMaxDeliveries
	NatsAdvisoryKindResourceExhausted                         = monitoring.NatsAdvisoryKindResourceExhausted
	NatsAdvisoryKindUnclassified                              = monitoring.NatsAdvisoryKindUnclassified
	NatsMeshCellStateHealthy                                  = monitoring.NatsMeshCellStateHealthy
	NatsMeshCellStateStale                                    = monitoring.NatsMeshCellStateStale
	NatsMeshCellStateMissing                                  = monitoring.NatsMeshCellStateMissing
	NatsMeshCellStateConflicting                              = monitoring.NatsMeshCellStateConflicting
	NatsMeshCellStateDisconnected                             = monitoring.NatsMeshCellStateDisconnected
	NatsMeshHealthCurrentSchemaVersion                        = monitoring.NatsMeshHealthCurrentSchemaVersion
	NatsMonitoringAvailabilityAvailable                       = monitoring.NatsMonitoringAvailabilityAvailable
	NatsMonitoringAvailabilityDegraded                        = monitoring.NatsMonitoringAvailabilityDegraded
	NatsMonitoringAvailabilityUnavailable                     = monitoring.NatsMonitoringAvailabilityUnavailable
	NatsMonitoringAggregateCurrentSchemaVersion               = monitoring.NatsMonitoringAggregateCurrentSchemaVersion
	NatsMonitoringParsersMaximumReplyBytes                    = monitoring.NatsMonitoringParsersMaximumReplyBytes
	NatsMonitoringSupervisionActionContinue                   = monitoring.NatsMonitoringSupervisionActionContinue
	NatsMonitoringSupervisionActionMarkDegraded               = monitoring.NatsMonitoringSupervisionActionMarkDegraded
	NatsMonitoringSupervisionActionMarkUnavailable            = monitoring.NatsMonitoringSupervisionActionMarkUnavailable
	NatsMonitoringSupervisionDegradedAfterConsecutiveFailures = monitoring.NatsMonitoringSupervisionDegradedAfterConsecutiveFailures
	NatsMonitoringRedactionRedactedPlaceholder                = monitoring.NatsMonitoringRedactionRedactedPlaceholder
	NatsMonitoringSubjectsConnections                         = monitoring.NatsMonitoringSubjectsConnections
	NatsMonitoringSubjectsRoutes                              = monitoring.NatsMonitoringSubjectsRoutes
	NatsMonitoringSubjectsGateways                            = monitoring.NatsMonitoringSubjectsGateways
	NatsMonitoringSubjectsServer                              = monitoring.NatsMonitoringSubjectsServer
	NatsMonitoringSubjectsJetStream                           = monitoring.NatsMonitoringSubjectsJetStream
	NatsMonitoringSubjectsAccounts                            = monitoring.NatsMonitoringSubjectsAccounts
	NatsMonitoringSubjectsAccountAdvisories                   = monitoring.NatsMonitoringSubjectsAccountAdvisories
	NatsMonitoringSubjectsJetStreamAdvisories                 = monitoring.NatsMonitoringSubjectsJetStreamAdvisories
)

var NatsMonitoringLabels = monitoring.NatsMonitoringLabels
var NatsMonitoringInstrumentCatalog = monitoring.NatsMonitoringInstrumentCatalog
var NatsAlertCatalog = monitoring.NatsAlertCatalog
var NatsMonitoringClassifier = monitoring.NatsMonitoringClassifier
var NatsMonitoringParsers = monitoring.NatsMonitoringParsers
var NatsMonitoringRedaction = monitoring.NatsMonitoringRedaction
var NatsMonitoringSubjects = monitoring.NatsMonitoringSubjects
var NatsMonitoringPermissions = monitoring.NatsMonitoringPermissions
var NatsMonitoringPermissionsForbidden = monitoring.NatsMonitoringPermissionsForbidden
var NatsMonitoringSupervision natsMonitoringSupervisionFacade
var NatsMonitoringSupervisionDegradedAfter = monitoring.NatsMonitoringSupervisionDegradedAfter
var NatsMonitoringSupervisionUnavailableAfter = monitoring.NatsMonitoringSupervisionUnavailableAfter

func NewNatsMonitoringInstrument(name, unit string, kind NatsMonitoringInstrumentKind, labelKeys, sourceSubjects []string, failureBehavior string) (*NatsMonitoringInstrument, error) {
	return monitoring.NewNatsMonitoringInstrument(name, unit, kind, labelKeys, sourceSubjects, failureBehavior)
}
func NewNatsMonitoringAlertRule(id, description string, severity NatsMonitoringAlertSeverity, instrumentNames []string, firesWhen, recoveryWhen, runbook string) (*NatsMonitoringAlertRule, error) {
	return monitoring.NewNatsMonitoringAlertRule(id, description, severity, instrumentNames, firesWhen, recoveryWhen, runbook)
}
func NewNatsMonitoringSnapshotEntry(instrument, unit string, labels map[string]string, value float64) (*NatsMonitoringSnapshotEntry, error) {
	return monitoring.NewNatsMonitoringSnapshotEntry(instrument, unit, labels, value)
}
func NewNatsMonitoringPermissionPlan(publish, subscribe []string) (*NatsMonitoringPermissionPlan, error) {
	return monitoring.NewNatsMonitoringPermissionPlan(publish, subscribe)
}
func NatsMonitoringSnapshotFrom(aggregate NatsMonitoringAggregate) (*NatsMonitoringSnapshot, error) {
	return monitoring.NatsMonitoringSnapshotFrom(aggregate)
}
func NatsConnectionsObserve(cell string, plane NatsMonitoringPlane, connections, reconnects int64, observedAt time.Time) NatsConnectionsObservation {
	return monitoring.NatsConnectionsObserve(cell, plane, connections, reconnects, observedAt)
}
func NatsRoutesObserve(cell string, routes int64, observedAt time.Time) NatsRoutesObservation {
	return monitoring.NatsRoutesObserve(cell, routes, observedAt)
}
func NatsGatewaysObserve(cell string, connected, disconnected int, observedAt time.Time) NatsGatewaysObservation {
	return monitoring.NatsGatewaysObserve(cell, connected, disconnected, observedAt)
}
func NatsAccountsObserve(cell string, accounts, connections int64, observedAt time.Time) NatsAccountsObservation {
	return monitoring.NatsAccountsObserve(cell, accounts, connections, observedAt)
}
func NatsJetStreamObserve(cell string, domains, streams, consumers, memoryBytes, storageBytes int64, observedAt time.Time) NatsJetStreamObservation {
	return monitoring.NatsJetStreamObserve(cell, domains, streams, consumers, memoryBytes, storageBytes, observedAt)
}
func NatsServerResourceObserve(cell string, serverMemoryBytes, jetStreamStorageBytes int64, observedAt time.Time) NatsServerResourceObservation {
	return monitoring.NatsServerResourceObserve(cell, serverMemoryBytes, jetStreamStorageBytes, observedAt)
}
func NatsCertificateObserve(cell string, certificateClass NatsCertificateClass, notAfter, observedAt time.Time) NatsCertificateObservation {
	return monitoring.NatsCertificateObserve(cell, certificateClass, notAfter, observedAt)
}
func NewNatsMonitoringCorrelation(correlationToken, redactedSummary string) (*NatsMonitoringCorrelation, error) {
	return monitoring.NewNatsMonitoringCorrelation(correlationToken, redactedSummary)
}
func NatsMonitoringPermissionsGrants(granted []string, subject string) bool {
	return monitoring.NatsMonitoringPermissionsGrants(granted, subject)
}

func (natsMonitoringSupervisionFacade) Evaluate(lastSuccessfulObservation *time.Time, consecutiveFailedRounds int, now time.Time) NatsMonitoringSupervisionAction {
	if consecutiveFailedRounds < 0 {
		panic("Specified argument was out of the range of valid values. (Parameter 'consecutiveFailedRounds')")
	}
	if lastSuccessfulObservation != nil {
		age := now.Sub(*lastSuccessfulObservation)
		if age < NatsMonitoringSupervisionDegradedAfter && consecutiveFailedRounds == 0 {
			return NatsMonitoringSupervisionActionContinue
		}
		if age < NatsMonitoringSupervisionUnavailableAfter {
			return NatsMonitoringSupervisionActionMarkDegraded
		}
		return NatsMonitoringSupervisionActionMarkUnavailable
	}
	if consecutiveFailedRounds == 0 {
		return NatsMonitoringSupervisionActionMarkDegraded
	}
	return NatsMonitoringSupervisionActionMarkUnavailable
}

func (natsMonitoringSupervisionFacade) Availability(lastSuccessfulObservation *time.Time, consecutiveFailedRounds int, now time.Time) NatsMonitoringAvailability {
	switch NatsMonitoringSupervision.Evaluate(lastSuccessfulObservation, consecutiveFailedRounds, now) {
	case NatsMonitoringSupervisionActionContinue:
		return NatsMonitoringAvailabilityAvailable
	case NatsMonitoringSupervisionActionMarkDegraded:
		return NatsMonitoringAvailabilityDegraded
	default:
		return NatsMonitoringAvailabilityUnavailable
	}
}

func (natsMonitoringSupervisionFacade) RegionalControlContinues(NatsMonitoringSupervisionAction) bool {
	return true
}

func NatsMeshHealthEvaluate(expectedCells []string, membershipByCell map[string]RegionalRuntimeMembershipHealth, directory GlobalCellDirectorySnapshot, gatewaysByCell map[string]NatsGatewaysObservation, observedAt time.Time) (NatsMeshHealth, error) {
	view := monitoring.MeshDirectorySnapshot{Cells: make([]monitoring.MeshDirectoryEntry, 0, len(directory.Cells))}
	for _, entry := range directory.Cells {
		view.Cells = append(view.Cells, monitoring.MeshDirectoryEntry{Cell: entry.Cell, LeaseExpiresAt: entry.LeaseExpiresAt, MembershipCondition: entry.Membership.Condition})
	}
	return monitoring.NatsMeshHealthEvaluate(expectedCells, membershipByCell, view, gatewaysByCell, observedAt)
}
