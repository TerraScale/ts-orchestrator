package control

import (
	"time"

	monitoringcore "terrascale.tech/orchestrator/src/orchestrator/monitoring"
)

// These aliases preserve the control package API while endpoint statistics
// live in the focused monitoring package.
type NatsServiceEndpointName = monitoringcore.NatsServiceEndpointName

const (
	NatsServiceEndpointNameHealth         = monitoringcore.NatsServiceEndpointNameHealth
	NatsServiceEndpointNameInstanceHealth = monitoringcore.NatsServiceEndpointNameInstanceHealth
	NatsServiceEndpointNameStatus         = monitoringcore.NatsServiceEndpointNameStatus
	NatsServiceEndpointNameMembers        = monitoringcore.NatsServiceEndpointNameMembers
	NatsServiceEndpointNameStats          = monitoringcore.NatsServiceEndpointNameStats
	NatsServiceEndpointNameDirectDelivery = monitoringcore.NatsServiceEndpointNameDirectDelivery
)

type NatsServiceRequestResult = monitoringcore.NatsServiceRequestResult

const (
	NatsServiceRequestResultOk    = monitoringcore.NatsServiceRequestResultOk
	NatsServiceRequestResultError = monitoringcore.NatsServiceRequestResultError
)

type NatsServiceEndpointMeasurement = monitoringcore.NatsServiceEndpointMeasurement

func NatsServiceEndpointMeasurementEmpty(
	endpoint NatsServiceEndpointName,
) NatsServiceEndpointMeasurement {
	return monitoringcore.NatsServiceEndpointMeasurementEmpty(endpoint)
}

type NatsServiceEndpointStats = monitoringcore.NatsServiceEndpointStats

func NewNatsServiceEndpointStats() *NatsServiceEndpointStats {
	return monitoringcore.NewNatsServiceEndpointStats()
}

const NatsServiceStatsDocumentCurrentSchemaVersion = monitoringcore.NatsServiceStatsDocumentCurrentSchemaVersion

type NatsServiceStatsDocument = monitoringcore.NatsServiceStatsDocument

func NatsServiceStatsDocumentCreate(
	cell string,
	version string,
	schemaGeneration int,
	healthy bool,
	observedAt time.Time,
	endpoints []NatsServiceEndpointMeasurement,
) (*NatsServiceStatsDocument, error) {
	return monitoringcore.NatsServiceStatsDocumentCreate(
		cell, version, schemaGeneration, healthy, observedAt, endpoints)
}
