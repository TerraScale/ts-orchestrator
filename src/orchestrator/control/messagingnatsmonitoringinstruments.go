// Port of src/TerraScale.Orchestrator/Messaging/NatsMonitoringInstruments.cs.
package control

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// NatsMonitoringInstrumentKind mirrors the C# enum.
type NatsMonitoringInstrumentKind int

const (
	NatsMonitoringInstrumentKindCounter   NatsMonitoringInstrumentKind = 1
	NatsMonitoringInstrumentKindGauge     NatsMonitoringInstrumentKind = 2
	NatsMonitoringInstrumentKindHistogram NatsMonitoringInstrumentKind = 3
)

func (k NatsMonitoringInstrumentKind) String() string {
	switch k {
	case NatsMonitoringInstrumentKindCounter:
		return "Counter"
	case NatsMonitoringInstrumentKindGauge:
		return "Gauge"
	case NatsMonitoringInstrumentKindHistogram:
		return "Histogram"
	default:
		return ""
	}
}

// NatsMonitoringAlertSeverity mirrors the C# enum.
type NatsMonitoringAlertSeverity int

const (
	NatsMonitoringAlertSeverityWarning  NatsMonitoringAlertSeverity = 1
	NatsMonitoringAlertSeverityCritical NatsMonitoringAlertSeverity = 2
)

func (s NatsMonitoringAlertSeverity) String() string {
	switch s {
	case NatsMonitoringAlertSeverityWarning:
		return "Warning"
	case NatsMonitoringAlertSeverityCritical:
		return "Critical"
	default:
		return ""
	}
}

// NatsMonitoringInstrument mirrors the C# record: one canonical NATS
// monitoring instrument.
type NatsMonitoringInstrument struct {
	Name            string
	Unit            string
	Kind            NatsMonitoringInstrumentKind
	LabelKeys       []string
	SourceSubjects  []string
	FailureBehavior string
}

// NewNatsMonitoringInstrument mirrors the C# constructor.
func NewNatsMonitoringInstrument(
	name string,
	unit string,
	kind NatsMonitoringInstrumentKind,
	labelKeys []string,
	sourceSubjects []string,
	failureBehavior string,
) (*NatsMonitoringInstrument, error) {
	validated, err := natsMonitoringInstrumentValidateName(name)
	if err != nil {
		return nil, err
	}

	for _, key := range labelKeys {
		if !NatsMonitoringLabels.IsAllowedLabelKey(key) {
			return nil, fmt.Errorf(
				"The instrument '%s' uses the unbounded label key '%s'.", name, key)
		}
	}

	seen := map[string]struct{}{}
	for _, key := range labelKeys {
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("An instrument may not repeat a label key.")
		}

		seen[key] = struct{}{}
	}

	return &NatsMonitoringInstrument{
		Name:            validated,
		Unit:            unit,
		Kind:            kind,
		LabelKeys:       append([]string(nil), labelKeys...),
		SourceSubjects:  append([]string(nil), sourceSubjects...),
		FailureBehavior: failureBehavior,
	}, nil
}

func natsMonitoringInstrumentValidateName(name string) (string, error) {
	if len(name) == 0 ||
		!strings.HasPrefix(name, "terrascale.orchestrator.nats.") {
		return "", errors.New("A NATS monitoring instrument name must be rooted and bounded.")
	}

	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' || character == '.' || character == '_' {
			continue
		}

		return "", errors.New("A NATS monitoring instrument name must be rooted and bounded.")
	}

	return name, nil
}

// NatsMonitoringLabels mirrors the C# static class: the closed set of label
// keys NATS monitoring may use.
var NatsMonitoringLabels natsMonitoringLabels

type natsMonitoringLabels struct{}

// AllowedKeys mirrors the C# AllowedKeys.
func (natsMonitoringLabels) AllowedKeys() []string {
	return []string{
		"terrascale.cell",
		"plane",
		"cluster_role",
		"service",
		"endpoint",
		"stream_class",
		"consumer_class",
		"store_class",
		"certificate_class",
		"result",
		"state",
		"condition",
		"outcome",
	}
}

// ForbiddenKeyFragments mirrors the C# ForbiddenKeyFragments.
func (natsMonitoringLabels) ForbiddenKeyFragments() []string {
	return []string{
		"instance",
		"session",
		"nkey",
		"message",
		"operation",
		"consumer_name",
		"stream_name",
		"cid",
		"subject",
	}
}

// IsAllowedLabelKey mirrors the C# IsAllowedLabelKey.
func (natsMonitoringLabels) IsAllowedLabelKey(key string) bool {
	for _, allowed := range NatsMonitoringLabels.AllowedKeys() {
		if allowed == key {
			return true
		}
	}

	return false
}

// Plane mirrors the C# Plane.
func (natsMonitoringLabels) Plane(plane NatsMonitoringPlane) string {
	switch plane {
	case NatsMonitoringPlaneControl:
		return "control"
	case NatsMonitoringPlaneProduct:
		return "product"
	default:
		panic("Specified argument was out of the range of valid values. (Parameter 'plane')")
	}
}

// ClusterRole mirrors the C# ClusterRole.
func (natsMonitoringLabels) ClusterRole(role NatsClusterRole) string {
	switch role {
	case NatsClusterRoleRegional:
		return "regional"
	case NatsClusterRoleGlobalAuthority:
		return "global-authority"
	default:
		panic("Specified argument was out of range of valid values. (Parameter 'role')")
	}
}

// StreamClass mirrors the C# StreamClass.
func (natsMonitoringLabels) StreamClass(streamClass NatsStreamClass) string {
	return strings.ToLower(streamClass.String())
}

// ConsumerClass mirrors the C# ConsumerClass.
func (natsMonitoringLabels) ConsumerClass(consumerClass NatsConsumerClass) string {
	return strings.ToLower(consumerClass.String())
}

// StoreClass mirrors the C# StoreClass.
func (natsMonitoringLabels) StoreClass(storeClass NatsStoreClass) string {
	return strings.ToLower(storeClass.String())
}

// CertificateClass mirrors the C# CertificateClass.
func (natsMonitoringLabels) CertificateClass(certificateClass NatsCertificateClass) string {
	return strings.ToLower(certificateClass.String())
}

// Availability mirrors the C# Availability.
func (natsMonitoringLabels) Availability(availability NatsMonitoringAvailability) string {
	switch availability {
	case NatsMonitoringAvailabilityAvailable:
		return "available"
	case NatsMonitoringAvailabilityDegraded:
		return "degraded"
	case NatsMonitoringAvailabilityUnavailable:
		return "unavailable"
	default:
		panic("Specified argument was out of range of valid values. (Parameter 'availability')")
	}
}

// MeshState mirrors the C# MeshState.
func (natsMonitoringLabels) MeshState(state NatsMeshCellState) string {
	return strings.ToLower(state.String())
}

func natsMonitoringInstrument(
	name string,
	unit string,
	kind NatsMonitoringInstrumentKind,
	labelKeys []string,
	sourceSubjects []string,
	failureBehavior string,
) NatsMonitoringInstrument {
	instrument, err := NewNatsMonitoringInstrument(
		name, unit, kind, labelKeys, sourceSubjects, failureBehavior)
	if err != nil {
		panic(err)
	}

	return *instrument
}

// NatsMonitoringInstrumentCatalog mirrors the C# static class: the canonical
// NATS monitoring instrument catalog.
var NatsMonitoringInstrumentCatalog natsMonitoringInstrumentCatalog

type natsMonitoringInstrumentCatalog struct{}

var (
	natsMonitoringServiceRequestLabels  = []string{"service", "endpoint", "result"}
	natsMonitoringScopeLabels           = []string{"terrascale.cell", "plane"}
	natsMonitoringInstrumentsOnce       sync.Once
	natsMonitoringInstrumentsCollection []NatsMonitoringInstrument
)

// natsSubjectTaxonomyGlobalDirectoryQuerySubject re-exports the protocol
// taxonomy subject used by the mesh.cells catalog entry.
var natsSubjectTaxonomyGlobalDirectoryQuerySubject = protocol.NatsSubjectTaxonomy.GlobalDirectoryQuerySubject()

func natsMonitoringInstruments() []NatsMonitoringInstrument {
	natsMonitoringInstrumentsOnce.Do(func() {
		natsMonitoringInstrumentsCollection = []NatsMonitoringInstrument{
			natsMonitoringInstrument("terrascale.orchestrator.nats.service.requests", "{request}",
				NatsMonitoringInstrumentKindCounter, natsMonitoringServiceRequestLabels, []string{},
				"Absent until the first request; the controller's own service endpoints never depend on it."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.service.errors", "{error}",
				NatsMonitoringInstrumentKindCounter, natsMonitoringServiceRequestLabels, []string{},
				"Absent until the first error; errors never suppress the endpoint itself."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.service.request.duration", "ms",
				NatsMonitoringInstrumentKindHistogram, natsMonitoringServiceRequestLabels, []string{},
				"Absent until the first request; latency is also served by the read-only stats service endpoint."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.client.reconnects", "{reconnect}",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsConnections},
				"Holds the last observed value; supervision marks the availability gauge degraded or unavailable instead of guessing."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.connections", "{connection}",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsConnections},
				"Holds the last observed value while degraded; disappears when unavailable."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.routes", "{route}",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsRoutes},
				"Holds the last observed value while degraded; disappears when unavailable."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.gateways", "{gateway}",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "state"},
				[]string{NatsMonitoringSubjectsGateways},
				"Disconnected counts keep updating; a fully unreachable server freezes the last mesh observation and marks availability degraded."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.accounts", "{account}",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsAccounts},
				"Holds the last observed value while degraded; disappears when unavailable."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.jetstream.domains", "{domain}",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed value while degraded; disappears when unavailable."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.streams", "{stream}",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "stream_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Per-class counts disappear for classes that stop reporting; the total is never interpolated."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.consumers", "{consumer}",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "stream_class", "consumer_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Per-class counts disappear for classes that stop reporting."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.consumer.lag", "{message}",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "stream_class", "consumer_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed lag; a monitoring outage never fabricates zero lag."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.consumer.redelivered", "{message}",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "stream_class", "consumer_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed count; never reset by a monitoring restart."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.consumer.ack_pending", "{message}",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "stream_class", "consumer_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed count; never reset by a monitoring restart."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.flowcontrol.waiting", "{consumer}",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "stream_class", "consumer_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed count; pressure alerts treat a stale gauge as unknown, not zero."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.messages", "{message}",
				NatsMonitoringInstrumentKindCounter,
				[]string{"terrascale.cell", "plane", "stream_class", "consumer_class", "result"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Monotone delivery/redelivery/duplicate deltas between observations; an observation gap pauses the counter without backfill."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.stream.bytes", "By",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "stream_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Per-class bytes disappear for classes that stop reporting."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.stream.duplicates", "{message}",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "stream_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Application-level message-ID deduplication counts; absent when no deduplication ran."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.kv.watches", "{watch}",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "store_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed value while degraded."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.objectstore.objects", "{object}",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "store_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed value while degraded."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.objectstore.bytes", "By",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "store_class"},
				[]string{NatsMonitoringSubjectsJetStream},
				"Holds the last observed value while degraded."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.server.memory", "By",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsServer},
				"Holds the last observed value while degraded; disappears when unavailable."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.storage.bytes", "By",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsServer, NatsMonitoringSubjectsJetStream},
				"Holds the last observed value while degraded; disappears when unavailable."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.partition.duration", "ms",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsGateways},
				"Zero while connected; grows while the mesh reports a full gateway partition; resets to zero on recovery, which is the recovery-duration signal."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.recovery.duration", "ms",
				NatsMonitoringInstrumentKindGauge, natsMonitoringScopeLabels,
				[]string{NatsMonitoringSubjectsGateways},
				"Holds the last completed recovery duration; zero before the first recovery."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.certificate.expiry.days", "d",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "certificate_class"}, []string{},
				"Sourced from the monitoring identity's own credentials and rendered server configuration; missing certificates are absent, not zero."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.monitoring.availability", "{boolean}",
				NatsMonitoringInstrumentKindGauge,
				[]string{"terrascale.cell", "plane", "condition"}, []string{},
				"The truthful self-report: available, degraded, or unavailable. This is the only signal guaranteed to exist."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.mesh.cells", "{cell}",
				NatsMonitoringInstrumentKindGauge, []string{"terrascale.cell", "plane", "state"},
				[]string{natsSubjectTaxonomyGlobalDirectoryQuerySubject},
				"Mesh states compose the landed directory and membership aggregates plus gateway links; a lost directory degrades to disconnected or stale, never fabricated health."),
			natsMonitoringInstrument("terrascale.orchestrator.nats.advisories", "{advisory}",
				NatsMonitoringInstrumentKindCounter, []string{"terrascale.cell", "plane", "result"},
				[]string{NatsMonitoringSubjectsAccountAdvisories, NatsMonitoringSubjectsJetStreamAdvisories},
				"Advisory loss pauses the counter and degrades availability; it never fabricates counts and never affects control."),
		}
	})

	return natsMonitoringInstrumentsCollection
}

// Instruments mirrors the C# Instruments property.
func (natsMonitoringInstrumentCatalog) Instruments() []NatsMonitoringInstrument {
	return natsMonitoringInstruments()
}

// Require mirrors the C# Require.
func (natsMonitoringInstrumentCatalog) Require(name string) (NatsMonitoringInstrument, error) {
	for _, instrument := range natsMonitoringInstruments() {
		if instrument.Name == name {
			return instrument, nil
		}
	}

	return NatsMonitoringInstrument{}, fmt.Errorf(
		"The NATS monitoring instrument '%s' is not cataloged.", name)
}

// NatsMonitoringAlertRule mirrors the C# record: a typed alert-rule
// descriptor tied to canonical failure and recovery states.
type NatsMonitoringAlertRule struct {
	Id              string
	Description     string
	Severity        NatsMonitoringAlertSeverity
	InstrumentNames []string
	FiresWhen       string
	RecoveryWhen    string
	Runbook         string
}

// NewNatsMonitoringAlertRule mirrors the C# constructor.
func NewNatsMonitoringAlertRule(
	id string,
	description string,
	severity NatsMonitoringAlertSeverity,
	instrumentNames []string,
	firesWhen string,
	recoveryWhen string,
	runbook string,
) (*NatsMonitoringAlertRule, error) {
	for _, name := range instrumentNames {
		if _, err := NatsMonitoringInstrumentCatalog.Require(name); err != nil {
			return nil, err
		}
	}

	if len(instrumentNames) == 0 {
		return nil, errors.New("An alert rule must reference at least one instrument.")
	}

	seen := map[string]struct{}{}
	for _, name := range instrumentNames {
		if _, duplicate := seen[name]; duplicate {
			return nil, errors.New("An alert rule may not repeat an instrument.")
		}

		seen[name] = struct{}{}
	}

	return &NatsMonitoringAlertRule{
		Id:              id,
		Description:     description,
		Severity:        severity,
		InstrumentNames: append([]string(nil), instrumentNames...),
		FiresWhen:       firesWhen,
		RecoveryWhen:    recoveryWhen,
		Runbook:         runbook,
	}, nil
}

// NatsAlertCatalog mirrors the C# static class: actionable NATS alert
// conditions, each bound to catalog instruments.
var NatsAlertCatalog natsAlertCatalog

type natsAlertCatalog struct{}

// Rules mirrors the C# Rules.
func (natsAlertCatalog) Rules() []NatsMonitoringAlertRule {
	constructed := []NatsMonitoringAlertRule{
		natsAlertRule("nats.gateway.partition",
			"A cell's gateway links are all down: the region is isolated from the mesh and must run on regional autonomy.",
			NatsMonitoringAlertSeverityCritical,
			[]string{
				"terrascale.orchestrator.nats.partition.duration",
				"terrascale.orchestrator.nats.mesh.cells",
			},
			"partition duration > 0 for more than 30s and mesh state disconnected for that cell",
			"partition duration returns to 0 and mesh state is healthy or stale",
			"runbooks/nats-gateway-operations.md"),
		natsAlertRule("nats.gateway.recovery.slow",
			"A healed gateway partition did not reconverge within the recovery window.",
			NatsMonitoringAlertSeverityWarning,
			[]string{"terrascale.orchestrator.nats.recovery.duration"},
			"recovery duration exceeds 30s after links report connected",
			"recovery duration falls below 30s and mesh state is healthy",
			"runbooks/nats-gateway-operations.md"),
		natsAlertRule("nats.consumer.lag",
			"Consumer lag is growing for a stream class.",
			NatsMonitoringAlertSeverityWarning,
			[]string{"terrascale.orchestrator.nats.consumer.lag"},
			"lag > 1000 {message} for 2 minutes on any stream/consumer class",
			"lag < 100 {message} for 5 minutes",
			"runbooks/nats-monitoring.md"),
		natsAlertRule("nats.consumer.redelivery.storm",
			"Redeliveries dominate deliveries for a consumer class.",
			NatsMonitoringAlertSeverityWarning,
			[]string{
				"terrascale.orchestrator.nats.consumer.redelivered",
				"terrascale.orchestrator.nats.messages",
			},
			"redelivered grows faster than deliveries for 5 minutes",
			"redelivery delta returns to zero for 5 minutes",
			"runbooks/nats-monitoring.md"),
		natsAlertRule("nats.flowcontrol.pressure",
			"Consumers are not keeping up and are holding the stream back via flow control.",
			NatsMonitoringAlertSeverityWarning,
			[]string{"terrascale.orchestrator.nats.flowcontrol.waiting"},
			"waiting > 0 for 5 minutes on any consumer class",
			"waiting == 0 for 5 minutes",
			"runbooks/nats-monitoring.md"),
		natsAlertRule("nats.storage.pressure",
			"JetStream storage is approaching its declared limit.",
			NatsMonitoringAlertSeverityWarning,
			[]string{
				"terrascale.orchestrator.nats.storage.bytes",
				"terrascale.orchestrator.nats.stream.bytes",
			},
			"storage bytes exceed 80% of the topology-declared limit for 10 minutes",
			"storage bytes fall below 70% of the declared limit",
			"runbooks/nats-monitoring.md"),
		natsAlertRule("nats.server.memory.pressure",
			"Server process memory is rising toward the container limit.",
			NatsMonitoringAlertSeverityWarning,
			[]string{"terrascale.orchestrator.nats.server.memory"},
			"memory exceeds 80% of the per-server container limit for 10 minutes",
			"memory falls below 70% of the container limit",
			"runbooks/nats-monitoring.md"),
		natsAlertRule("nats.certificate.expiry.risk",
			"A TLS certificate inside the NATS plane expires soon.",
			NatsMonitoringAlertSeverityCritical,
			[]string{"terrascale.orchestrator.nats.certificate.expiry.days"},
			"remaining days < 30 for any certificate class",
			"certificate is rotated and remaining days > 30",
			"runbooks/nats-gateway-operations.md"),
		natsAlertRule("nats.advisory.slow.consumer",
			"The server reports slow consumers.",
			NatsMonitoringAlertSeverityWarning,
			[]string{"terrascale.orchestrator.nats.advisories"},
			"slow-consumer advisory count increases",
			"no new slow-consumer advisories for 15 minutes",
			"runbooks/nats-monitoring.md"),
		natsAlertRule("nats.advisory.leader.change",
			"A JetStream or authority leader changed — check for quorum loss.",
			NatsMonitoringAlertSeverityCritical,
			[]string{
				"terrascale.orchestrator.nats.advisories",
				"terrascale.orchestrator.nats.mesh.cells",
			},
			"leader-change advisory count increases and mesh state degrades",
			"mesh state returns to healthy with a stable leader",
			"runbooks/nats-gateway-operations.md"),
		natsAlertRule("nats.mesh.conflicting",
			"A cell reports conflicting controller sessions.",
			NatsMonitoringAlertSeverityCritical,
			[]string{"terrascale.orchestrator.nats.mesh.cells"},
			"mesh state conflicting for any cell",
			"mesh state returns to healthy after the conflict resolves on renewal",
			"runbooks/nats-gateway-operations.md"),
		natsAlertRule("nats.monitoring.unavailable",
			"NATS observability itself is blind: the last signal is too old to trust.",
			NatsMonitoringAlertSeverityWarning,
			[]string{"terrascale.orchestrator.nats.monitoring.availability"},
			"availability condition is unavailable for 2 minutes",
			"availability condition returns to available",
			"runbooks/nats-monitoring.md"),
	}

	return constructed
}

func natsAlertRule(
	id string,
	description string,
	severity NatsMonitoringAlertSeverity,
	instrumentNames []string,
	firesWhen string,
	recoveryWhen string,
	runbook string,
) NatsMonitoringAlertRule {
	rule, err := NewNatsMonitoringAlertRule(
		id, description, severity, instrumentNames, firesWhen, recoveryWhen, runbook)
	if err != nil {
		panic(err)
	}

	return *rule
}

// NatsMonitoringSnapshotEntryMaximumLabelValueLength mirrors the C# constant:
// the label-value length cap (a cell token, bounded at 63 characters).
const NatsMonitoringSnapshotEntryMaximumLabelValueLength = 63

// NatsMonitoringSnapshotEntry mirrors the C# record: one typed metric snapshot
// entry the Grafana/Prometheus-facing projection serves. JSON tags mirror the
// C# source-generated context (default options: PascalCase names).
type NatsMonitoringSnapshotEntry struct {
	Instrument string            `json:"Instrument"`
	Unit       string            `json:"Unit"`
	Labels     map[string]string `json:"Labels"`
	Value      float64           `json:"Value"`
}

// NewNatsMonitoringSnapshotEntry mirrors the C# constructor.
func NewNatsMonitoringSnapshotEntry(
	instrument string,
	unit string,
	labels map[string]string,
	value float64,
) (*NatsMonitoringSnapshotEntry, error) {
	cataloged, err := NatsMonitoringInstrumentCatalog.Require(instrument)
	if err != nil {
		return nil, err
	}

	bounded := map[string]string{}
	for key, labelValue := range labels {
		if !NatsMonitoringLabels.IsAllowedLabelKey(key) {
			return nil, fmt.Errorf(
				"The snapshot entry uses the unbounded label key '%s'.", key)
		}

		if len(labelValue) > NatsMonitoringSnapshotEntryMaximumLabelValueLength {
			return nil, errors.New("A snapshot label value exceeds the bounded length.")
		}

		bounded[key] = labelValue
	}

	return &NatsMonitoringSnapshotEntry{
		Instrument: cataloged.Name,
		Unit:       unit,
		Labels:     bounded,
		Value:      value,
	}, nil
}

// NatsMonitoringSnapshotCurrentSchemaVersion mirrors the C# constant.
const NatsMonitoringSnapshotCurrentSchemaVersion = 1

// NatsMonitoringSnapshot mirrors the C# record.
type NatsMonitoringSnapshot struct {
	SchemaVersion int                             `json:"SchemaVersion"`
	Cell          string                          `json:"Cell"`
	ObservedAt    time.Time                       `json:"ObservedAt"`
	Availability  NatsMonitoringAvailability      `json:"Availability"`
	Entries       []NatsMonitoringSnapshotEntry   `json:"Entries"`
}

// NatsMonitoringSnapshotFrom mirrors the static From: projects the bounded
// aggregate into the dashboard-facing snapshot — one entry per instrument
// series the current aggregate can truthfully support. Series whose source did
// not report are omitted, never zero-filled.
func NatsMonitoringSnapshotFrom(aggregate NatsMonitoringAggregate) (*NatsMonitoringSnapshot, error) {
	if err := aggregate.Validate(); err != nil {
		return nil, err
	}

	entries := []NatsMonitoringSnapshotEntry{}
	scope := map[string]string{
		"terrascale.cell": aggregate.Cell,
		"plane":           NatsMonitoringLabels.Plane(aggregate.Plane),
	}

	gauge := func(instrument string, value float64, labels map[string]string) {
		catalog, err := NatsMonitoringInstrumentCatalog.Require(instrument)
		if err != nil {
			panic(err)
		}

		merged := map[string]string{}
		for key, labelValue := range scope {
			merged[key] = labelValue
		}

		for key, labelValue := range labels {
			merged[key] = labelValue
		}

		entry, err := NewNatsMonitoringSnapshotEntry(catalog.Name, catalog.Unit, merged, value)
		if err != nil {
			panic(err)
		}

		entries = append(entries, *entry)
	}

	availabilityValue := float64(-1)
	switch aggregate.Availability {
	case NatsMonitoringAvailabilityAvailable:
		availabilityValue = 1
	case NatsMonitoringAvailabilityDegraded:
		availabilityValue = 0
	}

	gauge("terrascale.orchestrator.nats.monitoring.availability", availabilityValue,
		map[string]string{"condition": NatsMonitoringLabels.Availability(aggregate.Availability)})
	if aggregate.Availability == NatsMonitoringAvailabilityUnavailable {
		snapshot := &NatsMonitoringSnapshot{
			SchemaVersion: NatsMonitoringSnapshotCurrentSchemaVersion,
			Cell:          aggregate.Cell,
			ObservedAt:    aggregate.ObservedAt,
			Availability:  aggregate.Availability,
			Entries:       entries,
		}

		if err := snapshot.Validate(); err != nil {
			return nil, err
		}

		return snapshot, nil
	}

	gauge("terrascale.orchestrator.nats.connections", float64(aggregate.Connections), nil)
	gauge("terrascale.orchestrator.nats.client.reconnects", float64(aggregate.Reconnects), nil)
	gauge("terrascale.orchestrator.nats.routes", float64(aggregate.Routes), nil)
	gauge("terrascale.orchestrator.nats.accounts", float64(aggregate.Accounts), nil)
	gauge("terrascale.orchestrator.nats.jetstream.domains", float64(aggregate.JetStreamDomains), nil)
	gauge("terrascale.orchestrator.nats.server.memory", float64(aggregate.ServerMemoryBytes), nil)
	gauge("terrascale.orchestrator.nats.storage.bytes", float64(aggregate.JetStreamStorageBytes), nil)
	gauge("terrascale.orchestrator.nats.partition.duration",
		float64(aggregate.PartitionDurationMilliseconds), nil)
	gauge("terrascale.orchestrator.nats.recovery.duration",
		float64(aggregate.RecoveryDurationMilliseconds), nil)
	gauge("terrascale.orchestrator.nats.gateways", float64(aggregate.GatewaysConnected),
		map[string]string{"state": "connected"})
	gauge("terrascale.orchestrator.nats.gateways", float64(aggregate.GatewaysDisconnected),
		map[string]string{"state": "disconnected"})

	meshGroups := []struct {
		count int
		state NatsMeshCellState
	}{
		{aggregate.Mesh.HealthyCells(), NatsMeshCellStateHealthy},
		{aggregate.Mesh.StaleCells(), NatsMeshCellStateStale},
		{aggregate.Mesh.MissingCells(), NatsMeshCellStateMissing},
		{aggregate.Mesh.ConflictingCells(), NatsMeshCellStateConflicting},
		{aggregate.Mesh.DisconnectedCells(), NatsMeshCellStateDisconnected},
	}
	for _, group := range meshGroups {
		gauge("terrascale.orchestrator.nats.mesh.cells", float64(group.count),
			map[string]string{"state": NatsMonitoringLabels.MeshState(group.state)})
	}

	for _, stream := range aggregate.StreamsByClass {
		labels := map[string]string{
			"stream_class": NatsMonitoringLabels.StreamClass(stream.StreamClass),
		}
		gauge("terrascale.orchestrator.nats.streams", float64(stream.Streams), labels)
		gauge("terrascale.orchestrator.nats.stream.bytes", float64(stream.Bytes), labels)
		gauge("terrascale.orchestrator.nats.stream.duplicates", float64(stream.Duplicates), labels)
	}

	for _, consumer := range aggregate.ConsumersByClass {
		labels := map[string]string{
			"stream_class":   NatsMonitoringLabels.StreamClass(consumer.StreamClass),
			"consumer_class": NatsMonitoringLabels.ConsumerClass(consumer.ConsumerClass),
		}
		gauge("terrascale.orchestrator.nats.consumers", float64(consumer.Consumers), labels)
		gauge("terrascale.orchestrator.nats.consumer.lag", float64(consumer.Lag), labels)
		gauge("terrascale.orchestrator.nats.consumer.redelivered", float64(consumer.Redelivered), labels)
		gauge("terrascale.orchestrator.nats.consumer.ack_pending", float64(consumer.AckPending), labels)
		gauge("terrascale.orchestrator.nats.flowcontrol.waiting", float64(consumer.Waiting), labels)
	}

	for _, store := range aggregate.StoresByClass {
		labels := map[string]string{
			"store_class": NatsMonitoringLabels.StoreClass(store.StoreClass),
		}
		gauge("terrascale.orchestrator.nats.kv.watches", float64(store.Watches), labels)
		gauge("terrascale.orchestrator.nats.objectstore.objects", float64(store.Objects), labels)
		gauge("terrascale.orchestrator.nats.objectstore.bytes", float64(store.Bytes), labels)
	}

	for _, certificate := range aggregate.Certificates {
		gauge("terrascale.orchestrator.nats.certificate.expiry.days",
			float64(certificate.RemainingDays(aggregate.ObservedAt)),
			map[string]string{
				"certificate_class": NatsMonitoringLabels.CertificateClass(certificate.CertificateClass),
			})
	}

	snapshot := &NatsMonitoringSnapshot{
		SchemaVersion: NatsMonitoringSnapshotCurrentSchemaVersion,
		Cell:          aggregate.Cell,
		ObservedAt:    aggregate.ObservedAt,
		Availability:  aggregate.Availability,
		Entries:       entries,
	}

	if err := snapshot.Validate(); err != nil {
		return nil, err
	}

	return snapshot, nil
}

// Validate mirrors the C# Validate.
func (s *NatsMonitoringSnapshot) Validate() error {
	if s.SchemaVersion != NatsMonitoringSnapshotCurrentSchemaVersion ||
		!messagingCellTokenIsValid(s.Cell) || s.ObservedAt.IsZero() ||
		s.Availability < NatsMonitoringAvailabilityAvailable ||
		s.Availability > NatsMonitoringAvailabilityUnavailable {
		return errors.New("The NATS monitoring snapshot is invalid.")
	}

	seen := map[string]struct{}{}
	for _, entry := range s.Entries {
		identity := entry.Instrument + "|" + natsMonitoringLabelsIdentity(entry.Labels)
		if _, duplicate := seen[identity]; duplicate {
			return errors.New("The NATS monitoring snapshot is invalid.")
		}

		seen[identity] = struct{}{}

		for _, labelValue := range entry.Labels {
			if len(labelValue) > NatsMonitoringSnapshotEntryMaximumLabelValueLength {
				return errors.New(
					"The NATS monitoring snapshot contains an unbounded label value.")
			}
		}
	}

	return nil
}

func natsMonitoringLabelsIdentity(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for key, value := range labels {
		parts = append(parts, key+"="+value)
	}

	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// RenderPrometheus mirrors the C# RenderPrometheus: Prometheus text exposition
// with unit-suffixed names and sorted labels.
func (s *NatsMonitoringSnapshot) RenderPrometheus() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}

	byInstrument := map[string][]NatsMonitoringSnapshotEntry{}
	for _, entry := range s.Entries {
		byInstrument[entry.Instrument] = append(byInstrument[entry.Instrument], entry)
	}

	instrumentNames := make([]string, 0, len(byInstrument))
	for name := range byInstrument {
		instrumentNames = append(instrumentNames, name)
	}
	sort.Strings(instrumentNames)

	lines := make([]string, 0, len(s.Entries)*2)
	for _, name := range instrumentNames {
		instrument, err := NatsMonitoringInstrumentCatalog.Require(name)
		if err != nil {
			return "", err
		}

		lines = append(lines, fmt.Sprintf("# unit %s source %s failure %s",
			instrument.Unit,
			strings.Join(instrument.SourceSubjects, ","),
			instrument.FailureBehavior))

		entries := byInstrument[name]
		sort.Slice(entries, func(i, j int) bool {
			return natsMonitoringLabelsIdentity(entries[i].Labels) <
				natsMonitoringLabelsIdentity(entries[j].Labels)
		})

		for _, entry := range entries {
			keys := make([]string, 0, len(entry.Labels))
			for key := range entry.Labels {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			labelParts := make([]string, 0, len(keys))
			for _, key := range keys {
				labelParts = append(labelParts,
					fmt.Sprintf("%s=\"%s\"", key, natsMonitoringEscapeLabelValue(entry.Labels[key])))
			}

			labels := strings.Join(labelParts, ",")
			if len(labels) == 0 {
				lines = append(lines, fmt.Sprintf("%s %v", entry.Instrument, entry.Value))
			} else {
				lines = append(lines, fmt.Sprintf("%s{%s} %v", entry.Instrument, labels, entry.Value))
			}
		}
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// natsMonitoringEscapeLabelValue mirrors the C# EscapeLabelValue: backslash,
// double quote, and newline are the three characters the format requires to be
// escaped inside a quoted label value.
func natsMonitoringEscapeLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}
