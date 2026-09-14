package monitoring

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/membership"
)

// NatsMonitoringPlane mirrors the C# enum.
type NatsMonitoringPlane int

const (
	NatsMonitoringPlaneControl NatsMonitoringPlane = 1
	NatsMonitoringPlaneProduct NatsMonitoringPlane = 2
)

func (p NatsMonitoringPlane) String() string {
	switch p {
	case NatsMonitoringPlaneControl:
		return "Control"
	case NatsMonitoringPlaneProduct:
		return "Product"
	default:
		return strconv.Itoa(int(p))
	}
}

// NatsClusterRole mirrors the C# enum.
type NatsClusterRole int

const (
	NatsClusterRoleRegional        NatsClusterRole = 1
	NatsClusterRoleGlobalAuthority NatsClusterRole = 2
)

func (r NatsClusterRole) String() string {
	switch r {
	case NatsClusterRoleRegional:
		return "Regional"
	case NatsClusterRoleGlobalAuthority:
		return "GlobalAuthority"
	default:
		return strconv.Itoa(int(r))
	}
}

// NatsStreamClass mirrors the C# enum: bounded classification of an observed
// JetStream stream. Class — never a stream name — is the metric label.
type NatsStreamClass int

const (
	NatsStreamClassCellSpec       NatsStreamClass = 1
	NatsStreamClassCellOperations NatsStreamClass = 2
	NatsStreamClassCellEvents     NatsStreamClass = 3
	NatsStreamClassGlobalSpec     NatsStreamClass = 4
	NatsStreamClassGlobalCi       NatsStreamClass = 5
	NatsStreamClassKeyValue       NatsStreamClass = 6
	NatsStreamClassObjectStore    NatsStreamClass = 7
	NatsStreamClassUnknown        NatsStreamClass = 8
)

func (c NatsStreamClass) String() string {
	switch c {
	case NatsStreamClassCellSpec:
		return "CellSpec"
	case NatsStreamClassCellOperations:
		return "CellOperations"
	case NatsStreamClassCellEvents:
		return "CellEvents"
	case NatsStreamClassGlobalSpec:
		return "GlobalSpec"
	case NatsStreamClassGlobalCi:
		return "GlobalCi"
	case NatsStreamClassKeyValue:
		return "KeyValue"
	case NatsStreamClassObjectStore:
		return "ObjectStore"
	case NatsStreamClassUnknown:
		return "Unknown"
	default:
		return strconv.Itoa(int(c))
	}
}

// NatsConsumerClass mirrors the C# enum.
type NatsConsumerClass int

const (
	NatsConsumerClassStartupEvent   NatsConsumerClass = 1
	NatsConsumerClassCellSpec       NatsConsumerClass = 2
	NatsConsumerClassGlobalCi       NatsConsumerClass = 3
	NatsConsumerClassEphemeralWatch NatsConsumerClass = 4
	NatsConsumerClassUnknown        NatsConsumerClass = 5
)

func (c NatsConsumerClass) String() string {
	switch c {
	case NatsConsumerClassStartupEvent:
		return "StartupEvent"
	case NatsConsumerClassCellSpec:
		return "CellSpec"
	case NatsConsumerClassGlobalCi:
		return "GlobalCi"
	case NatsConsumerClassEphemeralWatch:
		return "EphemeralWatch"
	case NatsConsumerClassUnknown:
		return "Unknown"
	default:
		return strconv.Itoa(int(c))
	}
}

// NatsStoreClass mirrors the C# enum.
type NatsStoreClass int

const (
	NatsStoreClassKeyValue    NatsStoreClass = 1
	NatsStoreClassObjectStore NatsStoreClass = 2
)

func (c NatsStoreClass) String() string {
	switch c {
	case NatsStoreClassKeyValue:
		return "KeyValue"
	case NatsStoreClassObjectStore:
		return "ObjectStore"
	default:
		return strconv.Itoa(int(c))
	}
}

// NatsCertificateClass mirrors the C# enum.
type NatsCertificateClass int

const (
	NatsCertificateClassServerListener   NatsCertificateClass = 1
	NatsCertificateClassGatewayLink      NatsCertificateClass = 2
	NatsCertificateClassMonitoringClient NatsCertificateClass = 3
)

func (c NatsCertificateClass) String() string {
	switch c {
	case NatsCertificateClassServerListener:
		return "ServerListener"
	case NatsCertificateClassGatewayLink:
		return "GatewayLink"
	case NatsCertificateClassMonitoringClient:
		return "MonitoringClient"
	default:
		return strconv.Itoa(int(c))
	}
}

// NatsAdvisoryKind mirrors the C# enum: unknown kinds are counted as
// unclassified, never dropped silently.
type NatsAdvisoryKind int

const (
	NatsAdvisoryKindSlowConsumer          NatsAdvisoryKind = 1
	NatsAdvisoryKindLeaderChange          NatsAdvisoryKind = 2
	NatsAdvisoryKindAuthenticationFailure NatsAdvisoryKind = 3
	NatsAdvisoryKindMaxDeliveries         NatsAdvisoryKind = 4
	NatsAdvisoryKindResourceExhausted     NatsAdvisoryKind = 5
	NatsAdvisoryKindUnclassified          NatsAdvisoryKind = 6
)

func (k NatsAdvisoryKind) String() string {
	switch k {
	case NatsAdvisoryKindSlowConsumer:
		return "SlowConsumer"
	case NatsAdvisoryKindLeaderChange:
		return "LeaderChange"
	case NatsAdvisoryKindAuthenticationFailure:
		return "AuthenticationFailure"
	case NatsAdvisoryKindMaxDeliveries:
		return "MaxDeliveries"
	case NatsAdvisoryKindResourceExhausted:
		return "ResourceExhausted"
	case NatsAdvisoryKindUnclassified:
		return "Unclassified"
	default:
		return strconv.Itoa(int(k))
	}
}

// NatsConnectionsObservation mirrors the C# record.
type NatsConnectionsObservation struct {
	SchemaVersion int
	Cell          string
	Plane         NatsMonitoringPlane
	Connections   int64
	Reconnects    int64
	ObservedAt    time.Time
}

// NatsConnectionsObserve mirrors the static Observe.
func NatsConnectionsObserve(
	cell string,
	plane NatsMonitoringPlane,
	connections int64,
	reconnects int64,
	observedAt time.Time,
) NatsConnectionsObservation {
	return NatsConnectionsObservation{1, cell, plane, connections, reconnects, observedAt}
}

// Validate mirrors the C# Validate.
func (o NatsConnectionsObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.Connections < 0 || o.Reconnects < 0 || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS connections observation is invalid.")
	}

	return nil
}

// NatsRoutesObservation mirrors the C# record.
type NatsRoutesObservation struct {
	SchemaVersion int
	Cell          string
	Routes        int64
	ObservedAt    time.Time
}

// NatsRoutesObserve mirrors the static Observe.
func NatsRoutesObserve(cell string, routes int64, observedAt time.Time) NatsRoutesObservation {
	return NatsRoutesObservation{1, cell, routes, observedAt}
}

func (o NatsRoutesObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.Routes < 0 || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS routes observation is invalid.")
	}

	return nil
}

// NatsGatewaysObservation mirrors the C# record: aggregate observation of one
// server's outbound gateway links.
type NatsGatewaysObservation struct {
	SchemaVersion        int
	Cell                 string
	ConnectedGateways    int
	DisconnectedGateways int
	ObservedAt           time.Time
}

// NatsGatewaysObserve mirrors the static Observe.
func NatsGatewaysObserve(
	cell string,
	connected int,
	disconnected int,
	observedAt time.Time,
) NatsGatewaysObservation {
	return NatsGatewaysObservation{1, cell, connected, disconnected, observedAt}
}

// FullyDisconnected mirrors the C# property.
func (o NatsGatewaysObservation) FullyDisconnected() bool {
	return o.ConnectedGateways == 0 && o.DisconnectedGateways > 0
}

func (o NatsGatewaysObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.ConnectedGateways < 0 || o.DisconnectedGateways < 0 || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS gateways observation is invalid.")
	}

	return nil
}

// NatsAccountsObservation mirrors the C# record.
type NatsAccountsObservation struct {
	SchemaVersion int
	Cell          string
	Accounts      int64
	Connections   int64
	ObservedAt    time.Time
}

// NatsAccountsObserve mirrors the static Observe.
func NatsAccountsObserve(
	cell string,
	accounts int64,
	connections int64,
	observedAt time.Time,
) NatsAccountsObservation {
	return NatsAccountsObservation{1, cell, accounts, connections, observedAt}
}

func (o NatsAccountsObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.Accounts < 0 || o.Connections < 0 || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS accounts observation is invalid.")
	}

	return nil
}

// NatsJetStreamObservation mirrors the C# record.
type NatsJetStreamObservation struct {
	SchemaVersion int
	Cell          string
	Domains       int64
	Streams       int64
	Consumers     int64
	MemoryBytes   int64
	StorageBytes  int64
	ObservedAt    time.Time
}

// NatsJetStreamObserve mirrors the static Observe.
func NatsJetStreamObserve(
	cell string,
	domains int64,
	streams int64,
	consumers int64,
	memoryBytes int64,
	storageBytes int64,
	observedAt time.Time,
) NatsJetStreamObservation {
	return NatsJetStreamObservation{1, cell, domains, streams, consumers, memoryBytes, storageBytes, observedAt}
}

func (o NatsJetStreamObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.Domains < 0 || o.Streams < 0 || o.Consumers < 0 ||
		o.MemoryBytes < 0 || o.StorageBytes < 0 || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS JetStream observation is invalid.")
	}

	return nil
}

// NatsStreamClassState mirrors the C# record.
type NatsStreamClassState struct {
	StreamClass NatsStreamClass
	Streams     int64
	Messages    int64
	Bytes       int64
	Duplicates  int64
}

func (s NatsStreamClassState) Validate() error {
	if s.StreamClass < NatsStreamClassCellSpec || s.StreamClass > NatsStreamClassUnknown ||
		s.Streams < 0 || s.Messages < 0 || s.Bytes < 0 || s.Duplicates < 0 {
		return fmt.Errorf("The NATS stream class state is invalid.")
	}

	return nil
}

// NatsConsumerClassState mirrors the C# record: consumer identity (durable
// name, subject, session) is deliberately not representable here.
type NatsConsumerClassState struct {
	StreamClass   NatsStreamClass
	ConsumerClass NatsConsumerClass
	Consumers     int64
	Lag           int64
	Deliveries    int64
	Redelivered   int64
	AckPending    int64
	Waiting       int64
}

func (s NatsConsumerClassState) Validate() error {
	if s.StreamClass < NatsStreamClassCellSpec || s.StreamClass > NatsStreamClassUnknown ||
		s.ConsumerClass < NatsConsumerClassStartupEvent || s.ConsumerClass > NatsConsumerClassUnknown ||
		s.Consumers < 0 || s.Lag < 0 || s.Deliveries < 0 || s.Redelivered < 0 ||
		s.AckPending < 0 || s.Waiting < 0 {
		return fmt.Errorf("The NATS consumer class state is invalid.")
	}

	return nil
}

// NatsStoreClassState mirrors the C# record.
type NatsStoreClassState struct {
	StoreClass NatsStoreClass
	Buckets    int64
	Watches    int64
	Objects    int64
	Bytes      int64
}

func (s NatsStoreClassState) Validate() error {
	if s.StoreClass < NatsStoreClassKeyValue || s.StoreClass > NatsStoreClassObjectStore ||
		s.Buckets < 0 || s.Watches < 0 || s.Objects < 0 || s.Bytes < 0 {
		return fmt.Errorf("The NATS store class state is invalid.")
	}

	return nil
}

// NatsServerResourceObservation mirrors the C# record.
type NatsServerResourceObservation struct {
	SchemaVersion         int
	Cell                  string
	ServerMemoryBytes     int64
	JetStreamStorageBytes int64
	ObservedAt            time.Time
}

// NatsServerResourceObserve mirrors the static Observe.
func NatsServerResourceObserve(
	cell string,
	serverMemoryBytes int64,
	jetStreamStorageBytes int64,
	observedAt time.Time,
) NatsServerResourceObservation {
	return NatsServerResourceObservation{1, cell, serverMemoryBytes, jetStreamStorageBytes, observedAt}
}

func (o NatsServerResourceObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.ServerMemoryBytes < 0 || o.JetStreamStorageBytes < 0 || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS server resource observation is invalid.")
	}

	return nil
}

// NatsCertificateObservation mirrors the C# record.
type NatsCertificateObservation struct {
	SchemaVersion    int
	Cell             string
	CertificateClass NatsCertificateClass
	NotAfter         time.Time
	ObservedAt       time.Time
}

// NatsCertificateObserve mirrors the static Observe.
func NatsCertificateObserve(
	cell string,
	certificateClass NatsCertificateClass,
	notAfter time.Time,
	observedAt time.Time,
) NatsCertificateObservation {
	return NatsCertificateObservation{1, cell, certificateClass, notAfter, observedAt}
}

// RemainingDays mirrors the C# RemainingDays.
func (o NatsCertificateObservation) RemainingDays(now time.Time) int64 {
	if err := o.Validate(); err != nil {
		panic(err)
	}

	remaining := o.NotAfter.Sub(now)
	if remaining <= 0 {
		return 0
	}

	return int64(math.Ceil(remaining.Hours() / 24))
}

func (o NatsCertificateObservation) Validate() error {
	if o.SchemaVersion != 1 || !monitoringCellTokenIsValid(o.Cell) ||
		o.CertificateClass < NatsCertificateClassServerListener ||
		o.CertificateClass > NatsCertificateClassMonitoringClient ||
		o.NotAfter.IsZero() || o.ObservedAt.IsZero() {
		return fmt.Errorf("The NATS certificate observation is invalid.")
	}

	return nil
}

// NatsAdvisoryCount mirrors the C# record.
type NatsAdvisoryCount struct {
	Kind        NatsAdvisoryKind
	Occurrences int64
}

func (c NatsAdvisoryCount) Validate() error {
	if c.Kind < NatsAdvisoryKindSlowConsumer || c.Kind > NatsAdvisoryKindUnclassified ||
		c.Occurrences < 0 {
		return fmt.Errorf("The NATS advisory count is invalid.")
	}

	return nil
}

// NatsMeshCellState mirrors the C# enum.
type NatsMeshCellState int

const (
	NatsMeshCellStateHealthy      NatsMeshCellState = 1
	NatsMeshCellStateStale        NatsMeshCellState = 2
	NatsMeshCellStateMissing      NatsMeshCellState = 3
	NatsMeshCellStateConflicting  NatsMeshCellState = 4
	NatsMeshCellStateDisconnected NatsMeshCellState = 5
)

func (s NatsMeshCellState) String() string {
	switch s {
	case NatsMeshCellStateHealthy:
		return "Healthy"
	case NatsMeshCellStateStale:
		return "Stale"
	case NatsMeshCellStateMissing:
		return "Missing"
	case NatsMeshCellStateConflicting:
		return "Conflicting"
	case NatsMeshCellStateDisconnected:
		return "Disconnected"
	default:
		return strconv.Itoa(int(s))
	}
}

// NatsMeshCell mirrors the C# record.
type NatsMeshCell struct {
	Cell  string
	State NatsMeshCellState
}

func (c NatsMeshCell) Validate() error {
	if !monitoringCellTokenIsValid(c.Cell) ||
		c.State < NatsMeshCellStateHealthy || c.State > NatsMeshCellStateDisconnected {
		return fmt.Errorf("The NATS mesh cell state is invalid.")
	}

	return nil
}

// NatsMeshHealth mirrors the C# record: the aggregate mesh health.
type NatsMeshHealth struct {
	SchemaVersion int
	ObservedAt    time.Time
	Cells         []NatsMeshCell
}

// MeshDirectoryEntry is the bounded directory view needed to evaluate mesh
// health without depending on the control package.
type MeshDirectoryEntry struct {
	Cell                string
	LeaseExpiresAt      time.Time
	MembershipCondition membership.RegionalRuntimeMembershipCondition
}

// MeshDirectorySnapshot is the directory view consumed by monitoring.
type MeshDirectorySnapshot struct {
	Cells []MeshDirectoryEntry
}

// NatsMeshHealthCurrentSchemaVersion mirrors the C# constant.
const NatsMeshHealthCurrentSchemaVersion = 1

// Count mirrors the C# Count.
func (h NatsMeshHealth) Count(state NatsMeshCellState) int {
	count := 0
	for _, cell := range h.Cells {
		if cell.State == state {
			count++
		}
	}

	return count
}

func (h NatsMeshHealth) HealthyCells() int      { return h.Count(NatsMeshCellStateHealthy) }
func (h NatsMeshHealth) StaleCells() int        { return h.Count(NatsMeshCellStateStale) }
func (h NatsMeshHealth) MissingCells() int      { return h.Count(NatsMeshCellStateMissing) }
func (h NatsMeshHealth) ConflictingCells() int  { return h.Count(NatsMeshCellStateConflicting) }
func (h NatsMeshHealth) DisconnectedCells() int { return h.Count(NatsMeshCellStateDisconnected) }

// NatsMeshHealthEvaluate mirrors the static Evaluate: composes per-cell
// membership health and directory staleness with the gateway link
// observations.
func NatsMeshHealthEvaluate(
	expectedCells []string,
	membershipByCell map[string]membership.RegionalRuntimeMembershipHealth,
	directory MeshDirectorySnapshot,
	gatewaysByCell map[string]NatsGatewaysObservation,
	observedAt time.Time,
) (NatsMeshHealth, error) {
	distinct := map[string]struct{}{}
	for _, cell := range expectedCells {
		distinct[cell] = struct{}{}
	}

	ordered := make([]string, 0, len(distinct))
	for cell := range distinct {
		ordered = append(ordered, cell)
	}
	sort.Strings(ordered)

	cells := make([]NatsMeshCell, 0, len(ordered))
	for _, cell := range ordered {
		cells = append(cells, NatsMeshCell{
			Cell:  cell,
			State: natsMeshStateFor(cell, membershipByCell, directory, gatewaysByCell, observedAt),
		})
	}

	health := NatsMeshHealth{
		SchemaVersion: NatsMeshHealthCurrentSchemaVersion,
		ObservedAt:    observedAt,
		Cells:         cells,
	}

	if err := health.Validate(); err != nil {
		return NatsMeshHealth{}, err
	}

	return health, nil
}

func natsMeshStateFor(
	cell string,
	membershipByCell map[string]membership.RegionalRuntimeMembershipHealth,
	directory MeshDirectorySnapshot,
	gatewaysByCell map[string]NatsGatewaysObservation,
	observedAt time.Time,
) NatsMeshCellState {
	// A fully-disconnected gateway view is the partition signal and outranks
	// directory presence.
	if gateways, exists := gatewaysByCell[cell]; exists && gateways.FullyDisconnected() {
		return NatsMeshCellStateDisconnected
	}

	var entry *MeshDirectoryEntry
	for index := range directory.Cells {
		if directory.Cells[index].Cell == cell {
			entry = &directory.Cells[index]
			break
		}
	}

	if entry == nil || !entry.LeaseExpiresAt.After(observedAt) {
		if entry == nil {
			return NatsMeshCellStateMissing
		}

		return NatsMeshCellStateStale
	}

	if membership, exists := membershipByCell[cell]; exists && membership.ConflictingControllers > 0 {
		return NatsMeshCellStateConflicting
	}

	if entry.MembershipCondition == membership.RegionalRuntimeMembershipConditionHealthy {
		return NatsMeshCellStateHealthy
	}

	return NatsMeshCellStateStale
}

// Validate mirrors the C# Validate.
func (h NatsMeshHealth) Validate() error {
	if h.SchemaVersion != NatsMeshHealthCurrentSchemaVersion || h.ObservedAt.IsZero() ||
		len(h.Cells) == 0 {
		return fmt.Errorf("The NATS mesh health projection is invalid.")
	}

	seen := map[string]struct{}{}
	for _, cell := range h.Cells {
		if _, duplicate := seen[cell.Cell]; duplicate {
			return fmt.Errorf("The NATS mesh health projection is invalid.")
		}

		seen[cell.Cell] = struct{}{}
		if err := cell.Validate(); err != nil {
			return err
		}
	}

	for index := 1; index < len(h.Cells); index++ {
		if h.Cells[index-1].Cell >= h.Cells[index].Cell {
			return fmt.Errorf("The NATS mesh health projection is invalid.")
		}
	}

	return nil
}

// NatsMonitoringAvailability mirrors the C# enum.
type NatsMonitoringAvailability int

const (
	NatsMonitoringAvailabilityAvailable   NatsMonitoringAvailability = 1
	NatsMonitoringAvailabilityDegraded    NatsMonitoringAvailability = 2
	NatsMonitoringAvailabilityUnavailable NatsMonitoringAvailability = 3
)

func (a NatsMonitoringAvailability) String() string {
	switch a {
	case NatsMonitoringAvailabilityAvailable:
		return "Available"
	case NatsMonitoringAvailabilityDegraded:
		return "Degraded"
	case NatsMonitoringAvailabilityUnavailable:
		return "Unavailable"
	default:
		return strconv.Itoa(int(a))
	}
}

// NatsMonitoringAggregateCurrentSchemaVersion mirrors the C# constant.
const NatsMonitoringAggregateCurrentSchemaVersion = 1

// NatsMonitoringAggregate mirrors the C# record: the bounded NATS monitoring
// aggregate the observability instruments project.
type NatsMonitoringAggregate struct {
	SchemaVersion                 int
	Cell                          string
	Plane                         NatsMonitoringPlane
	ClusterRole                   NatsClusterRole
	ObservedAt                    time.Time
	Availability                  NatsMonitoringAvailability
	Mesh                          NatsMeshHealth
	Connections                   int64
	Reconnects                    int64
	Routes                        int64
	Accounts                      int64
	JetStreamDomains              int64
	GatewaysConnected             int64
	GatewaysDisconnected          int64
	ServerMemoryBytes             int64
	JetStreamStorageBytes         int64
	PartitionDurationMilliseconds int64
	RecoveryDurationMilliseconds  int64
	StreamsByClass                []NatsStreamClassState
	ConsumersByClass              []NatsConsumerClassState
	StoresByClass                 []NatsStoreClassState
	Advisories                    []NatsAdvisoryCount
	Certificates                  []NatsCertificateObservation
}

// WithAvailability mirrors the C# `with` expression used by supervision.
func (a NatsMonitoringAggregate) WithAvailability(availability NatsMonitoringAvailability) NatsMonitoringAggregate {
	updated := a
	updated.Availability = availability
	return updated
}

// Validate mirrors the C# Validate.
func (a NatsMonitoringAggregate) Validate() error {
	if a.SchemaVersion != NatsMonitoringAggregateCurrentSchemaVersion ||
		!monitoringCellTokenIsValid(a.Cell) ||
		a.Plane < NatsMonitoringPlaneControl || a.Plane > NatsMonitoringPlaneProduct ||
		a.ClusterRole < NatsClusterRoleRegional || a.ClusterRole > NatsClusterRoleGlobalAuthority ||
		a.Availability < NatsMonitoringAvailabilityAvailable ||
		a.Availability > NatsMonitoringAvailabilityUnavailable ||
		a.ObservedAt.IsZero() ||
		a.Connections < 0 || a.Reconnects < 0 || a.Routes < 0 || a.Accounts < 0 ||
		a.JetStreamDomains < 0 || a.GatewaysConnected < 0 || a.GatewaysDisconnected < 0 ||
		a.ServerMemoryBytes < 0 || a.JetStreamStorageBytes < 0 ||
		a.PartitionDurationMilliseconds < 0 || a.RecoveryDurationMilliseconds < 0 {
		return fmt.Errorf("The NATS monitoring aggregate is invalid.")
	}

	if err := a.Mesh.Validate(); err != nil {
		return err
	}

	for _, stream := range a.StreamsByClass {
		if err := stream.Validate(); err != nil {
			return err
		}
	}

	for _, consumer := range a.ConsumersByClass {
		if err := consumer.Validate(); err != nil {
			return err
		}
	}

	for _, store := range a.StoresByClass {
		if err := store.Validate(); err != nil {
			return err
		}
	}

	for _, advisory := range a.Advisories {
		if err := advisory.Validate(); err != nil {
			return err
		}
	}

	for _, certificate := range a.Certificates {
		if err := certificate.Validate(); err != nil {
			return err
		}
	}

	streamClasses := map[NatsStreamClass]struct{}{}
	for _, stream := range a.StreamsByClass {
		streamClasses[stream.StreamClass] = struct{}{}
	}

	if len(streamClasses) != len(a.StreamsByClass) {
		return fmt.Errorf("The NATS monitoring aggregate contains duplicate class entries.")
	}

	consumerClasses := map[[2]int]struct{}{}
	for _, consumer := range a.ConsumersByClass {
		consumerClasses[[2]int{int(consumer.StreamClass), int(consumer.ConsumerClass)}] = struct{}{}
	}

	if len(consumerClasses) != len(a.ConsumersByClass) {
		return fmt.Errorf("The NATS monitoring aggregate contains duplicate class entries.")
	}

	storeClasses := map[NatsStoreClass]struct{}{}
	for _, store := range a.StoresByClass {
		storeClasses[store.StoreClass] = struct{}{}
	}

	if len(storeClasses) != len(a.StoresByClass) {
		return fmt.Errorf("The NATS monitoring aggregate contains duplicate class entries.")
	}

	advisoryKinds := map[NatsAdvisoryKind]struct{}{}
	for _, advisory := range a.Advisories {
		advisoryKinds[advisory.Kind] = struct{}{}
	}

	if len(advisoryKinds) != len(a.Advisories) {
		return fmt.Errorf("The NATS monitoring aggregate contains duplicate class entries.")
	}

	certificateClasses := map[NatsCertificateClass]struct{}{}
	for _, certificate := range a.Certificates {
		certificateClasses[certificate.CertificateClass] = struct{}{}
	}

	if len(certificateClasses) != len(a.Certificates) {
		return fmt.Errorf("The NATS monitoring aggregate contains duplicate class entries.")
	}

	return nil
}

// NatsMonitoringClassifier mirrors the C# static class: maps a raw JetStream
// stream or consumer name onto its bounded metric class. The mapping is total.
var NatsMonitoringClassifier natsMonitoringClassifier

type natsMonitoringClassifier struct{}

// ClassifyStream mirrors ClassifyStream.
func (natsMonitoringClassifier) ClassifyStream(streamName string) NatsStreamClass {
	if streamName == "" {
		return NatsStreamClassUnknown
	}

	if len(streamName) >= 3 && streamName[:3] == "KV_" {
		return NatsStreamClassKeyValue
	}

	if len(streamName) >= 4 && streamName[:4] == "OBJ_" {
		return NatsStreamClassObjectStore
	}

	switch streamName {
	case "CELL_SPEC":
		return NatsStreamClassCellSpec
	case "CELL_OPERATIONS":
		return NatsStreamClassCellOperations
	case "CELL_EVENTS":
		return NatsStreamClassCellEvents
	case "GLOBAL_SPEC":
		return NatsStreamClassGlobalSpec
	case "GLOBAL_CI":
		return NatsStreamClassGlobalCi
	default:
		return NatsStreamClassUnknown
	}
}

// ClassifyConsumer mirrors ClassifyConsumer. NATS.Net KeyValue/ObjectStore
// watches use ephemeral push consumers whose delivered durable name is an
// internal NUID: classify by shape, never identity.
func (natsMonitoringClassifier) ClassifyConsumer(consumerName string) NatsConsumerClass {
	if consumerName == "" {
		return NatsConsumerClassUnknown
	}

	if stringsHasPrefixOrdinal(consumerName, "gitops_cell_spec_") {
		return NatsConsumerClassCellSpec
	}

	if stringsHasPrefixOrdinal(consumerName, "runtime_startup") {
		return NatsConsumerClassStartupEvent
	}

	if stringsHasPrefixOrdinal(consumerName, "ci_") {
		return NatsConsumerClassGlobalCi
	}

	if len(consumerName) == 22 || len(consumerName) == 23 {
		for index := 0; index < len(consumerName); index++ {
			character := consumerName[index]
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' {
				continue
			}

			return NatsConsumerClassUnknown
		}

		return NatsConsumerClassEphemeralWatch
	}

	return NatsConsumerClassUnknown
}

// ClassifyAdvisory mirrors ClassifyAdvisory.
func (natsMonitoringClassifier) ClassifyAdvisory(advisorySubject string) NatsAdvisoryKind {
	if advisorySubject == "" {
		return NatsAdvisoryKindUnclassified
	}

	if stringsContains(advisorySubject, "SLOW_CONSUMER") {
		return NatsAdvisoryKindSlowConsumer
	}

	if stringsContains(advisorySubject, "LEADER") || stringsContains(advisorySubject, "RAFT") {
		return NatsAdvisoryKindLeaderChange
	}

	if stringsContains(advisorySubject, "AUTH") || stringsContains(advisorySubject, "AUTHENTICATION") {
		return NatsAdvisoryKindAuthenticationFailure
	}

	if stringsContains(advisorySubject, "MAX_DELIVERIES") {
		return NatsAdvisoryKindMaxDeliveries
	}

	if stringsContains(advisorySubject, "RESOURCE") || stringsContains(advisorySubject, "MAX_MEMORY") ||
		stringsContains(advisorySubject, "MAX_STORAGE") {
		return NatsAdvisoryKindResourceExhausted
	}

	return NatsAdvisoryKindUnclassified
}

func stringsHasPrefixOrdinal(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func stringsContains(value, fragment string) bool {
	return len(fragment) == 0 || indexOfOrdinal(value, fragment) >= 0
}

func indexOfOrdinal(value, fragment string) int {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return index
		}
	}

	return -1
}

// INatsMonitoringObservation mirrors the C# interface: implemented by every
// bounded observation so fail-closed parsing is compile-time checked.
type INatsMonitoringObservation interface {
	Validate() error
}

// NatsMonitoringParsersMaximumReplyBytes mirrors the C# MaximumReplyBytes: the
// bounded reply cap.
const NatsMonitoringParsersMaximumReplyBytes = 4 * 1024 * 1024

// NatsMonitoringParsers mirrors the C# static class: parses bounded
// observations from raw $SYS monitoring and advisory payloads. Parsing is
// defensive by contract.
var NatsMonitoringParsers natsMonitoringParsers

type natsMonitoringParsers struct{}

// Connections mirrors NatsMonitoringParsers.Connections.
func (natsMonitoringParsers) Connections(
	source string,
	cell string,
	plane NatsMonitoringPlane,
	observedAt time.Time,
) *NatsConnectionsObservation {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	data := natsMonitoringEnvelopeData(root)
	total := natsMonitoringReadLong(data, "total")
	if total == nil {
		total = natsMonitoringReadLong(data, "num_connections")
	}

	if total == nil {
		return nil
	}

	reconnects := int64(0)
	if connections, exists := data["connections"]; exists {
		if list, isList := connections.([]interface{}); isList {
			for _, connection := range list {
				if entry, isMap := connection.(map[string]interface{}); isMap {
					if value := natsMonitoringReadLong(entry, "num_reconnects"); value != nil {
						reconnects += *value
					}
				}
			}
		}
	}

	observation := NatsConnectionsObserve(cell, plane, *total, reconnects, observedAt)
	if err := observation.Validate(); err != nil {
		return nil
	}

	return &observation
}

// Routes mirrors NatsMonitoringParsers.Routes.
func (natsMonitoringParsers) Routes(source, cell string, observedAt time.Time) *NatsRoutesObservation {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	routes := natsMonitoringReadLong(natsMonitoringEnvelopeData(root), "num_routes")
	if routes == nil {
		return nil
	}

	observation := NatsRoutesObserve(cell, *routes, observedAt)
	if err := observation.Validate(); err != nil {
		return nil
	}

	return &observation
}

// Gateways mirrors NatsMonitoringParsers.Gateways.
func (natsMonitoringParsers) Gateways(source, cell string, observedAt time.Time) *NatsGatewaysObservation {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	data, exists := root["data"].(map[string]interface{})
	if !exists {
		return nil
	}

	connected := 0
	disconnected := 0
	if gateways, isMap := data["outbound_gateways"].(map[string]interface{}); isMap {
		for _, gateway := range gateways {
			gatewayObject, isObject := gateway.(map[string]interface{})
			hasConnection := false
			if isObject {
				_, hasConnection = gatewayObject["connection"].(map[string]interface{})
			}

			if hasConnection {
				connected++
			} else if isObject {
				disconnected++
			}
		}
	}

	observation := NatsGatewaysObserve(cell, connected, disconnected, observedAt)
	if err := observation.Validate(); err != nil {
		return nil
	}

	return &observation
}

// Accounts mirrors NatsMonitoringParsers.Accounts.
func (natsMonitoringParsers) Accounts(source, cell string, observedAt time.Time) *NatsAccountsObservation {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	data := natsMonitoringEnvelopeData(root)
	name := natsMonitoringReadString(data, "name")
	if name == nil {
		return nil
	}

	accounts := int64(1)
	if value := natsMonitoringReadLong(data, "account_total"); value != nil {
		accounts = *value
	}

	connections := int64(0)
	if value := natsMonitoringReadLong(data, "num_connections"); value != nil {
		connections = *value
	}

	if value := natsMonitoringReadLong(data, "total"); value != nil {
		connections = *value
	}

	observation := NatsAccountsObserve(cell, accounts, connections, observedAt)
	if err := observation.Validate(); err != nil {
		return nil
	}

	return &observation
}

// ServerResources mirrors NatsMonitoringParsers.ServerResources.
func (natsMonitoringParsers) ServerResources(source, cell string, observedAt time.Time) *NatsServerResourceObservation {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	data := natsMonitoringEnvelopeData(root)
	memory := natsMonitoringReadLong(data, "mem")
	if memory == nil {
		return nil
	}

	storage := int64(0)
	if jetstream, isMap := data["jetstream"].(map[string]interface{}); isMap {
		if value := natsMonitoringReadLong(jetstream, "storage"); value != nil {
			storage = *value
		}
	}

	observation := NatsServerResourceObserve(cell, *memory, storage, observedAt)
	if err := observation.Validate(); err != nil {
		return nil
	}

	return &observation
}

// JetStream mirrors NatsMonitoringParsers.JetStream.
func (natsMonitoringParsers) JetStream(source, cell string, observedAt time.Time) *NatsJetStreamObservation {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	sourceData := natsMonitoringEnvelopeData(root)
	memory := natsMonitoringReadLong(sourceData, "memory")
	storage := natsMonitoringReadLong(sourceData, "storage")
	if memory == nil || storage == nil {
		return nil
	}

	streams := int64(0)
	if value := natsMonitoringReadLong(sourceData, "streams"); value != nil {
		streams = *value
	}

	consumers := int64(0)
	if value := natsMonitoringReadLong(sourceData, "consumers"); value != nil {
		consumers = *value
	}

	domains := int64(0)
	if details, isList := sourceData["account_details"].([]interface{}); isList {
		domains = int64(len(details))
	}

	observation := NatsJetStreamObserve(cell, domains, streams, consumers, *memory, *storage, observedAt)
	if err := observation.Validate(); err != nil {
		return nil
	}

	return &observation
}

// NatsMonitoringJetStreamDetail mirrors the C# tuple result of JetStreamDetail.
type NatsMonitoringJetStreamDetail struct {
	Streams   []NatsStreamClassState
	Consumers []NatsConsumerClassState
}

// JetStreamDetail mirrors NatsMonitoringParsers.JetStreamDetail: extracts the
// per-class stream detail from a detailed JSZ reply. Stream and consumer names
// are classified immediately and never leave this method.
func (natsMonitoringParsers) JetStreamDetail(source string) *NatsMonitoringJetStreamDetail {
	root, ok := natsMonitoringTryDocument(source)
	if !ok {
		return nil
	}

	sourceData := natsMonitoringEnvelopeData(root)
	streams, isList := sourceData["stream_detail"].([]interface{})
	if !isList {
		return nil
	}

	streamStates := map[NatsStreamClass]NatsStreamClassState{}
	consumerStates := map[[2]int]NatsConsumerClassState{}
	for _, streamEntry := range streams {
		stream, isMap := streamEntry.(map[string]interface{})
		if !isMap {
			continue
		}

		name := natsMonitoringReadString(stream, "name")
		if name == nil {
			continue
		}

		streamClass := NatsMonitoringClassifier.ClassifyStream(*name)
		streamStates[streamClass] = natsMonitoringReadStreamState(stream, streamClass)
		consumers, hasConsumers := stream["consumer_detail"].([]interface{})
		if !hasConsumers {
			continue
		}

		for _, consumerEntry := range consumers {
			consumer, isConsumer := consumerEntry.(map[string]interface{})
			if !isConsumer {
				continue
			}

			consumerName := natsMonitoringReadString(consumer, "name")
			consumerClass := NatsMonitoringClassifier.ClassifyConsumer("")
			if consumerName != nil {
				consumerClass = NatsMonitoringClassifier.ClassifyConsumer(*consumerName)
			}

			key := [2]int{int(streamClass), int(consumerClass)}
			existing, hasExisting := consumerStates[key]
			observed := natsMonitoringReadConsumerState(consumer, streamClass, consumerClass)
			consumerStates[key] = natsMonitoringMergeConsumerState(existing, observed, hasExisting)
		}
	}

	orderedStreams := make([]NatsStreamClassState, 0, len(streamStates))
	for _, state := range streamStates {
		orderedStreams = append(orderedStreams, state)
	}
	sort.Slice(orderedStreams, func(i, j int) bool {
		return orderedStreams[i].StreamClass < orderedStreams[j].StreamClass
	})

	orderedConsumers := make([]NatsConsumerClassState, 0, len(consumerStates))
	for _, state := range consumerStates {
		orderedConsumers = append(orderedConsumers, state)
	}
	sort.Slice(orderedConsumers, func(i, j int) bool {
		if orderedConsumers[i].StreamClass != orderedConsumers[j].StreamClass {
			return orderedConsumers[i].StreamClass < orderedConsumers[j].StreamClass
		}

		return orderedConsumers[i].ConsumerClass < orderedConsumers[j].ConsumerClass
	})

	for _, state := range orderedStreams {
		if err := state.Validate(); err != nil {
			return nil
		}
	}

	for _, state := range orderedConsumers {
		if err := state.Validate(); err != nil {
			return nil
		}
	}

	return &NatsMonitoringJetStreamDetail{Streams: orderedStreams, Consumers: orderedConsumers}
}

func natsMonitoringReadStreamState(stream map[string]interface{}, streamClass NatsStreamClass) NatsStreamClassState {
	messages := int64(0)
	bytes := int64(0)
	// JetStream detail carries no duplicate-detection counter: the duplicate
	// signal is application-level and is supplied by the adapter.
	duplicates := int64(0)
	if state, isMap := stream["state"].(map[string]interface{}); isMap {
		if value := natsMonitoringReadLong(state, "bytes"); value != nil {
			bytes = *value
		}

		if value := natsMonitoringReadLong(state, "messages"); value != nil {
			messages = *value
		}
	}

	result := NatsStreamClassState{
		StreamClass: streamClass,
		Streams:     1,
		Messages:    messages,
		Bytes:       bytes,
		Duplicates:  duplicates,
	}
	if err := result.Validate(); err != nil {
		panic(err)
	}

	return result
}

func natsMonitoringReadConsumerState(
	consumer map[string]interface{},
	streamClass NatsStreamClass,
	consumerClass NatsConsumerClass,
) NatsConsumerClassState {
	delivered := int64(0)
	redelivered := int64(0)
	ackPending := int64(0)
	waiting := int64(0)
	lag := int64(0)

	if deliveredElement, isMap := consumer["delivered"].(map[string]interface{}); isMap {
		if value := natsMonitoringReadLong(deliveredElement, "consumer_seq"); value != nil {
			delivered = *value
		}
	}

	if ackFloor, isMap := consumer["ack_floor"].(map[string]interface{}); isMap {
		if value := natsMonitoringReadLong(ackFloor, "consumer_seq"); value != nil {
			redelivered = delivered - *value
			if redelivered < 0 {
				redelivered = 0
			}
		}
	}

	if value := natsMonitoringReadLong(consumer, "num_ack_pending"); value != nil {
		ackPending = *value
	}

	if value := natsMonitoringReadLong(consumer, "num_waiting"); value != nil {
		waiting = *value
	}

	if value := natsMonitoringReadLong(consumer, "num_pending"); value != nil {
		lag = *value
	}

	result := NatsConsumerClassState{
		StreamClass:   streamClass,
		ConsumerClass: consumerClass,
		Consumers:     1,
		Lag:           lag,
		Deliveries:    delivered,
		Redelivered:   redelivered,
		AckPending:    ackPending,
		Waiting:       waiting,
	}
	if err := result.Validate(); err != nil {
		panic(err)
	}

	return result
}

func natsMonitoringMergeConsumerState(
	existing NatsConsumerClassState,
	observed NatsConsumerClassState,
	hasExisting bool,
) NatsConsumerClassState {
	if !hasExisting {
		return observed
	}

	return NatsConsumerClassState{
		StreamClass:   existing.StreamClass,
		ConsumerClass: existing.ConsumerClass,
		Consumers:     existing.Consumers + observed.Consumers,
		Lag:           existing.Lag + observed.Lag,
		Deliveries:    existing.Deliveries + observed.Deliveries,
		Redelivered:   existing.Redelivered + observed.Redelivered,
		AckPending:    existing.AckPending + observed.AckPending,
		Waiting:       existing.Waiting + observed.Waiting,
	}
}

// natsMonitoringTryDocument mirrors TryDocument: bounded input; an oversized
// reply is a hostile shape, not a census.
func natsMonitoringTryDocument(source string) (map[string]interface{}, bool) {
	if len(source) == 0 || len(source) > NatsMonitoringParsersMaximumReplyBytes {
		return nil, false
	}

	var root map[string]interface{}
	if err := json.Unmarshal([]byte(source), &root); err != nil {
		return nil, false
	}

	return root, true
}

// natsMonitoringEnvelopeData mirrors EnvelopeData: the system-service reply
// envelope is {"server": {...}, "data": {...}}; parsers read only data.
func natsMonitoringEnvelopeData(root map[string]interface{}) map[string]interface{} {
	if data, exists := root["data"].(map[string]interface{}); exists {
		return data
	}

	return root
}

func natsMonitoringReadLong(element map[string]interface{}, name string) *int64 {
	value, exists := element[name]
	if !exists {
		return nil
	}

	switch typed := value.(type) {
	case float64:
		parsed := int64(typed)
		return &parsed
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return nil
		}

		return &parsed
	default:
		return nil
	}
}

func natsMonitoringReadString(element map[string]interface{}, name string) *string {
	if value, exists := element[name].(string); exists {
		return &value
	}

	return nil
}

// INatsMonitoringObservation is implemented by every bounded observation so
// fail-closed parsing stays compile-time checked; the typed parsers above
// mirror the C# ValidOrNull<T> gate by returning nil on validation failure.
