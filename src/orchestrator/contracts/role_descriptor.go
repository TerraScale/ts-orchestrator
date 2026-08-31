package contracts

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RuntimeDriver mirrors the RuntimeDriver enum.
type RuntimeDriver int

const (
	RuntimeDriverUnspecified   RuntimeDriver = 0
	RuntimeDriverNativeSystemd RuntimeDriver = 1
	RuntimeDriverOciContainer  RuntimeDriver = 2
)

func (d RuntimeDriver) String() string {
	switch d {
	case RuntimeDriverNativeSystemd:
		return "NativeSystemd"
	case RuntimeDriverOciContainer:
		return "OciContainer"
	default:
		return strconv.Itoa(int(d))
	}
}

func runtimeDriverIsDefined(d RuntimeDriver) bool {
	return d >= RuntimeDriverNativeSystemd && d <= RuntimeDriverOciContainer
}

// TransportProtocol mirrors the TransportProtocol enum.
type TransportProtocol int

const (
	TransportProtocolUnspecified TransportProtocol = 0
	TransportProtocolTcp         TransportProtocol = 1
	TransportProtocolUdp         TransportProtocol = 2
)

func (p TransportProtocol) String() string {
	switch p {
	case TransportProtocolTcp:
		return "Tcp"
	case TransportProtocolUdp:
		return "Udp"
	default:
		return strconv.Itoa(int(p))
	}
}

func transportProtocolIsDefined(p TransportProtocol) bool {
	return p >= TransportProtocolTcp && p <= TransportProtocolUdp
}

// NetworkPort is one declared (protocol, port) pair.
type NetworkPort struct {
	Protocol TransportProtocol
	Port     uint16
}

// NewNetworkPort mirrors the NetworkPort constructor.
func NewNetworkPort(protocol TransportProtocol, port uint16) (NetworkPort, error) {
	if !transportProtocolIsDefined(protocol) {
		return NetworkPort{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'protocol', actual value %d)", int(protocol))
	}

	if port == 0 {
		return NetworkPort{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'port', actual value %d)", int(port))
	}

	return NetworkPort{Protocol: protocol, Port: port}, nil
}

func (p NetworkPort) String() string {
	return p.Protocol.String() + ":" + strconv.FormatUint(uint64(p.Port), 10)
}

// RoleCapability mirrors the RoleCapability enum.
type RoleCapability int

const (
	RoleCapabilityUnspecified         RoleCapability = 0
	RoleCapabilityPublicHttp          RoleCapability = 1
	RoleCapabilityProductDatabase     RoleCapability = 2
	RoleCapabilityControlAuthority    RoleCapability = 3
	RoleCapabilityControlMessaging    RoleCapability = 4
	RoleCapabilityProductMessaging    RoleCapability = 5
	RoleCapabilityTelemetryQuery      RoleCapability = 6
	RoleCapabilityTelemetryIngest     RoleCapability = 7
	RoleCapabilityAlerting            RoleCapability = 8
	RoleCapabilitySyntheticProbe      RoleCapability = 9
	RoleCapabilityNetworkCoordination RoleCapability = 10
	RoleCapabilityRoutePolicy         RoleCapability = 11
	RoleCapabilityIsolatedBuild       RoleCapability = 12
)

func (c RoleCapability) String() string {
	switch c {
	case RoleCapabilityPublicHttp:
		return "PublicHttp"
	case RoleCapabilityProductDatabase:
		return "ProductDatabase"
	case RoleCapabilityControlAuthority:
		return "ControlAuthority"
	case RoleCapabilityControlMessaging:
		return "ControlMessaging"
	case RoleCapabilityProductMessaging:
		return "ProductMessaging"
	case RoleCapabilityTelemetryQuery:
		return "TelemetryQuery"
	case RoleCapabilityTelemetryIngest:
		return "TelemetryIngest"
	case RoleCapabilityAlerting:
		return "Alerting"
	case RoleCapabilitySyntheticProbe:
		return "SyntheticProbe"
	case RoleCapabilityNetworkCoordination:
		return "NetworkCoordination"
	case RoleCapabilityRoutePolicy:
		return "RoutePolicy"
	case RoleCapabilityIsolatedBuild:
		return "IsolatedBuild"
	default:
		return strconv.Itoa(int(c))
	}
}

func roleCapabilityIsDefined(c RoleCapability) bool {
	return c >= RoleCapabilityPublicHttp && c <= RoleCapabilityIsolatedBuild
}

// VolumePurpose mirrors the VolumePurpose enum.
type VolumePurpose int

const (
	VolumePurposeUnspecified      VolumePurpose = 0
	VolumePurposeTerraBaseData    VolumePurpose = 1
	VolumePurposeNatsControlStore VolumePurpose = 2
	VolumePurposeNatsProductStore VolumePurpose = 3
	VolumePurposeMetricsData      VolumePurpose = 4
	VolumePurposeLogData          VolumePurpose = 5
	VolumePurposeTraceData        VolumePurpose = 6
	VolumePurposeTelemetrySpool   VolumePurpose = 7
	VolumePurposeEphemeralBuild   VolumePurpose = 8
)

func (p VolumePurpose) String() string {
	switch p {
	case VolumePurposeTerraBaseData:
		return "TerraBaseData"
	case VolumePurposeNatsControlStore:
		return "NatsControlStore"
	case VolumePurposeNatsProductStore:
		return "NatsProductStore"
	case VolumePurposeMetricsData:
		return "MetricsData"
	case VolumePurposeLogData:
		return "LogData"
	case VolumePurposeTraceData:
		return "TraceData"
	case VolumePurposeTelemetrySpool:
		return "TelemetrySpool"
	case VolumePurposeEphemeralBuild:
		return "EphemeralBuild"
	default:
		return strconv.Itoa(int(p))
	}
}

func volumePurposeIsDefined(p VolumePurpose) bool {
	return p >= VolumePurposeTerraBaseData && p <= VolumePurposeEphemeralBuild
}

// SecretProfileReference is a reference-only secret profile pointer.
type SecretProfileReference struct {
	ProfileId ResourceId
}

// NewSecretProfileReference mirrors the constructor; a zero ResourceId stands
// in for the C# null argument.
func NewSecretProfileReference(profileId ResourceId) (SecretProfileReference, error) {
	if profileId.Value == "" {
		return SecretProfileReference{}, errors.New("Value cannot be null. (Parameter 'profileId')")
	}

	return SecretProfileReference{ProfileId: profileId}, nil
}

func (r SecretProfileReference) String() string { return r.ProfileId.String() }

// HealthSignal mirrors the HealthSignal enum.
type HealthSignal int

const (
	HealthSignalUnspecified         HealthSignal = 0
	HealthSignalProcessLiveness     HealthSignal = 1
	HealthSignalApplicationLiveness HealthSignal = 2
	HealthSignalReadiness           HealthSignal = 3
	HealthSignalDependencyReadiness HealthSignal = 4
	HealthSignalDrainReadiness      HealthSignal = 5
	HealthSignalRolloutVerification HealthSignal = 6
)

func (s HealthSignal) String() string {
	switch s {
	case HealthSignalProcessLiveness:
		return "ProcessLiveness"
	case HealthSignalApplicationLiveness:
		return "ApplicationLiveness"
	case HealthSignalReadiness:
		return "Readiness"
	case HealthSignalDependencyReadiness:
		return "DependencyReadiness"
	case HealthSignalDrainReadiness:
		return "DrainReadiness"
	case HealthSignalRolloutVerification:
		return "RolloutVerification"
	default:
		return strconv.Itoa(int(s))
	}
}

func healthSignalIsDefined(s HealthSignal) bool {
	return s >= HealthSignalProcessLiveness && s <= HealthSignalRolloutVerification
}

// HealthContract is the nonempty, duplicate-free, stably ordered set of health
// signals a role must expose.
type HealthContract struct {
	Signals []HealthSignal
}

// NewHealthContract mirrors the HealthContract constructor.
func NewHealthContract(signals []HealthSignal) (HealthContract, error) {
	stable, err := stableEnumSet(signals, "signals", healthSignalIsDefined)
	if err != nil {
		return HealthContract{}, err
	}

	if len(stable) == 0 {
		return HealthContract{}, errors.New("At least one health signal is required. (Parameter 'signals')")
	}

	return HealthContract{Signals: stable}, nil
}

// PlacementClassReference names one canonical placement class.
type PlacementClassReference struct {
	Id string
}

// NewPlacementClassReference mirrors the constructor.
func NewPlacementClassReference(id string) (PlacementClassReference, error) {
	token, err := canonicalTextToken(id, "id", 63)
	if err != nil {
		return PlacementClassReference{}, err
	}

	return PlacementClassReference{Id: token}, nil
}

func (r PlacementClassReference) String() string { return r.Id }

// FailureDomainSpread mirrors the FailureDomainSpread enum.
type FailureDomainSpread int

const (
	FailureDomainSpreadUnspecified     FailureDomainSpread = 0
	FailureDomainSpreadNone            FailureDomainSpread = 1
	FailureDomainSpreadPreferDistinct  FailureDomainSpread = 2
	FailureDomainSpreadRequireDistinct FailureDomainSpread = 3
)

func (s FailureDomainSpread) String() string {
	switch s {
	case FailureDomainSpreadNone:
		return "None"
	case FailureDomainSpreadPreferDistinct:
		return "PreferDistinct"
	case FailureDomainSpreadRequireDistinct:
		return "RequireDistinct"
	default:
		return strconv.Itoa(int(s))
	}
}

func failureDomainSpreadIsDefined(s FailureDomainSpread) bool {
	return s >= FailureDomainSpreadNone && s <= FailureDomainSpreadRequireDistinct
}

// PlacementConstraints is the closed placement constraint surface.
type PlacementConstraints struct {
	RequiredNodeClass   *PlacementClassReference
	FailureDomainSpread FailureDomainSpread
	OnePerHost          bool
}

// NewPlacementConstraints mirrors the constructor; a nil RequiredNodeClass is
// the C# null value.
func NewPlacementConstraints(
	requiredNodeClass *PlacementClassReference,
	failureDomainSpread FailureDomainSpread,
	onePerHost bool,
) (PlacementConstraints, error) {
	if !failureDomainSpreadIsDefined(failureDomainSpread) {
		return PlacementConstraints{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'failureDomainSpread', actual value %d)",
			int(failureDomainSpread))
	}

	return PlacementConstraints{
		RequiredNodeClass:   requiredNodeClass,
		FailureDomainSpread: failureDomainSpread,
		OnePerHost:          onePerHost,
	}, nil
}

// ScalingControllerOwner mirrors the ScalingControllerOwner enum.
type ScalingControllerOwner int

const (
	ScalingControllerOwnerUnspecified  ScalingControllerOwner = 0
	ScalingControllerOwnerFixed        ScalingControllerOwner = 1
	ScalingControllerOwnerStateless    ScalingControllerOwner = 2
	ScalingControllerOwnerTerraBase    ScalingControllerOwner = 3
	ScalingControllerOwnerControlPlane ScalingControllerOwner = 4
)

func (o ScalingControllerOwner) String() string {
	switch o {
	case ScalingControllerOwnerFixed:
		return "Fixed"
	case ScalingControllerOwnerStateless:
		return "Stateless"
	case ScalingControllerOwnerTerraBase:
		return "TerraBase"
	case ScalingControllerOwnerControlPlane:
		return "ControlPlane"
	default:
		return strconv.Itoa(int(o))
	}
}

func scalingControllerOwnerIsDefined(o ScalingControllerOwner) bool {
	return o >= ScalingControllerOwnerFixed && o <= ScalingControllerOwnerControlPlane
}

// ResourceEnvelope is the eight-dimension nonnegative resource envelope.
type ResourceEnvelope struct {
	Cpu             int64
	Memory          int64
	BlockIo         int64
	EphemeralDisk   int64
	Bandwidth       int64
	Pids            int64
	FileDescriptors int64
	HugePages       int64
}

// NewResourceEnvelope mirrors the constructor (every dimension nonnegative).
func NewResourceEnvelope(cpu, memory, blockIo, ephemeralDisk, bandwidth, pids, fileDescriptors, hugePages int64) (ResourceEnvelope, error) {
	nonNegative := func(value int64, name string) (int64, error) {
		if value < 0 {
			return 0, fmt.Errorf(
				"Specified argument was out of the range of valid values. (Parameter '%s', actual value %d)", name, value)
		}

		return value, nil
	}

	var err error
	if cpu, err = nonNegative(cpu, "cpu"); err != nil {
		return ResourceEnvelope{}, err
	}

	if memory, err = nonNegative(memory, "memory"); err != nil {
		return ResourceEnvelope{}, err
	}

	if blockIo, err = nonNegative(blockIo, "blockIo"); err != nil {
		return ResourceEnvelope{}, err
	}

	if ephemeralDisk, err = nonNegative(ephemeralDisk, "ephemeralDisk"); err != nil {
		return ResourceEnvelope{}, err
	}

	if bandwidth, err = nonNegative(bandwidth, "bandwidth"); err != nil {
		return ResourceEnvelope{}, err
	}

	if pids, err = nonNegative(pids, "pids"); err != nil {
		return ResourceEnvelope{}, err
	}

	if fileDescriptors, err = nonNegative(fileDescriptors, "fileDescriptors"); err != nil {
		return ResourceEnvelope{}, err
	}

	if hugePages, err = nonNegative(hugePages, "hugePages"); err != nil {
		return ResourceEnvelope{}, err
	}

	return ResourceEnvelope{
		Cpu:             cpu,
		Memory:          memory,
		BlockIo:         blockIo,
		EphemeralDisk:   ephemeralDisk,
		Bandwidth:       bandwidth,
		Pids:            pids,
		FileDescriptors: fileDescriptors,
		HugePages:       hugePages,
	}, nil
}

// Values mirrors the internal ResourceEnvelope.Values iterator order.
func (e ResourceEnvelope) Values() []int64 {
	return []int64{e.Cpu, e.Memory, e.BlockIo, e.EphemeralDisk, e.Bandwidth, e.Pids, e.FileDescriptors, e.HugePages}
}

// ResourceBounds pairs a minimum and a maximum resource envelope.
type ResourceBounds struct {
	Minimum ResourceEnvelope
	Maximum ResourceEnvelope
}

// NewResourceBounds mirrors the constructor; every minimum dimension must be
// less than or equal to its maximum.
func NewResourceBounds(minimum, maximum ResourceEnvelope) (ResourceBounds, error) {
	minValues := minimum.Values()
	maxValues := maximum.Values()
	for index := 0; index < len(minValues); index++ {
		if minValues[index] > maxValues[index] {
			return ResourceBounds{}, errors.New(
				"Every minimum resource must be less than or equal to its maximum.")
		}
	}

	return ResourceBounds{Minimum: minimum, Maximum: maximum}, nil
}

// RoleDescriptor is the safe built-in descriptor surface for INV-017. It has
// no arbitrary execution, privilege, Linux capability, host path, or NATS
// permission fields; the canonical output contains references only and is safe
// for SEC-NO-SECRET-OUTPUT.
type RoleDescriptor struct {
	ApiVersion             ApiVersion
	Role                   AdmittedRole
	AllowedRuntimes        []RuntimeDriver
	Ports                  []NetworkPort
	Capabilities           []RoleCapability
	VolumePurposes         []VolumePurpose
	SecretProfiles         []SecretProfileReference
	Health                 HealthContract
	Placement              PlacementConstraints
	ScalingControllerOwner ScalingControllerOwner
	ResourceBounds         ResourceBounds
}

// NewRoleDescriptor mirrors the (assembly-internal) constructor: it validates
// every input, rejects duplicates and unknown enum values, and stores every
// collection in canonical order so projections are permutation-invariant.
func NewRoleDescriptor(
	apiVersion ApiVersion,
	role AdmittedRole,
	allowedRuntimes []RuntimeDriver,
	ports []NetworkPort,
	capabilities []RoleCapability,
	volumePurposes []VolumePurpose,
	secretProfiles []SecretProfileReference,
	health HealthContract,
	placement PlacementConstraints,
	scalingControllerOwner ScalingControllerOwner,
	resourceBounds ResourceBounds,
) (RoleDescriptor, error) {
	if apiVersion.Value == "" {
		return RoleDescriptor{}, errors.New("Value cannot be null. (Parameter 'apiVersion')")
	}

	if role.kind == RoleKindUnspecified {
		return RoleDescriptor{}, errors.New("Value cannot be null. (Parameter 'role')")
	}

	stableRuntimes, err := stableEnumSet(allowedRuntimes, "allowedRuntimes", runtimeDriverIsDefined)
	if err != nil {
		return RoleDescriptor{}, err
	}

	if len(stableRuntimes) == 0 {
		return RoleDescriptor{}, errors.New("At least one value is required. (Parameter 'allowedRuntimes')")
	}

	stablePorts, err := stablePorts(ports)
	if err != nil {
		return RoleDescriptor{}, err
	}

	stableCapabilities, err := stableEnumSet(capabilities, "capabilities", roleCapabilityIsDefined)
	if err != nil {
		return RoleDescriptor{}, err
	}

	stableVolumes, err := stableEnumSet(volumePurposes, "volumePurposes", volumePurposeIsDefined)
	if err != nil {
		return RoleDescriptor{}, err
	}

	stableSecrets, err := stableSecretProfiles(secretProfiles)
	if err != nil {
		return RoleDescriptor{}, err
	}

	if len(health.Signals) == 0 {
		return RoleDescriptor{}, errors.New("Value cannot be null. (Parameter 'health')")
	}

	if placement.FailureDomainSpread == FailureDomainSpreadUnspecified {
		return RoleDescriptor{}, errors.New("Value cannot be null. (Parameter 'placement')")
	}

	if !scalingControllerOwnerIsDefined(scalingControllerOwner) {
		return RoleDescriptor{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'scalingControllerOwner', actual value %d)",
			int(scalingControllerOwner))
	}

	return RoleDescriptor{
		ApiVersion:             apiVersion,
		Role:                   role,
		AllowedRuntimes:        stableRuntimes,
		Ports:                  stablePorts,
		Capabilities:           stableCapabilities,
		VolumePurposes:         stableVolumes,
		SecretProfiles:         stableSecrets,
		Health:                 health,
		Placement:              placement,
		ScalingControllerOwner: scalingControllerOwner,
		ResourceBounds:         resourceBounds,
	}, nil
}

// ToCanonicalString produces the pipe-joined canonical projection.
func (d RoleDescriptor) ToCanonicalString() string {
	requiredNodeClass := "-"
	if d.Placement.RequiredNodeClass != nil {
		requiredNodeClass = d.Placement.RequiredNodeClass.Id
	}

	return strings.Join([]string{
		"apiVersion=" + d.ApiVersion.String(),
		"role=" + d.Role.Projection(),
		"runtimes=" + joinRoleValues(d.AllowedRuntimes),
		"ports=" + joinRoleValues(d.Ports),
		"capabilities=" + joinRoleValues(d.Capabilities),
		"volumes=" + joinRoleValues(d.VolumePurposes),
		"secrets=" + joinRoleValues(d.SecretProfiles),
		"health=" + joinRoleValues(d.Health.Signals),
		"placement=" + requiredNodeClass + ":" + d.Placement.FailureDomainSpread.String() + ":" +
			strconv.FormatBool(d.Placement.OnePerHost),
		"scaling=" + d.ScalingControllerOwner.String(),
		"minimum=" + joinRoleNumbers(d.ResourceBounds.Minimum.Values()),
		"maximum=" + joinRoleNumbers(d.ResourceBounds.Maximum.Values()),
	}, "|")
}

// GetCanonicalDigestInput returns the UTF-8 bytes of the canonical projection.
func (d RoleDescriptor) GetCanonicalDigestInput() []byte {
	return []byte(d.ToCanonicalString())
}

// Equal mirrors RoleDescriptor.Equals: canonical-string equality.
func (d RoleDescriptor) Equal(other RoleDescriptor) bool {
	return d.ToCanonicalString() == other.ToCanonicalString()
}

// Hash mirrors RoleDescriptor.GetHashCode: the 32-bit FNV-1a hash of the
// canonical digest input, byte for byte.
func (d RoleDescriptor) Hash() int32 {
	const offset uint32 = 2166136261
	const prime uint32 = 16777619
	hash := offset
	for _, value := range d.GetCanonicalDigestInput() {
		hash = (hash ^ uint32(value)) * prime
	}

	return int32(hash)
}

func joinRoleValues[T fmt.Stringer](values []T) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = value.String()
	}

	return strings.Join(parts, ",")
}

func joinRoleNumbers(values []int64) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.FormatInt(value, 10)
	}

	return strings.Join(parts, ",")
}

// stableEnumSet mirrors StableEnums: defined values only, no duplicates, ordered.
func stableEnumSet[T ~int](source []T, name string, isDefined func(T) bool) ([]T, error) {
	values := make([]T, 0, len(source))
	seen := make(map[T]struct{}, len(source))
	for _, value := range source {
		if !isDefined(value) {
			return nil, fmt.Errorf("Unknown enum value. (Parameter '%s')", name)
		}

		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("Duplicate values are not allowed. (Parameter '%s')", name)
		}

		seen[value] = struct{}{}
		values = append(values, value)
	}

	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values, nil
}

// stablePorts mirrors StableValues for ports: keyed by (protocol, port), no duplicates, ordered.
func stablePorts(source []NetworkPort) ([]NetworkPort, error) {
	values := make([]NetworkPort, 0, len(source))
	seen := make(map[NetworkPort]struct{}, len(source))
	for _, port := range source {
		if _, duplicate := seen[port]; duplicate {
			return nil, errors.New("Duplicate values are not allowed. (Parameter 'ports')")
		}

		seen[port] = struct{}{}
		values = append(values, port)
	}

	sort.Slice(values, func(i, j int) bool {
		if values[i].Protocol != values[j].Protocol {
			return values[i].Protocol < values[j].Protocol
		}

		return values[i].Port < values[j].Port
	})
	return values, nil
}

// stableSecretProfiles mirrors StableValues for secret profiles: keyed by the
// profile id (ordinal), no duplicates, ordered.
func stableSecretProfiles(source []SecretProfileReference) ([]SecretProfileReference, error) {
	values := make([]SecretProfileReference, 0, len(source))
	seen := make(map[string]struct{}, len(source))
	for _, profile := range source {
		if profile.ProfileId.Value == "" {
			return nil, errors.New("Null values are not allowed. (Parameter 'secretProfiles')")
		}

		if _, duplicate := seen[profile.ProfileId.Value]; duplicate {
			return nil, errors.New("Duplicate values are not allowed. (Parameter 'secretProfiles')")
		}

		seen[profile.ProfileId.Value] = struct{}{}
		values = append(values, profile)
	}

	sort.SliceStable(values, func(i, j int) bool {
		return values[i].ProfileId.Value < values[j].ProfileId.Value
	})
	return values, nil
}
