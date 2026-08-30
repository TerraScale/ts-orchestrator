// This file ports Runtime/Mcp/McpWorkloadContract.cs.
package runtime

import (
	"fmt"
	"regexp"
	"strconv"
)

// Canonical public route and host-owned application paths of the MCP product
// workload (ADR 0032). They are string constants recorded in the typed
// manifest; they are not live DNS or ingress bindings.
const (
	// McpPublicRoutesCanonicalHost is the canonical public host. TLS terminates
	// at the shared product edge and forwarding preserves the host's HTTPS
	// requirement; the workload never serves plain HTTP publicly.
	McpPublicRoutesCanonicalHost = "mcp.terrascale.tech"

	// McpPublicRoutesMcpPath is the canonical MCP application path owned by the
	// workload host.
	McpPublicRoutesMcpPath = "/mcp"

	// McpPublicRoutesCanonicalRoute is the canonical public MCP endpoint.
	McpPublicRoutesCanonicalRoute = "https://" + McpPublicRoutesCanonicalHost + McpPublicRoutesMcpPath

	// McpPublicRoutesProtectedResourceMetadataPath is the OAuth 2.0
	// protected-resource metadata path owned by the workload host.
	McpPublicRoutesProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource/mcp"

	// McpPublicRoutesLivenessPath is the host-owned liveness path.
	McpPublicRoutesLivenessPath = "/health/live"

	// McpPublicRoutesReadinessPath is the host-owned readiness path.
	McpPublicRoutesReadinessPath = "/health/ready"
)

// McpRouteKind is the closed route-kind vocabulary owned by the MCP host.
type McpRouteKind int

const (
	McpRouteKindMcpEndpoint McpRouteKind = iota
	McpRouteKindProtectedResourceMetadata
	McpRouteKindLiveness
	McpRouteKindReadiness
)

func (k McpRouteKind) defined() bool {
	return k >= McpRouteKindMcpEndpoint && k <= McpRouteKindReadiness
}

func (k McpRouteKind) String() string {
	names := [...]string{
		"McpEndpoint", "ProtectedResourceMetadata", "Liveness", "Readiness",
	}
	if k >= 0 && int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("McpRouteKind(%d)", int(k))
}

// McpPublicRouteView is the redacted public projection of one MCP route.
// Redacted by construction: it carries only the route kind, host, path,
// transport requirement, and routability. Project identifiers, caller identity,
// credentials, and internal diagnostics have no field to live in, so no mapping
// produced from this type can expose them.
type McpPublicRouteView struct {
	Kind              McpRouteKind
	Host              string
	Path              string
	HttpsRequired     bool
	PubliclyRoutable  bool
}

// MarshalJSON mirrors the C# JsonPropertyName wire names, with the kind
// serialized as its numeric enum value (no string converter is applied there).
func (v McpPublicRouteView) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"kind":%d,"host":%q,"path":%q,"httpsRequired":%s,"publiclyRoutable":%s}`,
		int(v.Kind), v.Host, v.Path,
		strconv.FormatBool(v.HttpsRequired), strconv.FormatBool(v.PubliclyRoutable))), nil
}

func mcpIsPubliclyRoutable(kind McpRouteKind) bool {
	return kind == McpRouteKindMcpEndpoint || kind == McpRouteKindProtectedResourceMetadata
}

// McpRouteContract is the closed MCP route mapping: exactly the canonical
// endpoint, the protected-resource metadata route, and the two health routes,
// all on the canonical HTTPS host.
var McpRouteContract = struct {
	McpEndpoint              McpPublicRouteView
	ProtectedResourceMetadata McpPublicRouteView
	Liveness                 McpPublicRouteView
	Readiness                McpPublicRouteView
	All                      []McpPublicRouteView
	AdmittedProbePaths       []string
}{
	McpEndpoint: McpPublicRouteView{
		Kind:             McpRouteKindMcpEndpoint,
		Host:             McpPublicRoutesCanonicalHost,
		Path:             McpPublicRoutesMcpPath,
		HttpsRequired:    true,
		PubliclyRoutable: mcpIsPubliclyRoutable(McpRouteKindMcpEndpoint),
	},
	ProtectedResourceMetadata: McpPublicRouteView{
		Kind:             McpRouteKindProtectedResourceMetadata,
		Host:             McpPublicRoutesCanonicalHost,
		Path:             McpPublicRoutesProtectedResourceMetadataPath,
		HttpsRequired:    true,
		PubliclyRoutable: mcpIsPubliclyRoutable(McpRouteKindProtectedResourceMetadata),
	},
	Liveness: McpPublicRouteView{
		Kind:             McpRouteKindLiveness,
		Host:             McpPublicRoutesCanonicalHost,
		Path:             McpPublicRoutesLivenessPath,
		HttpsRequired:    true,
		PubliclyRoutable: mcpIsPubliclyRoutable(McpRouteKindLiveness),
	},
	Readiness: McpPublicRouteView{
		Kind:             McpRouteKindReadiness,
		Host:             McpPublicRoutesCanonicalHost,
		Path:             McpPublicRoutesReadinessPath,
		HttpsRequired:    true,
		PubliclyRoutable: mcpIsPubliclyRoutable(McpRouteKindReadiness),
	},
	AdmittedProbePaths: []string{McpPublicRoutesLivenessPath, McpPublicRoutesReadinessPath},
}

func init() {
	McpRouteContract.All = []McpPublicRouteView{
		McpRouteContract.McpEndpoint,
		McpRouteContract.ProtectedResourceMetadata,
		McpRouteContract.Liveness,
		McpRouteContract.Readiness,
	}
}

// McpWorkloadPortsHttpListenerPort is the single admitted host-local HTTP
// listener port. A distinct port may be assigned only through an ADR-0032
// catalog change after deployment qualification.
const McpWorkloadPortsHttpListenerPort = 18675

// The closed set of approved MCP configuration keys. Values are bounded,
// non-secret configuration only.
const (
	McpConfigurationKeysPublicBaseUrl           = "public-base-url"
	McpConfigurationKeysAuthenticationIssuerUrl = "authentication-issuer-url"
	McpConfigurationKeysDashboardApiBaseUrl     = "dashboard-api-base-url"
	McpConfigurationKeysMinimumLogLevel         = "minimum-log-level"
)

// McpConfigurationKeys holds the approved key set and its HTTPS-URL subset.
var McpConfigurationKeys = struct {
	PublicBaseUrl           string
	AuthenticationIssuerUrl string
	DashboardApiBaseUrl     string
	MinimumLogLevel         string
	All                     []string
	HttpsUrlKeys            []string
}{
	PublicBaseUrl:           McpConfigurationKeysPublicBaseUrl,
	AuthenticationIssuerUrl: McpConfigurationKeysAuthenticationIssuerUrl,
	DashboardApiBaseUrl:     McpConfigurationKeysDashboardApiBaseUrl,
	MinimumLogLevel:         McpConfigurationKeysMinimumLogLevel,
	All: []string{
		McpConfigurationKeysPublicBaseUrl,
		McpConfigurationKeysAuthenticationIssuerUrl,
		McpConfigurationKeysDashboardApiBaseUrl,
		McpConfigurationKeysMinimumLogLevel,
	},
	HttpsUrlKeys: []string{
		McpConfigurationKeysPublicBaseUrl,
		McpConfigurationKeysAuthenticationIssuerUrl,
		McpConfigurationKeysDashboardApiBaseUrl,
	},
}

// McpSecretReference constants.
const (
	McpSecretReferenceScheme            = "vault"
	McpSecretReferenceAdmittedPathPrefix = "terrascale/mcp/"
	McpSecretReferenceMaximumLength      = 128
)

// McpSecretReference is one bounded vault path token: it names WHERE the
// confidential material lives; the bytes are delivered by the runtime
// credential mechanism at execution time and never appear in desired state,
// manifests, journals, logs, or evidence.
type McpSecretReference struct {
	Value string
}

var mcpSecretReferenceTokenPattern = regexp.MustCompile(
	`^vault:terrascale/mcp/[a-z0-9][a-z0-9-]{0,62}$`)

// McpSecretReferenceNamesOAuthClientSecret is the admitted secret reference
// name for the MCP workload: the confidential OAuth client secret, admitted BY
// REFERENCE only.
const McpSecretReferenceNamesOAuthClientSecret = "oauth-client-secret"

var mcpSecretReferenceNames = []string{McpSecretReferenceNamesOAuthClientSecret}

// NewMcpSecretReference validates the bounded reference token.
func NewMcpSecretReference(value string) (McpSecretReference, error) {
	if len(value) > McpSecretReferenceMaximumLength || !mcpSecretReferenceTokenPattern.MatchString(value) {
		return McpSecretReference{}, &ArgumentError{
			Param: "value",
			Message: "A MCP secret reference must be a bounded " +
				"'vault:terrascale/mcp/<name>' token.",
		}
	}
	if !containsStringValue(mcpSecretReferenceNames, mcpSecretReferenceName(value)) {
		return McpSecretReference{}, &ArgumentError{
			Param: "value",
			Message: fmt.Sprintf(
				"The MCP secret reference '%s' is not admitted; only '%s' may be referenced.",
				value, joinQuoted(mcpSecretReferenceNames)),
		}
	}
	return McpSecretReference{Value: value}, nil
}

// Name returns the reference name after the admitted path prefix.
func (r McpSecretReference) Name() string {
	return mcpSecretReferenceName(r.Value)
}

func mcpSecretReferenceName(value string) string {
	return value[len(McpSecretReferenceScheme)+1+len(McpSecretReferenceAdmittedPathPrefix):]
}

func containsStringValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func joinQuoted(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += "', '"
		}
		result += value
	}
	return result
}

// McpSecretReferenceContractDefault is the canonical OAuth client secret
// reference (reference only, never bytes).
var McpSecretReferenceContractDefault = mustMcpSecretReference(
	McpSecretReferenceScheme + ":" + McpSecretReferenceAdmittedPathPrefix +
		McpSecretReferenceNamesOAuthClientSecret)

// McpSecretReferenceContractAdmitted is the closed set of admissible
// references.
var McpSecretReferenceContractAdmitted = []McpSecretReference{McpSecretReferenceContractDefault}

func mustMcpSecretReference(value string) McpSecretReference {
	reference, err := NewMcpSecretReference(value)
	if err != nil {
		panic(err)
	}
	return reference
}

// McpQualifiedHttpArtifactDigestLength bounds a qualified digest.
const McpQualifiedHttpArtifactDigestLength = 64

// McpQualifiedHttpArtifact is one exact digest bound to one architecture.
type McpQualifiedHttpArtifact struct {
	Digest       string
	Architecture HostArchitecture
}

// NewMcpQualifiedHttpArtifact validates the digest and architecture.
func NewMcpQualifiedHttpArtifact(digest string, architecture HostArchitecture) (McpQualifiedHttpArtifact, error) {
	if len(digest) != McpQualifiedHttpArtifactDigestLength || !isLowercaseHexDigest(digest) {
		return McpQualifiedHttpArtifact{}, &ArgumentError{
			Param:   "digest",
			Message: "A qualified MCP artifact digest must be lowercase SHA-256 hex.",
		}
	}
	if !architecture.defined() {
		return McpQualifiedHttpArtifact{}, &ArgumentError{
			Param:   "architecture",
			Message: "The MCP artifact architecture is not admitted.",
		}
	}
	return McpQualifiedHttpArtifact{Digest: digest, Architecture: architecture}, nil
}

// McpHttpArtifactQualification is the qualified MCP HTTP artifact set.
// Fail-closed by construction: McpHttpArtifactQualificationNone admits no
// artifact, so nothing is deployable until qualification evidence registers
// exact digests. Digests enter this set only from accepted qualification
// evidence, never from a delivery request.
type McpHttpArtifactQualification struct {
	artifacts []McpQualifiedHttpArtifact
	digestsByArchitecture map[HostArchitecture][]string
}

// McpHttpArtifactQualificationNone admits no artifact.
var McpHttpArtifactQualificationNone = &McpHttpArtifactQualification{}

// NewMcpHttpArtifactQualification builds a qualification from exact evidence.
// Multiple digests per architecture are allowed (the current and prior
// qualified releases), but digest/architecture pairs must be distinct.
func NewMcpHttpArtifactQualification(artifacts ...McpQualifiedHttpArtifact) (*McpHttpArtifactQualification, error) {
	for index := range artifacts {
		for other := index + 1; other < len(artifacts); other++ {
			if artifacts[index] == artifacts[other] {
				return nil, &ArgumentError{
					Message: "A digest/architecture pair may appear exactly once in a qualification.",
				}
			}
		}
	}
	qualification := &McpHttpArtifactQualification{
		artifacts:             append([]McpQualifiedHttpArtifact{}, artifacts...),
		digestsByArchitecture: make(map[HostArchitecture][]string),
	}
	for _, artifact := range artifacts {
		qualification.digestsByArchitecture[artifact.Architecture] = append(
			qualification.digestsByArchitecture[artifact.Architecture], artifact.Digest)
	}
	return qualification, nil
}

// Artifacts returns the qualified artifact snapshot.
func (q *McpHttpArtifactQualification) Artifacts() []McpQualifiedHttpArtifact {
	snapshot := make([]McpQualifiedHttpArtifact, len(q.artifacts))
	copy(snapshot, q.artifacts)
	return snapshot
}

// Admits reports whether the exact digest is qualified for the architecture.
func (q *McpHttpArtifactQualification) Admits(digest string, architecture HostArchitecture) bool {
	qualified, present := q.digestsByArchitecture[architecture]
	return present && containsStringValue(qualified, digest)
}

// AdmitsArchitecture reports whether any artifact is qualified for the
// architecture.
func (q *McpHttpArtifactQualification) AdmitsArchitecture(architecture HostArchitecture) bool {
	_, present := q.digestsByArchitecture[architecture]
	return present
}

// McpIngressEvidence is the live evidence an open MCP ingress requires.
// Absence of any item keeps ingress closed.
type McpIngressEvidence struct {
	AuthenticationVerified bool
	ScopeDenialVerified    bool
	TenantIsolationVerified bool
	HealthVerified         bool
	RollbackVerified       bool
}

// IsComplete reports whether every evidence bit is set.
func (e McpIngressEvidence) IsComplete() bool {
	return e.AuthenticationVerified && e.ScopeDenialVerified &&
		e.TenantIsolationVerified && e.HealthVerified && e.RollbackVerified
}

// McpIngressEvidenceNone carries no evidence.
var McpIngressEvidenceNone = McpIngressEvidence{}

// McpIngressState is the open/closed ingress state.
type McpIngressState int

const (
	McpIngressStateClosed McpIngressState = iota
	McpIngressStateOpen
)

// McpIngressGate keeps ingress closed until the complete live evidence bundle
// passes.
var McpIngressGate mcpIngressGate

type mcpIngressGate struct{}

// Evaluate applies the fail-closed evidence gate.
func (mcpIngressGate) Evaluate(evidence *McpIngressEvidence) McpIngressState {
	if evidence != nil && evidence.IsComplete() {
		return McpIngressStateOpen
	}
	return McpIngressStateClosed
}

// McpPlacementContract constants of the stateless MCP placement.
const (
	// McpPlacementContractMinimumInstances is the admission floor: two
	// instances in independent failure domains, independently routed.
	McpPlacementContractMinimumInstances = 2

	// McpPlacementContractStickySessions is always false: requests carry no
	// session affinity.
	McpPlacementContractStickySessions = false
)

// McpProductRouteEntry is one named product route in the operator table.
type McpProductRouteEntry struct {
	Name string
	Open bool
}

// McpProductRouteTableMcpRouteName is the MCP route name.
const McpProductRouteTableMcpRouteName = "mcp"

// McpProductRouteTable is the operator view of product routes.
type McpProductRouteTable struct {
	Routes []McpProductRouteEntry
}

// McpProductRouteTableWithRoutesOpen builds a table with every named route open.
func McpProductRouteTableWithRoutesOpen(names []string) McpProductRouteTable {
	routes := make([]McpProductRouteEntry, len(names))
	for index, name := range names {
		routes[index] = McpProductRouteEntry{Name: name, Open: true}
	}
	return McpProductRouteTable{Routes: routes}
}

// IsOpen reports whether the named route is open.
func (t McpProductRouteTable) IsOpen(name string) bool {
	for _, route := range t.Routes {
		if route.Name == name && route.Open {
			return true
		}
	}
	return false
}

// OpenRouteNames lists the open route names in table order.
func (t McpProductRouteTable) OpenRouteNames() []string {
	var open []string
	for _, route := range t.Routes {
		if route.Open {
			open = append(open, route.Name)
		}
	}
	return open
}

// McpStdioDistributionChannelChannelName is the stdio MCP distribution channel:
// artifacts customers run locally, outside this control plane's HTTP route
// table.
const McpStdioDistributionChannelChannelName = "stdio"

// McpRouteWithdrawal is the typed result of an emergency MCP route withdrawal.
type McpRouteWithdrawal struct {
	ClosedRoutes                 []string
	UntouchedRoutes              []string
	UntouchedDistributionChannels []string
	RemainingRoutes              McpProductRouteTable
}

// McpEmergencyRouteControl performs the emergency withdrawal of the MCP route.
var McpEmergencyRouteControl mcpEmergencyRouteControl

type mcpEmergencyRouteControl struct{}

// Withdraw closes ONLY the MCP HTTP route: every other product route and the
// separately distributed stdio artifacts are untouched. Withdrawal is an
// operator route action, not a workload mutation; instances and artifacts are
// left alone.
func (mcpEmergencyRouteControl) Withdraw(table McpProductRouteTable) McpRouteWithdrawal {
	var closed, untouched []string
	remaining := make([]McpProductRouteEntry, len(table.Routes))
	copy(remaining, table.Routes)
	for index, route := range table.Routes {
		if route.Name == McpProductRouteTableMcpRouteName {
			closed = append(closed, route.Name)
			remaining[index] = McpProductRouteEntry{Name: route.Name, Open: false}
		} else {
			untouched = append(untouched, route.Name)
		}
	}
	return McpRouteWithdrawal{
		ClosedRoutes:                 closed,
		UntouchedRoutes:              untouched,
		UntouchedDistributionChannels: []string{McpStdioDistributionChannelChannelName},
		RemainingRoutes:              McpProductRouteTable{Routes: remaining},
	}
}
