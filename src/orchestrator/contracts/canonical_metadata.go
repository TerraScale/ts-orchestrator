package contracts

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// canonicalTextToken mirrors the internal CanonicalText.Token helper. The
// message matches the C# ArgumentException text.
func canonicalTextToken(value, parameterName string, maximumLength int) (string, error) {
	if len(value) < 1 || len(value) > maximumLength || !canonicalTokenPattern(value) {
		return "", fmt.Errorf("Value must be a 1-%d character canonical lowercase token. (Parameter '%s')",
			maximumLength, parameterName)
	}

	return value, nil
}

// canonicalTokenPattern mirrors the generated regex ^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$.
func canonicalTokenPattern(value string) bool {
	runes := []rune(value)
	if len(runes) == 0 {
		return false
	}

	first := runes[0]
	if first < 'a' || first > 'z' {
		return false
	}

	index := 1
	for index < len(runes) {
		separator := runes[index]
		if separator != '.' && separator != '-' {
			return false
		}

		index++
		start := index
		for index < len(runes) && runes[index] >= 'a' && runes[index] <= 'z' ||
			runes[index] >= '0' && runes[index] <= '9' {
			index++
		}

		if index == start {
			return false
		}
	}

	return true
}

const apiVersionOne = "terrascale.io/orchestrator/v1"

// ApiVersion is the canonical resource API version. The zero value is
// meaningless; obtain one through ApiVersionV1 or ApiVersionParse.
type ApiVersion struct {
	Value string
}

// ApiVersionV1 mirrors ApiVersion.V1.
var ApiVersionV1 = ApiVersion{Value: apiVersionOne}

// ApiVersionParse mirrors ApiVersion.Parse and fails closed on every unknown
// or noncanonical value.
func ApiVersionParse(value string) (ApiVersion, error) {
	if value == apiVersionOne {
		return ApiVersionV1, nil
	}

	return ApiVersion{}, errors.New("Unknown or noncanonical API version. (Parameter 'value')")
}

func (v ApiVersion) String() string { return v.Value }

// ResourceId is a canonical lowercase resource identifier.
type ResourceId struct {
	Value string
}

const (
	// ResourceIdMaximumLength mirrors ResourceId.MaximumLength.
	ResourceIdMaximumLength = 63
	// ResourceIdJsonSchemaPattern mirrors ResourceId.JsonSchemaPattern.
	ResourceIdJsonSchemaPattern = "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$"
)

// NewResourceId mirrors the ResourceId constructor (canonical token, at most
// ResourceIdMaximumLength characters).
func NewResourceId(value string) (ResourceId, error) {
	token, err := canonicalTextToken(value, "value", ResourceIdMaximumLength)
	if err != nil {
		return ResourceId{}, err
	}

	return ResourceId{Value: token}, nil
}

func (i ResourceId) String() string { return i.Value }

// Generation is a nonzero resource generation.
type Generation struct {
	Value uint64
}

// NewGeneration mirrors the Generation constructor; generation zero is invalid.
func NewGeneration(value uint64) (Generation, error) {
	if value == 0 {
		return Generation{}, errors.New("Generation zero is invalid. (Parameter 'value')")
	}

	return Generation{Value: value}, nil
}

func (g Generation) String() string { return strconv.FormatUint(g.Value, 10) }

// ResourceVersion is a nonzero resource version.
type ResourceVersion struct {
	Value uint64
}

// NewResourceVersion mirrors the ResourceVersion constructor.
func NewResourceVersion(value uint64) (ResourceVersion, error) {
	if value == 0 {
		return ResourceVersion{}, errors.New("Resource version zero is invalid. (Parameter 'value')")
	}

	return ResourceVersion{Value: value}, nil
}

func (v ResourceVersion) String() string { return strconv.FormatUint(v.Value, 10) }

// AuthorityKind mirrors the AuthorityKind enum.
type AuthorityKind int

const (
	AuthorityKindUnspecified        AuthorityKind = 0
	AuthorityKindGlobalController   AuthorityKind = 1
	AuthorityKindRegionalController AuthorityKind = 2
	AuthorityKindDomainController   AuthorityKind = 3
)

func (k AuthorityKind) String() string {
	switch k {
	case AuthorityKindGlobalController:
		return "GlobalController"
	case AuthorityKindRegionalController:
		return "RegionalController"
	case AuthorityKindDomainController:
		return "DomainController"
	default:
		return strconv.Itoa(int(k))
	}
}

func authorityKindIsDefined(k AuthorityKind) bool {
	return k >= AuthorityKindGlobalController && k <= AuthorityKindDomainController
}

// ResourceOwnership names the authority that owns a resource.
type ResourceOwnership struct {
	Kind        AuthorityKind
	AuthorityId ResourceId
}

// NewResourceOwnership mirrors the ResourceOwnership constructor.
func NewResourceOwnership(kind AuthorityKind, authorityId ResourceId) (ResourceOwnership, error) {
	if !authorityKindIsDefined(kind) {
		return ResourceOwnership{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'kind', actual value %d)", int(kind))
	}

	if authorityId.Value == "" {
		return ResourceOwnership{}, errors.New("Value cannot be null. (Parameter 'authorityId')")
	}

	return ResourceOwnership{Kind: kind, AuthorityId: authorityId}, nil
}

// CreationActorKind mirrors the CreationActorKind enum.
type CreationActorKind int

const (
	CreationActorKindUnspecified CreationActorKind = 0
	CreationActorKindBootstrap   CreationActorKind = 1
	CreationActorKindController  CreationActorKind = 2
	CreationActorKindGitOps      CreationActorKind = 3
	CreationActorKindOperator    CreationActorKind = 4
)

func (k CreationActorKind) String() string {
	switch k {
	case CreationActorKindBootstrap:
		return "Bootstrap"
	case CreationActorKindController:
		return "Controller"
	case CreationActorKindGitOps:
		return "GitOps"
	case CreationActorKindOperator:
		return "Operator"
	default:
		return strconv.Itoa(int(k))
	}
}

func creationActorKindIsDefined(k CreationActorKind) bool {
	return k >= CreationActorKindBootstrap && k <= CreationActorKindOperator
}

// CreationActor names the actor that created a resource.
type CreationActor struct {
	Kind    CreationActorKind
	ActorId ResourceId
}

// NewCreationActor mirrors the CreationActor constructor.
func NewCreationActor(kind CreationActorKind, actorId ResourceId) (CreationActor, error) {
	if !creationActorKindIsDefined(kind) {
		return CreationActor{}, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'kind', actual value %d)", int(kind))
	}

	if actorId.Value == "" {
		return CreationActor{}, errors.New("Value cannot be null. (Parameter 'actorId')")
	}

	return CreationActor{Kind: kind, ActorId: actorId}, nil
}

// AuditCorrelationId is a canonical audit correlation token.
type AuditCorrelationId struct {
	Value string
}

// NewAuditCorrelationId mirrors the AuditCorrelationId constructor (63-character default bound).
func NewAuditCorrelationId(value string) (AuditCorrelationId, error) {
	token, err := canonicalTextToken(value, "value", 63)
	if err != nil {
		return AuditCorrelationId{}, err
	}

	return AuditCorrelationId{Value: token}, nil
}

func (i AuditCorrelationId) String() string { return i.Value }

// ResourceMetadata is the canonical metadata header of every resource.
type ResourceMetadata struct {
	ApiVersion         ApiVersion
	Id                 ResourceId
	Generation         Generation
	ResourceVersion    ResourceVersion
	Ownership          ResourceOwnership
	CreationActor      CreationActor
	AuditCorrelationId AuditCorrelationId
}

// NewResourceMetadata mirrors the ResourceMetadata constructor; a zero value
// in any member field stands in for the C# null argument and fails.
func NewResourceMetadata(
	apiVersion ApiVersion,
	id ResourceId,
	generation Generation,
	resourceVersion ResourceVersion,
	ownership ResourceOwnership,
	creationActor CreationActor,
	auditCorrelationId AuditCorrelationId,
) (ResourceMetadata, error) {
	if apiVersion.Value == "" {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'apiVersion')")
	}

	if id.Value == "" {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'id')")
	}

	if generation.Value == 0 {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'generation')")
	}

	if resourceVersion.Value == 0 {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'resourceVersion')")
	}

	if ownership.AuthorityId.Value == "" || ownership.Kind == AuthorityKindUnspecified {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'ownership')")
	}

	if creationActor.ActorId.Value == "" || creationActor.Kind == CreationActorKindUnspecified {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'creationActor')")
	}

	if auditCorrelationId.Value == "" {
		return ResourceMetadata{}, errors.New("Value cannot be null. (Parameter 'auditCorrelationId')")
	}

	return ResourceMetadata{
		ApiVersion:         apiVersion,
		Id:                 id,
		Generation:         generation,
		ResourceVersion:    resourceVersion,
		Ownership:          ownership,
		CreationActor:      creationActor,
		AuditCorrelationId: auditCorrelationId,
	}, nil
}

// ToCanonicalString produces the pipe-joined canonical projection used by digests.
func (m ResourceMetadata) ToCanonicalString() string {
	return strings.Join([]string{
		"apiVersion=" + m.ApiVersion.String(),
		"id=" + m.Id.String(),
		"generation=" + m.Generation.String(),
		"resourceVersion=" + m.ResourceVersion.String(),
		"owner=" + m.Ownership.Kind.String() + ":" + m.Ownership.AuthorityId.String(),
		"createdBy=" + m.CreationActor.Kind.String() + ":" + m.CreationActor.ActorId.String(),
		"audit=" + m.AuditCorrelationId.String(),
	}, "|")
}

// GetCanonicalDigestInput returns the UTF-8 bytes of the canonical projection.
func (m ResourceMetadata) GetCanonicalDigestInput() []byte {
	return []byte(m.ToCanonicalString())
}
