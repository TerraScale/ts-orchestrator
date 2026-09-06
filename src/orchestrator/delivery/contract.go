// Package delivery owns the orchestrator's half of the D-67 signed delivery
// API: the version-1 wire contract shared with ts-deploy (D-68), artifact
// verification and per-Region mirroring (D-71), the canary-to-rolling rollout
// state machine with drain, health, and catch-up gates, automatic rollback,
// the 24-hour key rotation machinery (D-70), and the internal SPIFFE
// certificate authority (D-02). The package never opens a network connection
// itself: fetchers, mirrors, host control, edge promotion, and secret stores
// are injected seams.
package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

// The types, bounds, and validators in this file are the mirror of
// ts-deploy's internal/cli/handoff/deliverycontracts.go (version 1). The two
// live in different repositories, so parity is enforced by the golden JSON
// fixtures in testdata/ and by refusing to emit a receipt this file's own
// receipt validator would reject. Additive changes only: new optional fields
// or new enum values, never renames.

const (
	// ContractVersion is the one admitted delivery schema version.
	ContractVersion = 1
	// MaxDocumentBytes is the request and receipt document bound.
	MaxDocumentBytes = 1_048_576
	// MaxArtifactBytes is the release artifact bound ts-deploy enforces
	// client-side; the orchestrator refuses anything larger fail closed.
	MaxArtifactBytes = 512 << 20

	maxText      = 256
	maxReason    = 1_024
	maxRegions   = 32
	maxJSONDepth = 8
)

// Source is the exact source revision that produced the artifact.
type Source struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	TreeDigest string `json:"treeDigest"`
}

// Artifact is the exact trusted artifact identity of a delivery.
type Artifact struct {
	Name                    string `json:"name"`
	ManifestName            string `json:"manifestName"`
	Digest                  string `json:"digest"`
	SignatureDigest         string `json:"signatureDigest"`
	ManifestDigest          string `json:"manifestDigest"`
	ManifestSignatureDigest string `json:"manifestSignatureDigest"`
	Kind                    string `json:"kind"`
	Architecture            string `json:"architecture"`
}

// RollbackArtifact is the exact prior artifact a rollback returns to.
type RollbackArtifact struct {
	ArtifactDigest string `json:"artifactDigest"`
	ManifestDigest string `json:"manifestDigest"`
	Kind           string `json:"kind"`
	Architecture   string `json:"architecture"`
}

// Informational carries optional notes and notification channels.
type Informational struct {
	Notes                *string   `json:"notes"`
	NotificationChannels *[]string `json:"notificationChannels"`
}

// Target names the service, environment, and Regions of a delivery.
type Target struct {
	Service     string   `json:"service"`
	Environment string   `json:"environment"`
	Regions     []string `json:"regions"`
}

// Request is the version-1 DeliveryRequest ts-deploy POSTs.
type Request struct {
	SchemaVersion         int               `json:"schemaVersion"`
	OperationID           string            `json:"operationId"`
	Source                *Source           `json:"source"`
	Artifact              *Artifact         `json:"artifact"`
	Target                *Target           `json:"target"`
	ConfigurationRevision string            `json:"configurationRevision"`
	MigrationRevision     *string           `json:"migrationRevision"`
	RequestedBy           string            `json:"requestedBy"`
	Reason                string            `json:"reason"`
	Rollback              *RollbackArtifact `json:"rollback"`
	Informational         *Informational    `json:"informational"`
}

// Provenance reports whether the artifact identity was verified and the
// revisions it was verified against.
type Provenance struct {
	Verified              bool    `json:"verified"`
	ConfigurationRevision string  `json:"configurationRevision"`
	MigrationRevision     *string `json:"migrationRevision"`
}

// HealthCheck is one named gate result of the rollout.
type HealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Health is the aggregated gate result; Checks marshals null when nil,
// matching the nullable list contract.
type Health struct {
	Checks    []*HealthCheck `json:"checks"`
	Converged bool           `json:"converged"`
}

// Rollback is the rollback outcome of a delivery.
type Rollback struct {
	Attempted            bool    `json:"attempted"`
	TargetArtifactDigest *string `json:"targetArtifactDigest"`
	Status               string  `json:"status"`
	TargetManifestDigest *string `json:"targetManifestDigest"`
}

// Error is the typed, actionable error document of a failed delivery.
type Error struct {
	Code        *string `json:"code"`
	Message     *string `json:"message"`
	Remediation *string `json:"remediation"`
}

// Receipt is the version-1 DeliveryReceipt the orchestrator publishes; every
// receipt the API returns or stores passes ValidateReceipt against its
// request before leaving this package.
type Receipt struct {
	SchemaVersion          int         `json:"schemaVersion"`
	OperationID            string      `json:"operationId"`
	Status                 string      `json:"status"`
	Source                 *Source     `json:"source"`
	ArtifactDigest         *string     `json:"artifactDigest"`
	Target                 *Target     `json:"target"`
	Provenance             *Provenance `json:"provenance"`
	Health                 *Health     `json:"health"`
	Rollback               *Rollback   `json:"rollback"`
	AuditID                string      `json:"auditId"`
	Error                  *Error      `json:"error"`
	ArtifactManifestDigest *string     `json:"artifactManifestDigest"`
}

// Receipt statuses (the closed set the contract validates).
const (
	StatusSucceeded  = "succeeded"
	StatusFailed     = "failed"
	StatusRolledBack = "rolled_back"
)

// Rollback statuses.
const (
	RollbackNotRequired = "not_required"
	RollbackSucceeded   = "succeeded"
	RollbackFailed      = "failed"
)

// ValidationError is the typed rejection of a document that does not match
// the version-1 contract. Code values are shared with ts-deploy.
type ValidationError struct {
	Code        string
	Message     string
	Remediation string
}

func (e *ValidationError) Error() string { return e.Message }

// AsValidationError extracts a ValidationError.
func AsValidationError(err error) (*ValidationError, bool) {
	var validationError *ValidationError
	if errors.As(err, &validationError) {
		return validationError, true
	}
	return nil, false
}

// ParseRequest decodes one version-1 DeliveryRequest, rejecting unknown
// fields, trailing data, excessive depth, and oversized documents exactly as
// ts-deploy's codec does.
func ParseRequest(jsonText string) (*Request, error) {
	return deserialize[Request](jsonText, "delivery_request_invalid")
}

// ParseReceipt decodes one version-1 DeliveryReceipt under the same rules.
func ParseReceipt(jsonText string) (*Receipt, error) {
	return deserialize[Receipt](jsonText, "delivery_receipt_invalid")
}

func deserialize[T any](jsonText, code string) (*T, error) {
	if strings.TrimSpace(jsonText) == "" || len(jsonText) > MaxDocumentBytes {
		return nil, &ValidationError{
			Code:        code,
			Message:     "The delivery document is empty or too large.",
			Remediation: "Provide a UTF-8 JSON document smaller than 1 MiB.",
		}
	}
	if err := rejectDuplicateJSON([]byte(jsonText)); err != nil {
		return nil, &ValidationError{Code: code, Message: "The delivery document contains duplicate or aliased fields.", Remediation: "Use each version-1 field exactly once with its exact camelCase name."}
	}
	var raw any
	if err := json.Unmarshal([]byte(jsonText), &raw); err != nil || !exactJSONFields(raw, reflect.TypeOf((*T)(nil)).Elem()) {
		return nil, &ValidationError{Code: code, Message: "The delivery document contains an aliased field.", Remediation: "Use exact version-1 JSON field names."}
	}
	if err := checkJSONDepth(jsonText, maxJSONDepth); err != nil {
		return nil, &ValidationError{
			Code:        code,
			Message:     "The delivery document is not valid version-1 JSON.",
			Remediation: "Check the field names and value types against the delivery contract.",
		}
	}
	decoder := json.NewDecoder(strings.NewReader(jsonText))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return nil, &ValidationError{
			Code:        code,
			Message:     "The delivery document is not valid version-1 JSON.",
			Remediation: "Check the field names and value types against the delivery contract.",
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, &ValidationError{
			Code:        code,
			Message:     "The delivery document is not valid version-1 JSON.",
			Remediation: "Check the field names and value types against the delivery contract.",
		}
	}
	return &value, nil
}

func exactJSONFields(value any, typ reflect.Type) bool {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return true
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "" {
				tag = field.Name
			}
			if tag != "-" {
				fields[tag] = field.Type
			}
		}
		for key, child := range object {
			fieldType, ok := fields[key]
			if !ok {
				for canonical := range fields {
					if strings.EqualFold(key, canonical) {
						return false
					}
				}
				continue
			}
			if !exactJSONFields(child, fieldType) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		items, ok := value.([]any)
		if !ok {
			return true
		}
		for _, item := range items {
			if !exactJSONFields(item, typ.Elem()) {
				return false
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return true
		}
		for _, item := range object {
			if !exactJSONFields(item, typ.Elem()) {
				return false
			}
		}
	}
	return true
}

func checkJSONDepth(jsonText string, maxDepth int) error {
	decoder := json.NewDecoder(strings.NewReader(jsonText))
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > maxDepth {
					return fmt.Errorf("json depth exceeds %d", maxDepth)
				}
			case '}', ']':
				depth--
			}
		}
	}
}

var (
	sha256Pattern      = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	secretPattern      = regexp.MustCompile(`(?i)(bearer\s+|(?:token|password|secret|private[_ -]?key|authorization)\s*[:=])`)
	commitPattern      = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	operationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Serialize renders one contract document as indented camelCase JSON
// terminated by a newline, matching ts-deploy's codec byte for byte in
// shape (two-space indent, HTML escaping off).
func Serialize(value any) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
	return buffer.String()
}

// ValidateRequest validates one decoded DeliveryRequest. The codes, order,
// and bounds mirror ts-deploy's DeliveryContractValidator exactly.
func ValidateRequest(request *Request) (err error) {
	defer validationRecover(&err)
	if request == nil {
		return &ValidationError{
			Code:        "request_required",
			Message:     "A delivery request is required.",
			Remediation: "Provide a non-null version-1 DeliveryRequest.",
		}
	}
	validateRequest(request)
	return nil
}

// ValidateReceipt validates one receipt against the request that produced
// it. The orchestrator runs this on every receipt before returning or
// storing it, so a receipt ts-deploy would reject can never leave the API.
func ValidateReceipt(receipt *Receipt, request *Request) (err error) {
	defer validationRecover(&err)
	if receipt == nil {
		return &ValidationError{
			Code:        "receipt_required",
			Message:     "A delivery receipt is required.",
			Remediation: "Provide a non-null version-1 DeliveryReceipt.",
		}
	}
	if request == nil {
		return &ValidationError{
			Code:        "request_required",
			Message:     "A delivery request is required to validate a receipt.",
			Remediation: "Provide the request that produced the receipt.",
		}
	}
	validateReceipt(receipt, request)
	return nil
}

func validationRecover(err *error) {
	if recovered := recover(); recovered != nil {
		if validationError, ok := recovered.(*ValidationError); ok {
			*err = validationError
			return
		}
		panic(recovered)
	}
}

// SameDigest compares two digests case-insensitively.
func SameDigest(actual, expected string) bool {
	return strings.EqualFold(actual, expected)
}

func ptr[T any](value T) *T { return &value }

func strPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func validateRequest(request *Request) {
	if request.SchemaVersion != ContractVersion {
		fail("schema_unsupported", "Only delivery schema version 1 is supported.", "Set schemaVersion to 1.")
	}
	if !operationIDPattern.MatchString(request.OperationID) {
		fail("operation_id_invalid", "operationId must be a single safe path component.", "Use 1-128 ASCII letters, digits, '.', '_' or '-'.")
	}
	if request.Source == nil && request.Artifact == nil {
		fail("source_or_artifact_required", "A source or exact artifact is required.", "Provide source for a build or artifact for an exact trusted delivery.")
	}
	if request.Source != nil {
		validateSource(request.Source)
	}
	if request.Artifact != nil {
		validateArtifact(request.Artifact)
	}
	if request.Target == nil {
		fail("target_required", "A delivery target is required.", "Provide service, environment, and regions.")
	}
	validateTarget(request.Target)
	if request.Rollback != nil {
		validateRollbackArtifact(request.Rollback, request.Artifact)
	}
	digestField(request.ConfigurationRevision, "configurationRevision")
	if request.MigrationRevision != nil {
		digestField(*request.MigrationRevision, "migrationRevision")
	}
	bounded(request.RequestedBy, maxText, "actor_invalid", "requestedBy")
	bounded(request.Reason, maxReason, "reason_invalid", "reason")
	secretFree(request.OperationID, "operationId")
	if request.Source != nil {
		secretFree(request.Source.Repository, "source.repository")
	}
	secretFree(request.Target.Service, "target.service")
	secretFree(request.Target.Environment, "target.environment")
	for _, region := range request.Target.Regions {
		secretFree(region, "target.regions")
	}
	secretFree(request.RequestedBy, "requestedBy")
	secretFree(request.Reason, "reason")
	validateInformational(request.Informational)
}

func validateReceipt(receipt *Receipt, request *Request) {
	validateRequest(request)
	if receipt.SchemaVersion != ContractVersion {
		fail("receipt_schema_unsupported", "The delivery receipt uses an unsupported schema.", "Retry with a version-1 Orchestrator endpoint.")
	}
	if receipt.OperationID != request.OperationID {
		fail("receipt_operation_mismatch", "The delivery receipt operation does not match the request.", "Retry the operation with the same operationId.")
	}
	if receipt.Target == nil || receipt.Provenance == nil || receipt.Health == nil || receipt.Rollback == nil || strings.TrimSpace(receipt.AuditID) == "" {
		fail("receipt_incomplete", "The delivery receipt is missing required fields.", "Retry against a version-1 Orchestrator endpoint.")
	}
	if receipt.Source != nil {
		validateSource(receipt.Source)
	}
	if request.Source != nil && receipt.Source == nil {
		fail("receipt_source_missing", "The delivery receipt omitted the requested source identity.", "Do not use this receipt. Retry with the exact source identity.")
	}
	if request.Source != nil && receipt.Source != nil &&
		(receipt.Source.Repository != request.Source.Repository ||
			receipt.Source.Commit != request.Source.Commit ||
			receipt.Source.TreeDigest != request.Source.TreeDigest) {
		fail("receipt_source_mismatch", "The delivery receipt source does not match the request.", "Do not use this receipt. Retry with the exact source identity.")
	}

	hasArtifactDigest := receipt.ArtifactDigest != nil
	hasArtifactManifestDigest := receipt.ArtifactManifestDigest != nil
	if hasArtifactDigest != hasArtifactManifestDigest {
		fail("receipt_artifact_identity_incomplete", "The delivery receipt contains only one half of the artifact identity.", "Retry against a version-1 Orchestrator endpoint that returns both artifact digests or neither.")
	}
	if receipt.ArtifactDigest != nil && receipt.ArtifactManifestDigest != nil {
		digestField(*receipt.ArtifactDigest, "artifactDigest")
		digestField(*receipt.ArtifactManifestDigest, "artifactManifestDigest")
		if request.Artifact != nil &&
			(!SameDigest(*receipt.ArtifactDigest, request.Artifact.Digest) ||
				!SameDigest(*receipt.ArtifactManifestDigest, request.Artifact.ManifestDigest)) {
			fail("receipt_artifact_mismatch", "The delivery receipt artifact does not match the request.", "Do not use this receipt. Retry with the exact artifact identity.")
		}
	}
	validateTarget(receipt.Target)
	if !sameTarget(receipt.Target, request.Target) {
		fail("receipt_target_mismatch", "The delivery receipt target does not match the request.", "Retry with the requested target.")
	}
	if !SameDigest(receipt.Provenance.ConfigurationRevision, request.ConfigurationRevision) ||
		!nullableDigestEquals(receipt.Provenance.MigrationRevision, request.MigrationRevision) {
		fail("receipt_provenance_mismatch", "The delivery receipt provenance does not match the request.", "Do not use this receipt. Retry with the exact configuration and migration revisions.")
	}
	healthChecks := receipt.Health.Checks
	if healthChecks == nil {
		fail("receipt_health_invalid", "The delivery receipt contains no health checks.", "Retry with a complete health result from Orchestrator.")
	}
	for _, check := range healthChecks {
		if check == nil || (check.Status != "passed" && check.Status != "failed") {
			fail("receipt_health_invalid", "The delivery receipt contains invalid health checks.", "Retry with a complete health result from Orchestrator.")
		}
	}
	if receipt.Status == StatusSucceeded {
		allPassed := true
		for _, check := range healthChecks {
			if check.Status != "passed" {
				allPassed = false
				break
			}
		}
		if receipt.ArtifactDigest == nil || receipt.ArtifactManifestDigest == nil || len(healthChecks) == 0 ||
			!receipt.Provenance.Verified || !receipt.Health.Converged || !allPassed {
			fail("receipt_success_unverified", "The receipt cannot report success without verified provenance and healthy convergence.", "Inspect the failed checks and retry after the target is healthy.")
		}
	}
	if receipt.Status == StatusSucceeded && receipt.Rollback.Status != RollbackNotRequired {
		fail("receipt_rollback_invalid", "A successful receipt cannot include a rollback result.", "Retry against a version-1 Orchestrator endpoint.")
	}
	if receipt.Status != StatusSucceeded && receipt.Status != StatusFailed && receipt.Status != StatusRolledBack {
		fail("receipt_status_invalid", "The delivery receipt status is not supported.", "Retry with a version-1 Orchestrator endpoint.")
	}
	hasRollbackDigest := receipt.Rollback.TargetArtifactDigest != nil
	hasRollbackManifestDigest := receipt.Rollback.TargetManifestDigest != nil
	if receipt.Rollback.Status == RollbackNotRequired && receipt.Rollback.Attempted {
		fail("receipt_rollback_invalid", "A receipt cannot mark rollback as not required after attempting recovery.", "Retry against a version-1 Orchestrator endpoint.")
	}
	if receipt.Rollback.Status == RollbackNotRequired && (hasRollbackDigest || hasRollbackManifestDigest) {
		fail("receipt_rollback_invalid", "A receipt marked not_required cannot carry a rollback target.", "Retry against a version-1 Orchestrator endpoint.")
	}
	if receipt.Rollback.Status != RollbackNotRequired && !receipt.Rollback.Attempted {
		fail("receipt_rollback_invalid", "A rollback result must record that recovery was attempted.", "Inspect the durable delivery journal before retrying.")
	}
	if hasRollbackDigest != hasRollbackManifestDigest {
		fail("receipt_rollback_invalid", "The rollback receipt contains only one half of the target artifact identity.", "Inspect the durable delivery journal before retrying.")
	}
	if receipt.Rollback.TargetArtifactDigest != nil && receipt.Rollback.TargetManifestDigest != nil {
		digestField(*receipt.Rollback.TargetArtifactDigest, "rollback.targetArtifactDigest")
		digestField(*receipt.Rollback.TargetManifestDigest, "rollback.targetManifestDigest")
	}
	if receipt.Status == StatusRolledBack &&
		(receipt.Rollback.Status != RollbackSucceeded || !receipt.Rollback.Attempted ||
			receipt.Rollback.TargetArtifactDigest == nil || receipt.Rollback.TargetManifestDigest == nil) {
		fail("receipt_rollback_invalid", "A rolled-back receipt must include a verified rollback target.", "Inspect the durable delivery journal before retrying.")
	}
	if receipt.Status == StatusFailed && (receipt.Error == nil || receipt.Error.Code == nil) {
		fail("receipt_error_missing", "A failed delivery receipt must include an actionable error.", "Retry after reviewing the operation error and remediation.")
	}
	if receipt.Error != nil {
		boundedOptional(receipt.Error.Code, 64, "receipt_error_invalid", "error.code")
		boundedOptional(receipt.Error.Message, maxText, "receipt_error_invalid", "error.message")
		boundedOptional(receipt.Error.Remediation, maxReason, "receipt_error_invalid", "error.remediation")
		if secretBearing(strPtrValue(receipt.Error.Message)) || secretBearing(strPtrValue(receipt.Error.Remediation)) {
			fail("secret_in_receipt", "The delivery receipt contains secret material.", "Discard this receipt and retry against a redacting Orchestrator endpoint.")
		}
	}
	bounded(receipt.AuditID, maxText, "receipt_audit_invalid", "auditId")
}

func nullableDigestEquals(actual, expected *string) bool {
	if actual == nil && expected == nil {
		return true
	}
	if actual != nil && expected != nil {
		return SameDigest(*actual, *expected)
	}
	return false
}

func sameTarget(actual, expected *Target) bool {
	if actual.Service != expected.Service || actual.Environment != expected.Environment {
		return false
	}
	if len(actual.Regions) != len(expected.Regions) {
		return false
	}
	for index := range actual.Regions {
		if actual.Regions[index] != expected.Regions[index] {
			return false
		}
	}
	return true
}

func validateSource(source *Source) {
	bounded(source.Repository, maxText, "source_invalid", "source.repository")
	if !commitPattern.MatchString(source.Commit) {
		fail("source_invalid", "source.commit must be a 40-character Git commit.", "Provide the exact source commit that produced the artifact.")
	}
	if strings.HasPrefix(source.TreeDigest, "git:") {
		if source.TreeDigest != "git:"+strings.ToLower(source.Commit) {
			fail("source_invalid", "source.treeDigest git identity must match source.commit.", "Provide git:<commit> for the exact source commit.")
		}
	} else {
		digestField(source.TreeDigest, "source.treeDigest")
	}
}

func validateArtifact(artifact *Artifact) {
	if strings.TrimSpace(artifact.Name) == "" || strings.TrimSpace(artifact.ManifestName) == "" {
		fail("artifact_identity_incomplete", "artifact names are required.", "Provide the exact binary and manifest asset names.")
	}
	bounded(artifact.Name, maxText, "artifact_name_invalid", "artifact.name")
	bounded(artifact.ManifestName, maxText, "artifact_manifest_name_invalid", "artifact.manifestName")
	digestField(artifact.Digest, "artifact.digest")
	digestField(artifact.SignatureDigest, "artifact.signatureDigest")
	digestField(artifact.ManifestDigest, "artifact.manifestDigest")
	digestField(artifact.ManifestSignatureDigest, "artifact.manifestSignatureDigest")
	if artifact.Kind != "service" && artifact.Kind != "package" && artifact.Kind != "site" {
		fail("artifact_kind_invalid", "artifact.kind is not supported.", "Use service, package, or site.")
	}
	if artifact.Architecture != "linux/amd64" && artifact.Architecture != "linux/arm64" && artifact.Architecture != "multi" {
		fail("artifact_architecture_invalid", "artifact.architecture is not supported.", "Use linux/amd64, linux/arm64, or multi.")
	}
}

func validateRollbackArtifact(rollback *RollbackArtifact, artifact *Artifact) {
	digestField(rollback.ArtifactDigest, "rollback.artifactDigest")
	digestField(rollback.ManifestDigest, "rollback.manifestDigest")
	if rollback.Kind != "service" && rollback.Kind != "package" && rollback.Kind != "site" {
		fail("rollback_invalid", "rollback.kind is not deployable.", "Use service, package, or site.")
	}
	if rollback.Architecture != "linux/amd64" && rollback.Architecture != "linux/arm64" && rollback.Architecture != "multi" {
		fail("rollback_invalid", "rollback.architecture is not deployable.", "Use linux/amd64, linux/arm64, or multi.")
	}
	if artifact == nil {
		fail("rollback_invalid", "Rollback identity requires the exact candidate artifact.", "Provide artifact and rollback identities together.")
	}
	if rollback.Kind != artifact.Kind || rollback.Architecture != artifact.Architecture {
		fail("rollback_incompatible", "Rollback kind and architecture must match the candidate artifact.", "Provide the exact currently deployed artifact for the same target shape.")
	}
	if SameDigest(rollback.ArtifactDigest, artifact.Digest) {
		fail("rollback_not_prior", "Rollback identity is the same as the candidate artifact.", "Provide the exact prior artifact, or omit rollback for a first deployment.")
	}
}

func validateInformational(informational *Informational) {
	if informational == nil {
		return
	}
	boundedOptional(informational.Notes, maxReason, "informational_invalid", "informational.notes")
	secretFree(strPtrValue(informational.Notes), "informational.notes")
	if informational.NotificationChannels == nil {
		return
	}
	if len(*informational.NotificationChannels) > 8 {
		fail("informational_invalid", "informational.notificationChannels contains too many entries.", "Provide no more than 8 channel names.")
	}
	for _, channel := range *informational.NotificationChannels {
		bounded(channel, maxText, "informational_invalid", "informational.notificationChannels")
		secretFree(channel, "informational.notificationChannels")
	}
}

func validateTarget(target *Target) {
	bounded(target.Service, maxText, "target_invalid", "target.service")
	if target.Environment != "local" && target.Environment != "development" && target.Environment != "production" {
		fail("target_invalid", "target.environment is not supported.", "Use local, development, or production.")
	}
	valid := len(target.Regions) >= 1 && len(target.Regions) <= maxRegions
	if valid {
		seen := map[string]bool{}
		for _, region := range target.Regions {
			if strings.TrimSpace(region) == "" || len(region) > maxText || strings.ContainsFunc(region, unicode.IsControl) {
				valid = false
				break
			}
			seen[region] = true
		}
		if valid && len(seen) != len(target.Regions) {
			valid = false
		}
	}
	if !valid {
		fail("target_invalid", "target.regions must contain bounded region names.", "Provide at least one valid region name.")
	}
}

func digestField(value, field string) {
	if !sha256Pattern.MatchString(value) {
		fail("digest_invalid", field+" must be a sha256 digest.", "Provide sha256 followed by exactly 64 hexadecimal characters.")
	}
}

func bounded(value string, max int, code, field string) {
	if strings.TrimSpace(value) == "" || len(value) > max || strings.ContainsFunc(value, unicode.IsControl) {
		fail(code, field+" is empty, too long, or contains control characters.", "Provide a bounded "+field+" value.")
	}
}

func boundedOptional(value *string, max int, code, field string) {
	if value == nil {
		return
	}
	bounded(*value, max, code, field)
}

func fail(code, message, remediation string) {
	panic(&ValidationError{Code: code, Message: message, Remediation: remediation})
}

func secretBearing(value string) bool {
	return value != "" && secretPattern.MatchString(value)
}

func secretFree(value, field string) {
	if secretBearing(value) {
		fail("secret_input_rejected", field+" appears to contain a secret.", "Remove credentials and send them through the existing secret store.")
	}
}
