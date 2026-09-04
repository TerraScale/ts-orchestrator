package observability

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// LabelAllowList is a closed map of label keys to permitted values. An empty
// value set means the key is known but no value is admitted. This makes the
// safe default deny-by-default and prevents customer identifiers from becoming
// time-series dimensions.
type LabelAllowList map[string][]string

// DefaultLabelAllowList contains the finite values shared by orchestrator
// telemetry. Hosts and cells must be explicitly added by the regional
// composition root, keeping the cardinality decision visible in config.
var DefaultLabelAllowList = LabelAllowList{
	"plane":       {"control", "data", "storage", "observability", "product"},
	"region":      {"gru", "sfo", "fra", "unknown"},
	"subsystem":   {"hostagent", "nats", "orchestrator", "observability", "provider", "storage"},
	"result":      {"success", "error", "rejected", "unknown"},
	"state":       {"available", "degraded", "unavailable", "unknown"},
	"outcome":     {"success", "failure", "timeout", "unknown"},
	"signal":      {"metrics", "logs"},
	"severity":    {"info", "warning", "critical"},
	"environment": {"production", "staging", "development", "unknown"},
}

// closedLabelValueDomains is the vocabulary for semantic dimensions. A
// composition root may select a subset, but cannot add values dashboards and
// alerts cannot classify. Deployment-scoped host, cell, and service values
// remain explicit finite configuration.
var closedLabelValueDomains = map[string][]string{
	"plane":             {"control", "data", "storage", "observability", "product"},
	"region":            {"gru", "sfo", "fra", "unknown"},
	"cluster_role":      {"regional", "global-authority", "unknown"},
	"stream_class":      {"cellspec", "celloperations", "cellevents", "globalspec", "globalci", "keyvalue", "objectstore", "unknown"},
	"consumer_class":    {"startupevent", "cellspec", "globalci", "ephemeralwatch", "unknown"},
	"store_class":       {"keyvalue", "objectstore", "unknown"},
	"certificate_class": {"serverlistener", "gatewaylink", "monitoringclient", "unknown"},
	"result":            {"success", "error", "rejected", "delivered", "redelivered", "duplicate", "unknown"},
	"state":             {"available", "degraded", "unavailable", "healthy", "stale", "missing", "conflicting", "connected", "disconnected", "unknown"},
	"condition":         {"available", "degraded", "unavailable", "healthy", "stale", "missing", "conflicting", "connected", "disconnected", "unknown"},
	"outcome":           {"success", "failure", "timeout", "unknown"},
	"signal":            {"metrics", "logs"},
	"severity":          {"info", "warning", "critical"},
	"environment":       {"production", "staging", "development", "unknown"},
	"subsystem":         {"hostagent", "nats", "orchestrator", "observability", "provider", "storage"},
	"endpoint":          {"health", "instance_health", "status", "members", "stats", "direct_delivery"},
}

// fixedLabelKeys is the repository-wide vocabulary. A configured allow-list
// may choose a finite subset and may add finite host/cell values, but it may
// not invent a new dimension at runtime.
var fixedLabelKeys = map[string]struct{}{
	"certificate_class": {}, "cell": {}, "cluster_role": {}, "condition": {},
	"consumer_class": {}, "endpoint": {}, "environment": {}, "host": {},
	"outcome": {}, "plane": {}, "region": {}, "result": {}, "service": {},
	"severity": {}, "signal": {}, "state": {}, "storage_class": {},
	"stream_class": {}, "subsystem": {},
}

const (
	maxAllowedValuesPerLabel = 128
	maxAllowedLabelValues    = 2048
)

// NewLabelAllowList returns a defensive copy of the supplied policy.
func NewLabelAllowList(values map[string][]string) (LabelAllowList, error) {
	result := make(LabelAllowList, len(values))
	totalValues := 0
	for key, allowed := range values {
		if err := validateLabelKey(key); err != nil {
			return nil, err
		}
		if _, known := fixedLabelKeys[key]; !known {
			return nil, fmt.Errorf("label key %q is not in the fixed vocabulary", key)
		}
		if len(allowed) == 0 || len(allowed) > maxAllowedValuesPerLabel {
			return nil, fmt.Errorf("label %q must have between 1 and %d allowed values", key, maxAllowedValuesPerLabel)
		}
		totalValues += len(allowed)
		if totalValues > maxAllowedLabelValues {
			return nil, errors.New("label allow-list contains too many values")
		}
		seen := make(map[string]struct{}, len(allowed))
		for _, value := range allowed {
			if err := validateLabelValue(value); err != nil {
				return nil, fmt.Errorf("label %q: %w", key, err)
			}
			if err := validateClosedLabelValue(key, value); err != nil {
				return nil, err
			}
			if _, exists := seen[value]; exists {
				return nil, fmt.Errorf("label %q repeats value %q", key, value)
			}
			seen[value] = struct{}{}
		}
		result[key] = append([]string(nil), allowed...)
	}
	if len(result) == 0 {
		return nil, errors.New("label allow-list cannot be empty")
	}
	return result, nil
}

// Clone copies an allow-list so callers cannot mutate a validated policy.
func (a LabelAllowList) Clone() LabelAllowList {
	result := make(LabelAllowList, len(a))
	for key, values := range a {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func (a LabelAllowList) Validate() error {
	if len(a) == 0 {
		return errors.New("label allow-list cannot be empty")
	}
	totalValues := 0
	for key, values := range a {
		if err := validateLabelKey(key); err != nil {
			return err
		}
		if _, allowed := fixedLabelKeys[key]; !allowed {
			return fmt.Errorf("label key %q is not in the fixed vocabulary", key)
		}
		if len(values) == 0 || len(values) > maxAllowedValuesPerLabel {
			return fmt.Errorf("label %q must have at least one allowed value", key)
		}
		totalValues += len(values)
		if totalValues > maxAllowedLabelValues {
			return errors.New("label allow-list contains too many values")
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if err := validateLabelValue(value); err != nil {
				return fmt.Errorf("label %q: %w", key, err)
			}
			if err := validateClosedLabelValue(key, value); err != nil {
				return err
			}
			if _, exists := seen[value]; exists {
				return fmt.Errorf("label %q repeats value %q", key, value)
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}

// ValidateLabels validates keys and values against the fixed policy. It also
// rejects known customer dimensions even if a caller accidentally adds them to
// a custom policy.
func (a LabelAllowList) ValidateLabels(labels map[string]string) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if len(labels) > 16 {
		return errors.New("a telemetry record may contain at most 16 labels")
	}
	for key, value := range labels {
		if isCustomerDimension(key) {
			return fmt.Errorf("customer dimension %q is not permitted", key)
		}
		allowed, exists := a[key]
		if !exists {
			return fmt.Errorf("label key %q is not in the allow-list", key)
		}
		admitted := false
		for _, candidate := range allowed {
			if value == candidate {
				admitted = true
				break
			}
		}
		if !admitted {
			return fmt.Errorf("value %q is not allowed for label %q", value, key)
		}
	}
	return nil
}

// AllowedKeys returns sorted keys for diagnostics and tests.
func (a LabelAllowList) AllowedKeys() []string {
	keys := make([]string, 0, len(a))
	for key := range a {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validateLabelKey(value string) error {
	if value == "" || len(value) > 63 || strings.ContainsAny(value, "\r\n=\t ") {
		return fmt.Errorf("invalid label key %q", value)
	}
	for index := range value {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '.' {
			continue
		}
		return fmt.Errorf("invalid label key %q", value)
	}
	return nil
}

func validateLabelValue(value string) error {
	if value == "" || len(value) > 63 || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("label values must be non-empty, bounded, and control-free")
	}
	return nil
}

func validateClosedLabelValue(key, value string) error {
	domain, closed := closedLabelValueDomains[key]
	if !closed {
		return nil
	}
	for _, candidate := range domain {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("value %q is outside the closed domain for label %q", value, key)
}

func isCustomerDimension(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
	switch normalized {
	case "tenant", "tenant_id", "database", "database_id", "db", "db_id",
		"view", "view_id", "document", "document_id", "doc", "doc_id",
		"collection", "collection_id", "query", "query_id", "request", "request_id",
		"operation", "operation_id", "message", "message_id", "session", "session_id",
		"instance", "instance_id", "subject", "subject_id", "user", "user_id":
		return true
	default:
		return false
	}
}
