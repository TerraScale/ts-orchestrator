// Package contracts defines the frozen command identifiers shared by the
// protocol and control packages.
package contracts

import "strings"

// commandIdentifierRules mirrors the internal static CommandIdentifierRules.
func commandIdentifierRulesIsValid(value string) bool {
	trimmed := strings.TrimSpace(value)
	if value == "" || trimmed == "" {
		return false
	}

	return !strings.ContainsRune(value, '\x00')
}

// CellId is the strongly typed cell identifier of a signed command.
// The zero value carries an empty Value and reports IsValid() == false,
// mirroring the C# default readonly record struct.
type CellId struct {
	Value string
}

// IsValid reports whether the identifier satisfies the command identifier rules.
func (i CellId) IsValid() bool { return commandIdentifierRulesIsValid(i.Value) }

func (i CellId) String() string { return i.Value }

// CellIdTryCreate mirrors CellId.TryCreate; an empty value is the Go
// equivalent of the C# null argument and always fails.
func CellIdTryCreate(value string) (CellId, bool) {
	if !commandIdentifierRulesIsValid(value) {
		return CellId{}, false
	}

	return CellId{Value: value}, true
}

// AggregateId is the strongly typed aggregate identifier of a signed command.
type AggregateId struct {
	Value string
}

// IsValid reports whether the identifier satisfies the command identifier rules.
func (i AggregateId) IsValid() bool { return commandIdentifierRulesIsValid(i.Value) }

func (i AggregateId) String() string { return i.Value }

// AggregateIdTryCreate mirrors AggregateId.TryCreate.
func AggregateIdTryCreate(value string) (AggregateId, bool) {
	if !commandIdentifierRulesIsValid(value) {
		return AggregateId{}, false
	}

	return AggregateId{Value: value}, true
}

// OperationId is the strongly typed operation identifier of a signed command.
type OperationId struct {
	Value string
}

// IsValid reports whether the identifier satisfies the command identifier rules.
func (i OperationId) IsValid() bool { return commandIdentifierRulesIsValid(i.Value) }

func (i OperationId) String() string { return i.Value }

// OperationIdTryCreate mirrors OperationId.TryCreate.
func OperationIdTryCreate(value string) (OperationId, bool) {
	if !commandIdentifierRulesIsValid(value) {
		return OperationId{}, false
	}

	return OperationId{Value: value}, true
}

// IdempotencyKey is the strongly typed idempotency key of a signed command.
type IdempotencyKey struct {
	Value string
}

// IsValid reports whether the identifier satisfies the command identifier rules.
func (i IdempotencyKey) IsValid() bool { return commandIdentifierRulesIsValid(i.Value) }

func (i IdempotencyKey) String() string { return i.Value }

// IdempotencyKeyTryCreate mirrors IdempotencyKey.TryCreate.
func IdempotencyKeyTryCreate(value string) (IdempotencyKey, bool) {
	if !commandIdentifierRulesIsValid(value) {
		return IdempotencyKey{}, false
	}

	return IdempotencyKey{Value: value}, true
}
