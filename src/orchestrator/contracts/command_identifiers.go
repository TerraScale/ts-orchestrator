// Package contracts defines shared command identifiers and wire text bounds.
package contracts

import "strings"

// commandIdentifierRulesIsValid reports whether value satisfies the command
// identifier rules.
func commandIdentifierRulesIsValid(value string) bool {
	trimmed := strings.TrimSpace(value)
	if value == "" || trimmed == "" {
		return false
	}

	return !strings.ContainsRune(value, '\x00')
}

// CellId is the strongly typed cell identifier of a signed command.
// The zero value carries an empty Value and reports IsValid() == false.
type CellId struct {
	Value string
}

// IsValid reports whether the identifier satisfies the command identifier rules.
func (i CellId) IsValid() bool { return commandIdentifierRulesIsValid(i.Value) }

func (i CellId) String() string { return i.Value }

// CellIdTryCreate validates and constructs a CellId; an empty value always
// fails.
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

// AggregateIdTryCreate validates and constructs an AggregateId.
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

// OperationIdTryCreate validates and constructs an OperationId.
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

// IdempotencyKeyTryCreate validates and constructs an IdempotencyKey.
func IdempotencyKeyTryCreate(value string) (IdempotencyKey, bool) {
	if !commandIdentifierRulesIsValid(value) {
		return IdempotencyKey{}, false
	}

	return IdempotencyKey{Value: value}, true
}
