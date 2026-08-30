// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/StableIdentifierFormat.cs.
package contracts

// StableIdentifierKind mirrors the StableIdentifierKind enum.
type StableIdentifierKind int

const (
	StableIdentifierKindUnspecified  StableIdentifierKind = 0
	StableIdentifierKindRequirement  StableIdentifierKind = 1
	StableIdentifierKindInvariant    StableIdentifierKind = 2
	StableIdentifierKindSecurityRule StableIdentifierKind = 3
	StableIdentifierKindStateMachine StableIdentifierKind = 4
	StableIdentifierKindStableError  StableIdentifierKind = 5
)

// StableIdentifierFormat mirrors the internal static class of the same name:
// closed format rules for the permanent stable contract identifiers defined by
// the GOAL.md "Stable contract identifiers" tables. Requirement, invariant,
// and security-rule identifiers carry a three-digit zero-padded numeric
// suffix; state-machine and stable-error identifiers carry uppercase
// dash-separated word suffixes. It is exported because the identifiers are
// validated across the module.
var StableIdentifierFormat stableIdentifierFormat

type stableIdentifierFormat struct{}

// RequirementPrefix mirrors StableIdentifierFormat.RequirementPrefix.
func (stableIdentifierFormat) RequirementPrefix() string { return "REQ-ORCH-" }

// InvariantPrefix mirrors StableIdentifierFormat.InvariantPrefix.
func (stableIdentifierFormat) InvariantPrefix() string { return "INV-ORCH-" }

// SecurityRulePrefix mirrors StableIdentifierFormat.SecurityRulePrefix.
func (stableIdentifierFormat) SecurityRulePrefix() string { return "SEC-ORCH-" }

// StateMachinePrefix mirrors StableIdentifierFormat.StateMachinePrefix.
func (stableIdentifierFormat) StateMachinePrefix() string { return "SM-ORCH-" }

// StableErrorPrefix mirrors StableIdentifierFormat.StableErrorPrefix.
func (stableIdentifierFormat) StableErrorPrefix() string { return "ERR-ORCH-" }

// IsNumericSuffixId reports whether value is prefix + exactly three ASCII digits.
func (stableIdentifierFormat) IsNumericSuffixId(value, prefix string) bool {
	if len(value) != len(prefix)+3 || !startsWithOrdinal(value, prefix) {
		return false
	}

	suffix := value[len(prefix):]
	for index := 0; index < len(suffix); index++ {
		if suffix[index] < '0' || suffix[index] > '9' {
			return false
		}
	}

	return true
}

// IsNamedSuffixId reports whether value is prefix + one or more dash-separated
// uppercase-word tokens, each starting with an uppercase letter.
func (stableIdentifierFormat) IsNamedSuffixId(value, prefix string) bool {
	if !startsWithOrdinal(value, prefix) {
		return false
	}

	suffix := value[len(prefix):]
	if len(suffix) == 0 {
		return false
	}

	tokenStart := true
	for index := 0; index < len(suffix); index++ {
		character := suffix[index]
		if character == '-' {
			if tokenStart {
				return false
			}

			tokenStart = true
			continue
		}

		isUppercaseLetter := character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		if !isUppercaseLetter && !isDigit {
			return false
		}

		if tokenStart && !isUppercaseLetter {
			return false
		}

		tokenStart = false
	}

	return !tokenStart
}

func startsWithOrdinal(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
