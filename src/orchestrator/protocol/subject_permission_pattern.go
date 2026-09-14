package protocol

import "strings"

// SubjectPermissionPattern is one compiled NATS permission pattern: whole-token
// `*` wildcards and a terminal `>` multi-token wildcard.
type SubjectPermissionPattern struct {
	value  string
	tokens []string
}

// Value returns the original pattern text.
func (p *SubjectPermissionPattern) Value() string {
	if p == nil {
		return ""
	}

	return p.value
}

// TokenCount returns the number of dot-separated tokens.
func (p *SubjectPermissionPattern) TokenCount() int {
	if p == nil {
		return 0
	}

	return len(p.tokens)
}

// Tokens returns the token list; callers must not mutate it.
func (p *SubjectPermissionPattern) Tokens() []string {
	if p == nil {
		return nil
	}

	return p.tokens
}

// SubjectPermissionPatternTryParse mirrors SubjectPermissionPattern.TryParse.
func SubjectPermissionPatternTryParse(value string, limits *SubjectGrammarLimits) (*SubjectPermissionPattern, SubjectGrammarError) {
	tokens, err := subjectGrammarParserInstance.tryTokenize(value, limits)
	if err != SubjectGrammarErrorNone {
		return nil, err
	}

	for index, token := range tokens {
		if token == ">" {
			if index != len(tokens)-1 {
				return nil, SubjectGrammarErrorTerminalWildcardMustBeFinal
			}

			continue
		}

		if token == "*" {
			continue
		}

		if strings.Contains(token, "*") || strings.Contains(token, ">") {
			return nil, SubjectGrammarErrorInvalidWildcard
		}
	}

	return &SubjectPermissionPattern{value: value, tokens: tokens}, SubjectGrammarErrorNone
}

// Matches mirrors SubjectPermissionPattern.Matches: `*` matches exactly one
// token and a terminal `>` matches one or more remaining tokens.
func (p *SubjectPermissionPattern) Matches(subject *ConcreteSubject) bool {
	if p == nil || subject == nil {
		return false
	}

	patternTokens := p.tokens
	subjectTokens := subject.tokens
	terminalWildcard := patternTokens[len(patternTokens)-1] == ">"
	if terminalWildcard {
		if len(subjectTokens) < len(patternTokens) {
			return false
		}
	} else if len(subjectTokens) != len(patternTokens) {
		return false
	}

	literalCount := len(patternTokens)
	if terminalWildcard {
		literalCount--
	}

	for index := 0; index < literalCount; index++ {
		patternToken := patternTokens[index]
		if patternToken != "*" && patternToken != subjectTokens[index] {
			return false
		}
	}

	return true
}

// Equal mirrors SubjectPermissionPattern.Equals (ordinal value equality).
func (p *SubjectPermissionPattern) Equal(other *SubjectPermissionPattern) bool {
	if p == nil || other == nil {
		return p == other
	}

	return p.value == other.value
}

// CompareTo mirrors SubjectPermissionPattern.CompareTo (ordinal, nil sorts last).
func (p *SubjectPermissionPattern) CompareTo(other *SubjectPermissionPattern) int {
	if other == nil {
		return 1
	}

	return strings.Compare(p.value, other.value)
}

func (p *SubjectPermissionPattern) String() string { return p.Value() }
