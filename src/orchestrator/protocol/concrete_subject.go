package protocol

import "strings"

// ConcreteSubject is one tokenized concrete NATS subject (no wildcards).
type ConcreteSubject struct {
	value  string
	tokens []string
}

// Value returns the original subject text.
func (s *ConcreteSubject) Value() string {
	if s == nil {
		return ""
	}

	return s.value
}

// TokenCount returns the number of dot-separated tokens.
func (s *ConcreteSubject) TokenCount() int {
	if s == nil {
		return 0
	}

	return len(s.tokens)
}

// Tokens returns the token list; callers must not mutate it.
func (s *ConcreteSubject) Tokens() []string {
	if s == nil {
		return nil
	}

	return s.tokens
}

// ConcreteSubjectTryParse parses one concrete subject; wildcards are rejected.
func ConcreteSubjectTryParse(value string, limits *SubjectGrammarLimits) (*ConcreteSubject, SubjectGrammarError) {
	tokens, err := subjectGrammarParserInstance.tryTokenize(value, limits)
	if err != SubjectGrammarErrorNone {
		return nil, err
	}

	for _, token := range tokens {
		if strings.Contains(token, "*") || strings.Contains(token, ">") {
			return nil, SubjectGrammarErrorWildcardNotAllowed
		}
	}

	return &ConcreteSubject{value: value, tokens: tokens}, SubjectGrammarErrorNone
}

// Equal is ordinal value equality.
func (s *ConcreteSubject) Equal(other *ConcreteSubject) bool {
	if s == nil || other == nil {
		return s == other
	}

	return s.value == other.value
}

// CompareTo is ordinal; nil sorts last.
func (s *ConcreteSubject) CompareTo(other *ConcreteSubject) int {
	if other == nil {
		return 1
	}

	return strings.Compare(s.value, other.value)
}

func (s *ConcreteSubject) String() string { return s.Value() }
