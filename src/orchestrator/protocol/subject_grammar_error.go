package protocol

import (
	"strconv"
	"unicode"
	"unicode/utf8"
)

// SubjectGrammarError mirrors the SubjectGrammarError enum.
type SubjectGrammarError int

const (
	SubjectGrammarErrorNone                         SubjectGrammarError = 0
	SubjectGrammarErrorInvalidLimits                SubjectGrammarError = 1
	SubjectGrammarErrorEmpty                        SubjectGrammarError = 2
	SubjectGrammarErrorSubjectTooLong               SubjectGrammarError = 3
	SubjectGrammarErrorTooManyTokens                SubjectGrammarError = 4
	SubjectGrammarErrorEmptyToken                   SubjectGrammarError = 5
	SubjectGrammarErrorTokenTooLong                 SubjectGrammarError = 6
	SubjectGrammarErrorWhitespaceNotAllowed         SubjectGrammarError = 7
	SubjectGrammarErrorControlCharacterNotAllowed   SubjectGrammarError = 8
	SubjectGrammarErrorInvalidUnicodeScalarSequence SubjectGrammarError = 9
	SubjectGrammarErrorWildcardNotAllowed           SubjectGrammarError = 10
	SubjectGrammarErrorInvalidWildcard              SubjectGrammarError = 11
	SubjectGrammarErrorTerminalWildcardMustBeFinal  SubjectGrammarError = 12
)

func (e SubjectGrammarError) String() string {
	switch e {
	case SubjectGrammarErrorNone:
		return "None"
	case SubjectGrammarErrorInvalidLimits:
		return "InvalidLimits"
	case SubjectGrammarErrorEmpty:
		return "Empty"
	case SubjectGrammarErrorSubjectTooLong:
		return "SubjectTooLong"
	case SubjectGrammarErrorTooManyTokens:
		return "TooManyTokens"
	case SubjectGrammarErrorEmptyToken:
		return "EmptyToken"
	case SubjectGrammarErrorTokenTooLong:
		return "TokenTooLong"
	case SubjectGrammarErrorWhitespaceNotAllowed:
		return "WhitespaceNotAllowed"
	case SubjectGrammarErrorControlCharacterNotAllowed:
		return "ControlCharacterNotAllowed"
	case SubjectGrammarErrorInvalidUnicodeScalarSequence:
		return "InvalidUnicodeScalarSequence"
	case SubjectGrammarErrorWildcardNotAllowed:
		return "WildcardNotAllowed"
	case SubjectGrammarErrorInvalidWildcard:
		return "InvalidWildcard"
	case SubjectGrammarErrorTerminalWildcardMustBeFinal:
		return "TerminalWildcardMustBeFinal"
	default:
		return strconv.Itoa(int(e))
	}
}

// subjectGrammarParser validates bounded NATS subjects and permission patterns.
type subjectGrammarParser struct{}

var subjectGrammarParserInstance subjectGrammarParser

func (subjectGrammarParser) tryTokenize(value string, limits *SubjectGrammarLimits) ([]string, SubjectGrammarError) {
	if limits == nil {
		return nil, SubjectGrammarErrorInvalidLimits
	}

	if value == "" {
		return nil, SubjectGrammarErrorEmpty
	}

	if utf16CodeUnitCount(value) > limits.MaximumSubjectLength {
		return nil, SubjectGrammarErrorSubjectTooLong
	}

	tokenCount := 1
	tokenLength := 0
	for index := 0; index < len(value); {
		character, width := utf8.DecodeRuneInString(value[index:])
		if character == utf8.RuneError && width == 1 {
			return nil, SubjectGrammarErrorInvalidUnicodeScalarSequence
		}

		if character == '.' {
			if tokenLength == 0 {
				return nil, SubjectGrammarErrorEmptyToken
			}

			if tokenCount >= limits.MaximumTokenCount {
				return nil, SubjectGrammarErrorTooManyTokens
			}

			tokenCount++
			tokenLength = 0
			index += width
			continue
		}

		if unicode.IsSpace(character) {
			return nil, SubjectGrammarErrorWhitespaceNotAllowed
		}

		if unicode.IsControl(character) {
			return nil, SubjectGrammarErrorControlCharacterNotAllowed
		}

		characterUnits := 1
		if character > 0xFFFF {
			characterUnits = 2
		}

		if tokenLength > limits.MaximumTokenLength-characterUnits {
			return nil, SubjectGrammarErrorTokenTooLong
		}

		tokenLength += characterUnits
		index += width
	}

	if tokenLength == 0 {
		return nil, SubjectGrammarErrorEmptyToken
	}

	return splitSubjectTokens(value), SubjectGrammarErrorNone
}

// splitSubjectTokens mirrors string.Split('.') for a nonempty subject: the
// result is never empty and contains no trimming.
func splitSubjectTokens(value string) []string {
	tokens := []string{}
	start := 0
	for index := 0; index < len(value); index++ {
		if value[index] == '.' {
			tokens = append(tokens, value[start:index])
			start = index + 1
		}
	}

	return append(tokens, value[start:])
}
