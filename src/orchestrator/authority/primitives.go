package authority

import (
	"time"
	"unicode"

	"terrascale.tech/orchestrator/src/orchestrator/digest"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const int64max = int64(^uint64(0) >> 1)

func invalidArgument(message string) error {
	return &errs.Argument{Message: message}
}

func argumentNil(name string) error {
	return &errs.Argument{Param: name, Message: "Value cannot be null. (Parameter '" + name + "')"}
}

func isNullOrWhiteSpace(value string) bool {
	if value == "" {
		return true
	}
	for _, character := range value {
		if !isSpaceRune(character) {
			return false
		}
	}
	return true
}

func isSpaceRune(character rune) bool {
	switch character {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xA0:
		return true
	}
	return unicode.IsSpace(character)
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func checkedAddInt64(left, right int64) (int64, bool) {
	sum := left + right
	if right > 0 && sum < left || right < 0 && sum > left {
		return 0, false
	}
	return sum, true
}

func dotNetCanAdd(timestamp time.Time, duration time.Duration) bool {
	return digest.CanAddTime(timestamp, duration)
}

func dotNetTimeEquals(left, right time.Time) bool {
	return digest.TimeEqual(left, right)
}

type digestWriter = digest.Writer

func newDigestWriter() *digestWriter {
	return digest.NewWriter()
}

func digestHash(value string) string {
	return digest.Hash(value)
}
