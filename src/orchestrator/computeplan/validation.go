package computeplan

import (
	"unicode"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func invalidArgument(param, message string) error {
	return &errs.Argument{Param: param, Message: message}
}

func argumentNil(name string) error {
	return &errs.Argument{Param: name, Message: "Value cannot be null. (Parameter '" + name + "')"}
}

func isSpaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xA0:
		return true
	}
	return unicode.IsSpace(r)
}

func isControlRune(r rune) bool {
	return (r >= 0x00 && r <= 0x1F) || (r >= 0x7F && r <= 0x9F)
}
