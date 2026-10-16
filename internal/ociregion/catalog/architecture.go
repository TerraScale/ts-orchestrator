package catalog

import (
	"fmt"
	"strings"
	"unicode"
)

// ShapeArchitecture reads OCI's observed processor description, never a shape's family name.
func ShapeArchitecture(processorDescription string) (string, error) {
	arm, x86 := false, false
	for _, word := range strings.FieldsFunc(strings.ToLower(processorDescription), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		arm = arm || strings.HasPrefix(word, "ampere") || word == "arm" || word == "arm64" || word == "aarch64"
		x86 = x86 || word == "amd" || word == "intel" || word == "x86" || word == "amd64"
	}
	if arm == x86 {
		return "", fmt.Errorf("OCI processor description has unknown or contradictory architecture: %q", processorDescription)
	}
	if arm {
		return "arm64", nil
	}
	return "amd64", nil
}
