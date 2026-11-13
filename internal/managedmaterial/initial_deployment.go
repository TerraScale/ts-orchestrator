package managedmaterial

import (
	"strings"
)

func lowerHexIdentity(value string) bool {
	if len(value) != 32 || strings.Trim(value, "0") == "" {
		return false
	}
	for index := range len(value) {
		if !lowerAlphaNumeric(value[index]) || value[index] > 'f' {
			return false
		}
	}
	return true
}
