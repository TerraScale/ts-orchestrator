package app

import (
	"strings"
)

func validEnrollmentInstanceID(instanceID string) bool {
	if len(instanceID) <= len("ocid1.instance.") || len(instanceID) > 255 ||
		!strings.HasPrefix(instanceID, "ocid1.instance.") {
		return false
	}
	for _, character := range instanceID {
		if character != '.' && character != '-' && character != '_' &&
			(character < '0' || character > '9') &&
			(character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}
