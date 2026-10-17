package qualification

import (
	"errors"
	"time"
)

const (
	RetainTestedImage = "retain-tested-image"
	ExactHostReaders  = "exact-disposable-host-readers-v1"
)

// ValidateDisposition requires original authority for retention and exact-host
// read IAM. Transfer stays in the originally approved region and compartment.
func ValidateDisposition(purpose, disposition, readerIAM string, retain, transfer, cleanup time.Time) error {
	if purpose != RootCredentialBoundaryPurpose {
		if disposition != "" || readerIAM != "" || !retain.IsZero() || !transfer.IsZero() {
			return errors.New("artifact retention and reader IAM require explicit root boundary purpose")
		}
		return nil
	}
	if disposition != RetainTestedImage || readerIAM != ExactHostReaders || retain.Location() != time.UTC || transfer.Location() != time.UTC ||
		retain.IsZero() || transfer.IsZero() || transfer.After(retain) || !retain.Before(cleanup) || cleanup.Sub(retain) < 5*time.Minute {
		return errors.New("original root boundary authority requires finite exact-image retention, transfer and cleanup")
	}
	return nil
}
