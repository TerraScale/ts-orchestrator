package qualification

import (
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// The QCOW2 source bucket stays separate from the exact signed publication
// destination; neither a current locator nor a caller can choose a destination.
func ValidatePublicationBucket(purpose, cell, bucket string) error {
	if purpose != RootCredentialBoundaryPurpose {
		if bucket != "" {
			return errors.New("publication destination requires explicit root boundary purpose")
		}
		return nil
	}
	name, err := naming.RegionCell(cell).Name()
	if err != nil || !release.ValidRegion(cell) || bucket != name+"-head" {
		return errors.New("signed image publication destination differs from fixed regional head bucket")
	}
	return nil
}

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
