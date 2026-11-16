package region

import (
	"errors"
)

var (
	ErrOriginalFoundationDelivery         = errors.New("original public foundation bundle delivery refused")
	ErrOriginalFoundationAdmissionPending = errors.New("original startup binding, local custody, source archive and runtime admission are pending")
)

// OriginalFoundationAdmissionPendingError reports public delivery, never source
// custody or permission to start a controller.
type OriginalFoundationAdmissionPendingError struct {
	BundleSHA256 string
}
