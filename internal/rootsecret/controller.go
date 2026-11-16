// Package rootsecret delivers accepted credentials without exporting an OCI
// provider, signing key, SDK client or unrestricted secret-reading operation.
package rootsecret

import (
	"errors"
)

var ErrDelivery = errors.New("root credential delivery is unavailable or no longer authorized")

// Service is installed only in the existing root OCI dispatcher.
type Service struct{}
