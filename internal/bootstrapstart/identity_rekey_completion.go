package bootstrapstart

import (
	"errors"
)

var ErrIdentityRekeyPending = errors.New("identity rekey shared completion is pending")
