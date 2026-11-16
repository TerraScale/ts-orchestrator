package region

import (
	"time"
)

// OriginalNetBirdOCIRSession retains the original authenticated user. A manager
// instance proof cannot construct this producer or acquire its home IAM lease.
type OriginalNetBirdOCIRSession struct {
	authority *HomeIAMAuthority
	reader    *SignedFootprint
	scopes    [3]VerifiedOCIRIssuer
	original  FoundationRecord
	deadline  time.Time
}
