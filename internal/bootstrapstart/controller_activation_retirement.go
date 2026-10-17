package bootstrapstart

import (
	"context"
	"strings"
	"time"
)

// ReadManagerRetirement reads only the exact predecessor already selected by
// the protected slot HEAD; request bytes cannot select retirement authority.
func (proof *ControllerHostRecipient) ReadManagerRetirement(ctx context.Context, slot, instanceID string) (*ManagerRetirement, error) {
	if !proof.Valid(time.Now()) || instanceID == "" {
		return nil, ErrAdmission
	}
	if _, err := proof.VerifyActivationTopology(ctx); err != nil {
		return nil, err
	}
	retired, err := readControllerManagerRetirement(ctx, proof.reader, proof.issuer, slot, nil, proof.sources)
	if err != nil {
		return nil, err
	}
	if retired.PriorInstanceID() != instanceID || retired.OCIRegion() != proof.OCIRegion() ||
		retired.Environment() != proof.Environment() || !strings.EqualFold(retired.Cell(), proof.issuer.Cell) {
		return nil, ErrAdmission
	}
	retired.until = minTime(retired.until, proof.validUntil)
	if !proof.Valid(time.Now()) || !retired.Valid(time.Now()) {
		return nil, ErrAdmission
	}
	return retired, nil
}
