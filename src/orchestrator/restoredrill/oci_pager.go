package restoredrill

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/mail"

	"terrascale.tech/orchestrator/src/orchestrator/reaper"
)

// OCIEmailPager submits failed restore notifications to an explicitly configured
// operator mailbox. Success means OCI accepted the notification, not that an
// operator received or acknowledged the incident.
type OCIEmailPager struct {
	client    *reaper.OCIMailAdapter
	recipient string
}

func NewOCIEmailPager(client *reaper.OCIMailAdapter, recipient string) (*OCIEmailPager, error) {
	address, err := mail.ParseAddress(recipient)
	if client == nil || err != nil || address.Address != recipient || address.Name != "" {
		return nil, fmt.Errorf("%w: OCI email client and operator mailbox required", ErrProductionDependency)
	}
	return &OCIEmailPager{client: client, recipient: recipient}, nil
}

func (p *OCIEmailPager) Page(ctx context.Context, page Page) error {
	if p == nil || p.client == nil {
		return ErrProductionDependency
	}
	if !validID(page.RunID) || page.Outcome.ID != page.RunID ||
		(page.Outcome.Status != RunFailed && page.Outcome.Status != RunCanceled) {
		return fmt.Errorf("%w: failed restore run identity required", ErrInvalidRestoreRequest)
	}
	// Provider errors, journal cuts, database lists, and item records can contain
	// sensitive details. Operators inspect the durable run instead of receiving
	// those fields through a third-party email transport.
	operation := fmt.Sprintf("restore-drill-notification-%x", sha256.Sum256([]byte(page.RunID)))
	return p.client.SendMessage(ctx, reaper.OCIEmailMessage{
		To:           p.recipient,
		Subject:      "TerraScale restore drill failed",
		Body:         fmt.Sprintf("Restore drill %s has status %s. Inspect this run in the orchestrator's durable restore journal and investigate backup durability.\n", page.RunID, page.Outcome.Status),
		OperationKey: operation,
	})
}

var _ PagerPort = (*OCIEmailPager)(nil)
