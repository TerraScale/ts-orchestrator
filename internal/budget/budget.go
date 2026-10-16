// Package budget holds the tenancy's monthly OCI spend cap and the node
// allowances the home region's global leader derives from it. The budget is
// set once from the dashboard and stored in TS_GLOBAL_CONTROL; the leader
// writes the capacity document every minute, and every region reads both from
// its mirror. Growth is decided here, never by a region alone.
package budget

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// Schema is the version of the budget and capacity documents.
const Schema = 1

const (
	maxDocumentBytes   = 64 << 10
	maxMonthlyCapCents = 1_000_000_000_000
	maxSetByBytes      = 254
)

var currencyCode = regexp.MustCompile(`^[A-Z]{3}$`)

// Budget is the tenancy's monthly OCI spend cap in the billing currency.
type Budget struct {
	Schema          int       `json:"schema"`
	ID              string    `json:"id"` // ULID, new on every change
	MonthlyCapCents uint64    `json:"monthly_cap_cents"`
	Currency        string    `json:"currency"` // ISO 4217, upper case
	SetBy           string    `json:"set_by"`
	SetAt           time.Time `json:"set_at"`
}

// Validate requires the current schema, a ULID, a cap of 1 to 1e12 cents, an
// ISO 4217 currency, a printable set_by and a set time.
func (b Budget) Validate() error {
	switch {
	case b.Schema != Schema:
		return fmt.Errorf("budget schema %d is not %d", b.Schema, Schema)
	case !entityid.Valid(b.ID):
		return errors.New("budget ID must be a ULID")
	case b.MonthlyCapCents == 0 || b.MonthlyCapCents > maxMonthlyCapCents:
		return errors.New("budget monthly cap must be 1 to 1e12 cents")
	case !currencyCode.MatchString(b.Currency):
		return errors.New("budget currency must be an upper case ISO 4217 code")
	case len(b.SetBy) == 0 || len(b.SetBy) > maxSetByBytes || strings.IndexFunc(b.SetBy, unicode.IsControl) >= 0:
		return errors.New("budget set_by must be 1 to 254 bytes with no control characters")
	case b.SetAt.IsZero():
		return errors.New("budget set_at is required")
	}
	return nil
}

// DecodeBudget strictly decodes and validates a stored budget.
func DecodeBudget(payload []byte) (Budget, error) {
	var b Budget
	if err := protocol.DecodeStrict(payload, &b, maxDocumentBytes); err != nil {
		return Budget{}, fmt.Errorf("decode monthly budget: %w", err)
	}
	if err := b.Validate(); err != nil {
		return Budget{}, err
	}
	return b, nil
}

// Encode validates b and returns its stored form.
func (b Budget) Encode() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return protocol.EncodeJSON(b)
}

// Money formats cents in the currency's major unit, for example BRL 123.45.
func Money(cents uint64, currency string) string {
	return fmt.Sprintf("%s %d.%02d", currency, cents/100, cents%100)
}

// ReadBudget returns the current budget, or false when none was ever set.
func ReadBudget(ctx context.Context, reader *globalcontrol.Reader) (Budget, bool, error) {
	document, err := reader.Document(ctx, globalcontrol.KindBudget, protocol.GlobalScope)
	if errors.Is(err, globalcontrol.ErrNotFound) {
		return Budget{}, false, nil
	}
	if err != nil {
		return Budget{}, false, err
	}
	b, err := DecodeBudget(document.Payload)
	if err != nil {
		return Budget{}, false, err
	}
	return b, true, nil
}

// WriteBudget stores b as the next budget generation. Only the home region's
// global leader calls it.
func WriteBudget(ctx context.Context, writer *globalcontrol.Writer, epoch uint64, b Budget) error {
	payload, err := b.Encode()
	if err != nil {
		return err
	}
	_, err = writer.PutDocument(ctx, epoch, globalcontrol.KindBudget, protocol.GlobalScope, payload, nil)
	return err
}
