package budget

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func testBudget() Budget {
	return Budget{
		Schema:          Schema,
		ID:              entityid.New(),
		MonthlyCapCents: 50000,
		Currency:        "BRL",
		SetBy:           "mariogk@terrascale.tech",
		SetAt:           time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC),
	}
}

func TestBudgetValidateRefusesMalformedBudgets(t *testing.T) {
	for name, mutate := range map[string]func(*Budget){
		"schema":         func(b *Budget) { b.Schema = 2 },
		"bad ULID":       func(b *Budget) { b.ID = "not-a-ulid" },
		"zero cap":       func(b *Budget) { b.MonthlyCapCents = 0 },
		"cap too large":  func(b *Budget) { b.MonthlyCapCents = 1_000_000_000_001 },
		"lower currency": func(b *Budget) { b.Currency = "brl" },
		"short currency": func(b *Budget) { b.Currency = "BR" },
		"long currency":  func(b *Budget) { b.Currency = "BRLX" },
		"empty set_by":   func(b *Budget) { b.SetBy = "" },
		"control set_by": func(b *Budget) { b.SetBy = "mariogk\n@terrascale.tech" },
		"long set_by":    func(b *Budget) { b.SetBy = strings.Repeat("a", 255) },
		"zero set_at":    func(b *Budget) { b.SetAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			b := testBudget()
			mutate(&b)
			if err := b.Validate(); err == nil {
				t.Fatal("malformed budget validated")
			}
			if _, err := b.Encode(); err == nil {
				t.Fatal("malformed budget encoded")
			}
		})
	}
}

func TestDecodeBudgetRefusesUnknownFieldsAndInvalidBudgets(t *testing.T) {
	id := entityid.New()
	valid := `"schema":1,"id":"` + id + `","monthly_cap_cents":1,"currency":"BRL","set_by":"x","set_at":"2026-10-10T20:00:00Z"`
	if _, err := DecodeBudget([]byte("{" + valid + "}")); err != nil {
		t.Fatalf("valid budget = %v", err)
	}
	if _, err := DecodeBudget([]byte("{" + valid + `,"extra":true}`)); err == nil {
		t.Fatal("unknown field decoded")
	}
	if _, err := DecodeBudget([]byte("{" + strings.Replace(valid, `"currency":"BRL"`, `"currency":"brl"`, 1) + "}")); err == nil {
		t.Fatal("invalid currency decoded")
	}
	if _, err := DecodeBudget([]byte("not json")); err == nil {
		t.Fatal("garbage decoded")
	}
}

func TestBudgetEncodeDecodeRoundTrip(t *testing.T) {
	want := testBudget()
	encoded, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBudget(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.MonthlyCapCents != want.MonthlyCapCents || got.Currency != want.Currency ||
		got.SetBy != want.SetBy || !got.SetAt.Equal(want.SetAt) || got.Schema != want.Schema {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	again, err := got.Encode()
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatalf("re-encode = %s, %v; want %s", again, err, encoded)
	}
}
