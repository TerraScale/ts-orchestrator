package budget

import (
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



