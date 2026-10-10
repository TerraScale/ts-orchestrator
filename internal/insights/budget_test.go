package insights

import "testing"

func TestBudgetWarnsFromTheDefaultWarnRatio(t *testing.T) {
	thresholds := Thresholds{}.withDefaults()
	if thresholds.BudgetWarning != 0.8 {
		t.Fatalf("default budget warning = %v, want 0.8", thresholds.BudgetWarning)
	}
	for _, tc := range []struct {
		used     float64
		insights int
		severity Severity
	}{
		{used: 79, insights: 0},
		{used: 80, insights: 1, severity: SeverityWarning},
		{used: 100, insights: 1, severity: SeverityCritical},
	} {
		inputs := &Inputs{Thresholds: thresholds,
			Budgets: []Budget{{Name: "monthly OCI budget", Used: tc.used, Ceiling: 100, Unit: "BRL"}}}
		got := budgetCeiling(inputs)
		if len(got) != tc.insights {
			t.Fatalf("used %v of 100: %d insights, want %d", tc.used, len(got), tc.insights)
		}
		if tc.insights == 1 && got[0].Severity != tc.severity {
			t.Fatalf("used %v of 100: severity %v, want %v", tc.used, got[0].Severity, tc.severity)
		}
	}
}
