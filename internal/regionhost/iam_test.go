package regionhost

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/hostdashboard"
)

func TestDashboardSecretIsTheHostDashboardToken(t *testing.T) {
	for _, region := range []string{"gru", "sjc", "fra"} {
		if got, want := dashboardSecret(region), hostdashboard.SecretName(region); got != want {
			t.Errorf("%s: policy names %s, the dashboard creates %s", region, got, want)
		}
	}
}
