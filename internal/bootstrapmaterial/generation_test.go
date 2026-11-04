package bootstrapmaterial_test

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// generationNow anchors certificate validity and expiry assertions. Keep it
// older than the clock skew to catch checks using it for wall-clock JWTs
// (jwt.Encode stamps iat itself), without waiting for the fixture to age.
var generationNow = time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)

func generationExpectation() bootstrap.MaterialGenerationExpectation {
	return bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
		ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
}

func check(material generationtest.Material) (time.Time, error) {
	return bootstrapmaterial.CheckGenerationFiles(material.Generation(generationExpectation(), 1, ""), material.Read, time.Now())
}

func TestCheckGenerationFiles(t *testing.T) {
	material := generationtest.New(t, generationNow)
	first, err := check(material)
	if err != nil {
		t.Fatal(err)
	}
	if want := generationNow.AddDate(1, 0, 0).Add(-time.Hour); !first.Equal(want) {
		t.Fatalf("first expiry = %s, want the issuers' %s", first, want)
	}
	// A rollover bundle keeps the old CA beside the new one; the issuers
	// may already be the new CA's.
	rollover := generationtest.Rollover(t, generationNow, material)
	bundle := append(append([]byte(nil), material.Files["ca.pem"]...), rollover.Files["ca.pem"]...)
	if _, err := check(rollover.With(map[string][]byte{"ca.pem": bundle})); err != nil {
		t.Fatalf("a rollover bundle: %v", err)
	}
}
