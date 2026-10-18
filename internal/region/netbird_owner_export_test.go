package region

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// WithNetBirdManagerFixture exposes genuine signed SDK admission to external
// tests; remote services and ARM64 binary measurement remain test fixtures.
func WithNetBirdManagerFixture(t *testing.T, run func(*ociclient.Factory, FoundationResolver, VerifiedNetBirdManager)) {
	t.Helper()
	withNetBirdManagerFixture(t, run)
}
