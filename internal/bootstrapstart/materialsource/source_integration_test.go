//go:build fixturetest

package materialsource

import "testing"

func TestColdMaterialHTTPConcurrentBootAndHostLossRecovery(t *testing.T) {
	exerciseColdMaterialSource(t, nil)
}
