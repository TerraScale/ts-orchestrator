//go:build !linux

package initialgrant

import "testing"

func mountPublicationTestState(t *testing.T) {
	t.Helper()
	t.Skip("host publication requires Linux")
}
