package natscell

import (
	"testing"
)

func labController(t *testing.T, instance, dir string) Config {
	t.Helper()
	cfg := productionTestConfig(t, "gru", instance)
	cfg.Embedded.StoreDir = dir
	return cfg
}
