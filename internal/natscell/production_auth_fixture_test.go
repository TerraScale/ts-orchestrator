package natscell

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// Private fixtures reuse this package's account issuer to avoid importing a fixture that depends on natscell.
func productionTestRegion(t *testing.T, cell, instance string) *testRegion {
	t.Helper()
	region := newTestRegion(t, t.TempDir(), cell, HubAndSpoke(cell, nil))
	region.cfg.Instance = instance
	region.cfg.Embedded.BrokerIDs = []string{instance}
	region.cfg.Embedded.InterRegion = nil
	region.cfg.Embedded.RouteUser = "integration-route"
	return region
}

func productionTestConfig(t *testing.T, cell, instance string) Config {
	t.Helper()
	return productionTestRegion(t, cell, instance).cfg
}

func openTestBroker(t *testing.T, ctx context.Context, cfg Config) (*Runtime, error) {
	t.Helper()
	runtime, err := Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = runtime.Close() })
	raw, err := os.ReadFile(cfg.Embedded.CellJWTFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ApplyCellClaim(ctx, 1, string(raw)); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Bridge().OpenUntil(1, string(raw), time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	return runtime, nil
}

func productionTestUser(t *testing.T, region *testRegion, instance, role string, global bool) (Config, string) {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	grants, err := userPermissions(region.cfg.Cell, NKeyGrant{PublicKey: public, Node: map[string]string{"host": instance}[role], Role: role, Global: global})
	if err != nil {
		t.Fatal(err)
	}
	path := testJWTUserCredentialsWithKey(t, t.TempDir(), "user.creds", region.cell, region.cellID, user,
		grants.Publish.Allow, grants.Subscribe.Allow)
	cfg := Config{Cell: region.cfg.Cell, Instance: instance, Replicas: region.cfg.Replicas, ClientRole: role,
		URL: region.cfg.URL, CredentialsFile: path, TLS: region.cfg.TLS}
	return cfg, public
}

func productionRouteSecret(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "route-secret")
	if err := os.WriteFile(path, []byte("integration-route-secret-32-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
