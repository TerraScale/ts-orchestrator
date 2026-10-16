package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
)

const bootstrapPendingFile = "netbird-bootstrap.pending"

// EnrollBootstrap excludes rollout admission and recovery through enrollment.
func EnrollBootstrap(ctx context.Context, configPath string) error {
	m, err := localManagedClient()
	if err != nil {
		return err
	}
	return m.enrollBootstrap(ctx, configPath)
}

func (m managedClient) enrollBootstrap(ctx context.Context, configPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err := m.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	transaction, err := m.readTransaction()
	if err != nil {
		return err
	}
	if transaction.Pending {
		return errors.New("NetBird enrollment waits for the pending managed transaction")
	}
	if err := checkBootstrapPublication(filepath.Dir(configPath)); err != nil {
		return err
	}
	cfg, err := netbird.LoadConfig(configPath)
	if err != nil {
		return err
	}
	return m.enroll(ctx, cfg)
}

// ReadBootstrapConfig reads one completed publication under the installation lock.
// Existing-client enrollment does not require an image pin.
func ReadBootstrapConfig(ctx context.Context, configPath string, requirePin bool) (Pin, netbird.Config, error) {
	m, err := localManagedClient()
	if err != nil {
		return Pin{}, netbird.Config{}, err
	}
	return m.readBootstrapConfig(ctx, configPath, requirePin)
}

func checkBootstrapPublication(configRoot string) error {
	if _, err := os.Lstat(filepath.Join(configRoot, bootstrapPendingFile)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("NetBird bootstrap configuration publication is incomplete")
}

func (m managedClient) readBootstrapConfig(ctx context.Context, configPath string, requirePin bool) (Pin, netbird.Config, error) {
	if err := ctx.Err(); err != nil {
		return Pin{}, netbird.Config{}, err
	}
	lock, err := m.lock()
	if err != nil {
		return Pin{}, netbird.Config{}, err
	}
	defer lock.Close()
	if err := checkBootstrapPublication(filepath.Dir(configPath)); err != nil {
		return Pin{}, netbird.Config{}, err
	}
	cfg, err := netbird.LoadConfig(configPath)
	if err != nil || !requirePin {
		return Pin{}, cfg, err
	}
	body, info, err := readManagedStateFile(filepath.Join(filepath.Dir(configPath), "netbird-pin.json"))
	if err != nil {
		return Pin{}, netbird.Config{}, err
	}
	if !info.Exists || len(body) > 16<<10 {
		return Pin{}, netbird.Config{}, errors.New("NetBird bootstrap pin must be a bounded protected regular file")
	}
	var pin Pin
	if err := json.Unmarshal(body, &pin, json.RejectUnknownMembers(true)); err != nil {
		return Pin{}, netbird.Config{}, errors.New("invalid NetBird bootstrap pin JSON")
	}
	if err := ValidatePin(pin); err != nil {
		return Pin{}, netbird.Config{}, err
	}
	return pin, cfg, nil
}

// InstallBootstrapConfig replaces image defaults only before any managed
// transaction; its lock excludes installation snapshots and recovery.
func InstallBootstrapConfig(ctx context.Context, configRoot string, pin Pin, cfg netbird.Config) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m, err := localManagedClient()
	if err != nil {
		return false, err
	}
	return m.installBootstrapConfig(ctx, configRoot, pin, cfg)
}

func (m managedClient) installBootstrapConfig(ctx context.Context, configRoot string, pin Pin, cfg netbird.Config) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	lock, err := m.lock()
	if err != nil {
		return false, err
	}
	defer lock.Close()
	transaction, err := m.readTransaction()
	if err != nil || transaction.TransactionID != "" {
		return false, err
	}
	if err := ValidateManagedVersion(pin.Version); err != nil {
		return false, err
	}
	if err := ValidatePin(pin); err != nil {
		return false, err
	}
	if err := cfg.Validate(); err != nil {
		return false, err
	}
	relative, err := filepath.Rel(m.root, configRoot)
	if err != nil || !filepath.IsAbs(configRoot) || relative == ".." || strings.HasPrefix(relative, "../") {
		return false, errors.New("NetBird bootstrap configuration must be within the managed root")
	}
	if _, err := secureManagedDirectory(m.root, "/"+relative, 0755); err != nil {
		return false, err
	}
	// Keep readers and fresh snapshots held until both mirrors are durable.
	marker := filepath.Join(configRoot, bootstrapPendingFile)
	if err := atomicManagedFile(marker, []byte("publication incomplete\n"), 0600); err != nil {
		return false, err
	}
	for _, file := range []struct {
		name  string
		value any
	}{{"netbird-pin.json", pin}, {"netbird.json", cfg}} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		body, err := json.Marshal(file.value)
		if err != nil {
			return false, err
		}
		if err := atomicManagedFile(filepath.Join(configRoot, file.name), body, 0644); err != nil {
			return false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := removeManagedFile(marker); err != nil {
		return false, err
	}
	return true, nil
}
