package foundation

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	managerbundle "github.com/TerraScale/ts-orchestrator/deploy/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	DataDirectory  = "/var/lib/terrascale/netbird"
	ConfigPath     = "/run/terrascale-netbird/config.yaml"
	stackDirectory = "/opt/terrascale/netbird"
	localOrigin    = "http://127.0.0.1:18081"
)

// Supervisor owns upstream foundation processes independently of SwarmKit and the overlay.
type Supervisor struct {
	Vault        BootstrapVault
	PrepareStore func(context.Context) error
	StoreReady   func(context.Context) error
	Account      func(context.Context, func(context.Context) error) error
}

func (s Supervisor) validate() error {
	if s.PrepareStore == nil || s.StoreReady == nil || s.Account == nil {
		return errors.New("NetBird supervisor requires authenticated store lifecycle and serialized account owner")
	}
	return s.Vault.validate()
}

func systemctl(ctx context.Context, args ...string) error {
	if err := exec.CommandContext(ctx, "systemctl", args...).Run(); err != nil {
		return fmt.Errorf("NetBird systemd %s failed", args[0])
	}
	return nil
}

// Install stages only the single-binary host supervisor and its embedded upstream configuration.
func (s Supervisor) Install(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("NetBird foundation installation requires root")
	}
	for _, directory := range []string{DataDirectory, filepath.Dir(ConfigPath), stackDirectory} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return errors.New("NetBird foundation directory creation failed")
		}
	}
	for _, name := range []string{"systemd/netbird-backup.service", "systemd/netbird-backup.timer", "Caddyfile.netbird", "dashboard.environment", "templates/config.yaml.tmpl"} {
		wire, err := fs.ReadFile(managerbundle.Files, name)
		if err != nil {
			return errors.New("NetBird embedded deployment asset missing")
		}
		target := filepath.Join(stackDirectory, name)
		if strings.HasPrefix(name, "systemd/") {
			target = filepath.Join("/etc/systemd/system", filepath.Base(name))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return errors.New("NetBird asset directory creation failed")
		}
		if err := os.WriteFile(target, wire, 0644); err != nil {
			return errors.New("NetBird asset installation failed")
		}
	}
	if err := os.WriteFile("/etc/systemd/system/netbird-foundation.service", []byte(foundationUnit), 0644); err != nil {
		return errors.New("NetBird foundation unit installation failed")
	}
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := systemctl(ctx, "enable", "netbird-foundation.service"); err != nil {
		return err
	}
	return systemctl(ctx, "restart", "netbird-foundation.service")
}

// Run observes the shim-owned upstream tasks and repairs failures, with fixed credential renewal.
func (s Supervisor) Run(ctx context.Context) error {
	if _, err := s.Reconcile(ctx); err != nil {
		return err
	}
	health := time.NewTicker(15 * time.Second)
	defer health.Stop()
	account := time.NewTicker(time.Minute)
	defer account.Stop()
	renew := time.NewTicker(6 * time.Hour)
	defer renew.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-account.C:
			if err := s.maintain(ctx); err != nil {
				log.Printf("NetBird account reconciliation deferred: %v", err)
			}
		case <-renew.C:
			if _, err := s.Reconcile(ctx); err != nil {
				return err
			}
		case <-health.C:
			runtime, err := newFoundationRuntime()
			if err != nil {
				return err
			}
			healthy := runtime.healthy(ctx)
			runtime.client.Close()
			if !healthy {
				if _, err := s.Reconcile(ctx); err != nil {
					return err
				}
			}
		}
	}
}

// Reconcile holds the same local exclusion lock as backup, then opens ingress only after verified setup.
func (s Supervisor) Reconcile(ctx context.Context) (BootstrapResult, error) {
	var result BootstrapResult
	unlock, err := serviceLock(ctx)
	if err != nil {
		return result, err
	}
	defer unlock()
	if err = s.validate(); err != nil {
		return result, err
	}
	runtime, err := newFoundationRuntime()
	if err != nil {
		return result, err
	}
	defer runtime.client.Close()
	if err = runtime.stop(ctx, "netbird-ingress", s.Vault.Check); err != nil {
		return result, err
	}
	// Closing old handlers fences uncertain account writes before any bootstrap retry.
	if err = runtime.stop(ctx, "netbird-server", s.Vault.Check); err != nil {
		return result, err
	}
	if err = s.PrepareStore(ctx); err != nil {
		return result, err
	}
	if err = s.Render(ctx); err != nil {
		return result, err
	}
	components, err := foundationComponents()
	if err != nil {
		return result, err
	}
	for _, component := range components[:2] {
		if err = runtime.ensure(ctx, component, s.Vault.Check); err != nil {
			return result, err
		}
	}
	if err = s.wait(ctx, false); err != nil {
		return result, err
	}
	result, err = Bootstrap(ctx, localOrigin, DataDirectory+"/data/terrascale-identity", s.Vault)
	if err != nil {
		return result, err
	}
	if err = s.Account(ctx, s.quiesceStoreLocked); err != nil {
		return result, err
	}
	if err = s.StoreReady(ctx); err != nil {
		return result, err
	}
	if err = runtime.ensure(ctx, components[2], s.Vault.Check); err != nil {
		return result, err
	}
	if err = systemctl(ctx, "enable", "--now", "netbird-backup.timer"); err != nil {
		return result, err
	}

	return result, nil
}

func (s Supervisor) maintain(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	unlock, err := serviceLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.Account(ctx, s.quiesceLocked)
}

// Render recreates the runtime-only config from existing Vault keys; Ensure never rotates identity material.
func (s Supervisor) Render(ctx context.Context) error {
	if err := s.Vault.validate(); err != nil {
		return err
	}
	management := fencedBootstrapVault{s.Vault.Management, s.Vault.Check}
	wire, err := fs.ReadFile(managerbundle.Files, "templates/config.yaml.tmpl")
	if err != nil {
		return err
	}
	for _, key := range []string{"NETBIRD_RELAY_AUTH_SECRET", "NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY", "NETBIRD_DATASTORE_ENCRYPTION_KEY"} {
		name := vaultsecret.Name("gru-1", key)
		stored, err := vaultsecret.Ensure(ctx, management, s.Vault.Target, name, "NetBird foundation encryption and authentication material", func(context.Context) (string, error) {
			entries, err := os.ReadDir(DataDirectory + "/data")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", errors.New("NetBird existing data inspection failed")
			}
			for _, entry := range entries {
				if entry.Name() == "foundation-tls" && entry.IsDir() {
					children, readErr := os.ReadDir(DataDirectory + "/data/foundation-tls")
					if readErr == nil && len(children) == 0 {
						continue
					}
				}
				return "", errors.New("NetBird existing identity requires its original Vault keys")
			}
			return keyCredential(), nil
		})
		if err != nil {
			return errors.New("NetBird configuration credential provisioning failed")
		}
		value, err := vaultsecret.ReadBack(ctx, s.Vault.Bundles, s.Vault.Target.VaultID, name, stored.Created || stored.Provisioning)
		if err != nil || len(value) < 32 || len(value) > 256 {
			return errors.New("NetBird configuration credential delivery failed")
		}
		// Quoted YAML preserves generated padded base64 and restored upstream keys.
		quoted := fmt.Sprintf("%q", value)
		wire = []byte(strings.ReplaceAll(string(wire), "{{"+key+"}}", quoted))
	}
	if strings.Contains(string(wire), "{{") {
		return errors.New("NetBird configuration contains unresolved credentials")
	}
	if err := os.MkdirAll(filepath.Dir(ConfigPath), 0700); err != nil {
		return errors.New("NetBird runtime directory creation failed")
	}
	temp, err := os.CreateTemp(filepath.Dir(ConfigPath), ".config-*")
	if err != nil {
		return errors.New("NetBird runtime configuration creation failed")
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(wire); err != nil {
		temp.Close()
		return errors.New("NetBird runtime configuration write failed")
	}
	if err = temp.Close(); err != nil {
		return errors.New("NetBird runtime configuration close failed")
	}
	if err = os.Rename(temp.Name(), ConfigPath); err != nil {
		return errors.New("NetBird runtime configuration publication failed")
	}
	return nil
}

// Pause is called while Backup holds the shared snapshot lock; only its returned resume reopens the store.
func (s Supervisor) Pause(ctx context.Context) (func(context.Context) error, error) {
	runtime, err := newFoundationRuntime()
	if err != nil {
		return nil, err
	}
	defer runtime.client.Close()
	resume := func(resumeCtx context.Context) error {
		runtime, err := newFoundationRuntime()
		if err != nil {
			return err
		}
		defer runtime.client.Close()
		components, err := foundationComponents()
		if err != nil {
			return err
		}
		if err = runtime.ensure(resumeCtx, components[0], s.Vault.Check); err != nil {
			return err
		}
		if err = s.wait(resumeCtx, true); err != nil {
			return err
		}
		return runtime.ensure(resumeCtx, components[2], s.Vault.Check)
	}
	if err = runtime.stop(ctx, "netbird-ingress", s.Vault.Check); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		return nil, errors.Join(err, resume(cleanup))
	}
	if err = runtime.stop(ctx, "netbird-server", s.Vault.Check); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		return nil, errors.Join(err, resume(cleanup))
	}
	return resume, nil
}

// Quiesce closes every old handler before reopening the same manager store for setup-key recovery.
func (s Supervisor) Quiesce(ctx context.Context) error {
	unlock, err := serviceLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.quiesceLocked(ctx)
}

// Bootstrap recovery drains old requests without opening ingress before store readiness.
func (s Supervisor) quiesceStoreLocked(ctx context.Context) error {
	runtime, err := newFoundationRuntime()
	if err != nil {
		return err
	}
	defer runtime.client.Close()
	if err := runtime.stop(ctx, "netbird-server", s.Vault.Check); err != nil {
		return err
	}
	components, err := foundationComponents()
	if err != nil {
		return err
	}
	if err := runtime.ensure(ctx, components[0], s.Vault.Check); err != nil {
		return err
	}
	return s.wait(ctx, true)
}

func (s Supervisor) quiesceLocked(ctx context.Context) error {
	resume, err := s.Pause(ctx)
	if err != nil {
		return err
	}
	return resume(ctx)
}

func (s Supervisor) wait(ctx context.Context, authenticated bool) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	client, err := newBootstrapClient(localOrigin)
	if err != nil {
		return err
	}
	defer client.http.CloseIdleConnections()
	path, authorization := "/instance", ""
	if authenticated {
		value, err := vaultsecret.Read(ctx, s.Vault.Bundles, s.Vault.Target.VaultID, ManagementSecretName)
		if err != nil {
			return errors.New("NetBird readiness credential unavailable")
		}
		path = "/users"
		authorization = "Token " + value
	}
	for {
		if err = client.api(ctx, "GET", path, authorization, nil, new(any)); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("NetBird upstream readiness deadline exceeded")
		case <-time.After(time.Second):
		}
	}
}

const foundationUnit = `[Unit]
Description=TerraScale NetBird foundation lifecycle
After=network-online.target containerd.service
Wants=network-online.target
Requires=containerd.service
[Service]
ExecStart=/usr/local/bin/ts-orch netbird foundation serve
Restart=always
RestartSec=30
RuntimeDirectory=terrascale-netbird
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
LimitCORE=0
[Install]
WantedBy=multi-user.target
`
