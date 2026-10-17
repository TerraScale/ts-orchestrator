//go:build fixturetest

package app

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// The peers use the same original generated material as the installed seed.
// They have independent native stores; this does not admit bootstrap peers.
func startInstalledControllerBrokers(t *testing.T, ctx context.Context, installed *installedControllerFixture) []*natscell.Runtime {
	t.Helper()
	requireInstalledControllerNamespace(t)
	if ctx == nil || ctx.Err() != nil || installed == nil || installed.Config.NATS.Embedded == nil {
		t.Fatal("installed brokers require their original live installation")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		t.Fatal("installed brokers require a finite root runtime")
	}
	record, err := bootstrapmaterial.Load(installed.SourceDirectory)
	if err != nil || !time.Now().Before(record.ExpiresAt) {
		t.Fatal("installed broker material source changed", err)
	}
	configs := make([]natscell.Config, 0, len(record.Config.Slots))
	for _, slot := range record.Config.Slots {
		cfg := installed.Config.NATS
		if slot.Name != cfg.Instance {
			cfg.Instance = slot.Name
			cfg.URL = "tls://" + slot.PrivateIP + ":4222"
			material := func(name string) string {
				t.Helper()
				path := filepath.Join(installed.SourceDirectory, name)
				wire, err := os.ReadFile(path)
				index := slices.IndexFunc(record.Files, func(file bootstrapmaterial.File) bool { return file.Name == name })
				if err != nil || index < 0 || int64(len(wire)) > record.Files[index].MaxBytes || controllerSHA256(wire) != record.Files[index].SHA256 {
					t.Fatal("original generated broker material changed: "+name, err)
				}
				return path
			}
			cfg.CredentialsFile = material(slot.Name + ".creds")
			cfg.TLS = natscell.TLSFiles{CAFile: material("ca.pem"), CertFile: material(slot.Name + "-tls-cert.pem"), KeyFile: material(slot.Name + "-tls-key.pem")}
			embedded := *cfg.Embedded
			cfg.Embedded = &embedded
			embedded.Host, embedded.RouteHost = slot.PrivateIP, slot.PrivateIP
			embedded.StoreDir = filepath.Join("/var/lib/installed-controller-peers", slot.Name, "nats")
			embedded.TLS, embedded.RouteTLS = cfg.TLS, cfg.TLS
			embedded.OperatorJWTFile, embedded.SystemJWTFile = material("operator.jwt"), material("system.jwt")
			embedded.CellJWTFile, embedded.SystemCredentialsFile = material("cell.jwt"), material("system.creds")
			embedded.RoutePasswordFile, embedded.TicketPublicKeyFile = material("route-password"), material("ticket.pub")
			embedded.Routes = nil
			for _, other := range record.Config.Slots {
				if other.Name != slot.Name {
					embedded.Routes = append(embedded.Routes, "nats-route://"+other.PrivateIP+":6222")
				}
			}
			if _, err := natscell.PrepareInitialInstallationIdentity(cfg, installed.ServiceUID, installed.ServiceGID); err != nil {
				t.Fatal("prepare independent native peer store", err)
			}
		}
		if err := natscell.ValidateProductionCredentials(cfg); err != nil {
			t.Fatal("production generated broker credentials", err)
		}
		configs = append(configs, cfg)
	}
	if len(configs) != 3 {
		t.Fatal("installed broker source does not contain three slots")
	}
	brokers := make([]*natscell.Runtime, len(configs))
	startErrors := make([]error, len(configs))
	var starts sync.WaitGroup
	for index := range configs {
		starts.Go(func() { brokers[index], startErrors[index] = natscell.Start(ctx, configs[index]) })
	}
	starts.Wait()
	for _, broker := range brokers {
		if broker != nil {
			t.Cleanup(func() { _ = broker.Close() })
		}
	}
	for index, err := range startErrors {
		if err != nil {
			t.Fatalf("start original broker %s: %v", configs[index].Instance, err)
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		for _, broker := range brokers {
			ready = ready && broker.FullClusterReady(3)
		}
		if ready {
			return brokers
		}
		select {
		case <-ctx.Done():
			t.Fatal("original three-broker metadata group did not become ready", ctx.Err())
		case <-ticker.C:
		}
	}
}
