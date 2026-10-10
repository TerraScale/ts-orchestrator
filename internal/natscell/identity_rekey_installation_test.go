package natscell

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityRekeyPinsObservedNodeWithoutReplacingStore(t *testing.T) {
	cfg := installationIdentityFixture(t)
	node := existingInstallationPins(t, cfg)
	nodePath := filepath.Join(cfg.Embedded.StoreDir, nodeIdentityFile)
	if err := os.Remove(nodePath); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(cfg.Embedded.StoreDir, storeIdentityFile)
	before := installationStat(t, serverPath)
	dataPath := filepath.Join(cfg.Embedded.StoreDir, "serving-data")
	if err := os.WriteFile(dataPath, []byte("preserved serving state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveInstalledIdentity(cfg); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary admission accepted an absent node pin: %v", err)
	}
	observed, err := ObserveIdentityRekeyInstallation(cfg, node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(nodePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("observation published a pin: %v", err)
	}
	uid, gid := uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid()))
	if err := pinIdentityRekeyInstallation(cfg, observed, uid, gid); err != nil {
		t.Fatal(err)
	}
	actual, err := ObserveInstalledIdentity(cfg)
	if err != nil || actual != observed {
		t.Fatalf("installed identity = %+v, %v; want %+v", actual, err, observed)
	}
	pinBefore := installationStat(t, nodePath)
	if err := pinIdentityRekeyInstallation(cfg, observed, uid, gid); err != nil {
		t.Fatal(err)
	}
	if after := installationStat(t, nodePath); after.Ino != pinBefore.Ino || after.Uid != uid || after.Gid != gid {
		t.Fatalf("retry replaced or changed ownership of the pin: %+v", after)
	}
	if after := installationStat(t, serverPath); after != before {
		t.Fatalf("server pin changed: before %+v, after %+v", before, after)
	}
	wire, err := os.ReadFile(dataPath)
	if err != nil || !bytes.Equal(wire, []byte("preserved serving state")) {
		t.Fatalf("serving store changed: %q, %v", wire, err)
	}
}

func TestIdentityRekeyNodeObservationRejectsForeignAndIndirectPins(t *testing.T) {
	for _, kind := range []string{"foreign node", "foreign broker", "foreign digest", "node symlink", "dangling node symlink", "node hardlink", "missing server", "store symlink"} {
		t.Run(kind, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			node := existingInstallationPins(t, cfg)
			observed, err := ObserveInstalledIdentity(cfg)
			if err != nil {
				t.Fatal(err)
			}
			nodePath := filepath.Join(cfg.Embedded.StoreDir, nodeIdentityFile)
			original, err := os.ReadFile(nodePath)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign node":
				node = "foreign1"
				observed.RaftNodeID = node
			case "foreign broker":
				observed.CellAccount = observed.SystemAccount
			case "foreign digest":
				observed.NodeIdentitySHA256 = observed.ServerNameSHA256
			case "node symlink", "dangling node symlink", "node hardlink":
				target := filepath.Join(t.TempDir(), "target")
				if kind != "dangling node symlink" {
					if err := os.WriteFile(target, original, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Remove(nodePath); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "node hardlink" {
					link = os.Link
				}
				if err := link(target, nodePath); err != nil {
					t.Fatal(err)
				}
			case "missing server":
				if err := os.Remove(filepath.Join(cfg.Embedded.StoreDir, storeIdentityFile)); err != nil {
					t.Fatal(err)
				}
			case "store symlink":
				path := cfg.Embedded.StoreDir + "-link"
				if err := os.Symlink(cfg.Embedded.StoreDir, path); err != nil {
					t.Fatal(err)
				}
				cfg.Embedded.StoreDir = path
			}
			if kind != "foreign broker" && kind != "foreign digest" {
				if _, err := ObserveIdentityRekeyInstallation(cfg, node); err == nil {
					t.Fatal("accepted an unproven or indirect node identity")
				}
			}
			uid, gid := uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid()))
			if err := pinIdentityRekeyInstallation(cfg, observed, uid, gid); err == nil {
				t.Fatal("published an unproven or indirect node identity")
			}
			if kind == "foreign node" || kind == "foreign broker" || kind == "foreign digest" {
				wire, err := os.ReadFile(nodePath)
				if err != nil || !bytes.Equal(wire, original) {
					t.Fatalf("refusal changed the existing pin: %q, %v", wire, err)
				}
			}
		})
	}
}
