package natscell

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func installationIdentityFixture(t *testing.T) Config {
	t.Helper()
	cfg, _, _, _ := productionPreflightFixture(t)
	systemWire, err := os.ReadFile(cfg.Embedded.SystemJWTFile)
	if err != nil {
		t.Fatal(err)
	}
	system, err := jwt.DecodeAccountClaims(string(systemWire))
	if err != nil {
		t.Fatal(err)
	}
	cellWire, err := os.ReadFile(cfg.Embedded.CellJWTFile)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := jwt.DecodeAccountClaims(string(cellWire))
	if err != nil {
		t.Fatal(err)
	}
	// Every cell account also carries the link signer (TS-803), which is no
	// broker identity.
	for _, role := range []string{"host", "role", linkRole} {
		key, err := nkeys.CreateAccount()
		if err != nil {
			t.Fatal(err)
		}
		public, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		scope := jwt.NewUserScope()
		scope.Key, scope.Role = public, role
		cell.SigningKeys.AddScopedSigner(scope)
	}
	// The preflight fixture exposes no operator key; re-sign its current accounts.
	operatorKey, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, err := operatorKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	operator := jwt.NewOperatorClaims(operatorID)
	operator.SystemAccount = system.Subject
	for path, claim := range map[string]jwt.Claims{
		cfg.Embedded.OperatorJWTFile: operator,
		cfg.Embedded.SystemJWTFile:   system,
		cfg.Embedded.CellJWTFile:     cell,
	} {
		wire, err := claim.Encode(operatorKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func existingInstallationPins(t *testing.T, cfg Config) string {
	t.Helper()
	if err := os.MkdirAll(cfg.Embedded.StoreDir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := ServerName(cfg.Cell, cfg.Instance)
	prepared, err := server.NewServer(&server.Options{ServerName: name, DontListen: true, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Shutdown()
	if err := pinStoreIdentity(cfg.Embedded.StoreDir, name, cfg.Cell+"-"+cfg.Instance); err != nil {
		t.Fatal(err)
	}
	if err := pinNodeIdentity(cfg.Embedded.StoreDir, cfg.Cell, cfg.Instance, prepared.NodeName()); err != nil {
		t.Fatal(err)
	}
	return prepared.NodeName()
}

func installationStat(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	stat.Atim = unix.Timespec{}
	return stat
}

func TestPrepareInitialInstallationIdentityPreservesCurrentStore(t *testing.T) {
	for _, test := range []struct {
		cell, name string
		existing   bool
	}{
		{cell: "gru", name: "gru-1-ctl-1"},
		{cell: "gru", name: "gru-1-ctl-1", existing: true},
		{cell: "sjc", name: "ts-sjc-1"},
		{cell: "sjc", name: "ts-sjc-1", existing: true},
	} {
		state := "new nested store"
		if test.existing {
			state = "current serving store"
		}
		t.Run(test.cell+"/"+state, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			cfg.Cell, cfg.Instance, cfg.Embedded.BrokerIDs = test.cell, "controller-a", []string{"controller-a"}
			cfg.Embedded.StoreDir = filepath.Join(cfg.Embedded.StoreDir, "nested", "store")
			var nodeID string
			var dataPath string
			if test.existing {
				nodeID = existingInstallationPins(t, cfg)
				dataPath = filepath.Join(cfg.Embedded.StoreDir, "jetstream", "current-state")
				if err := os.Mkdir(filepath.Dir(dataPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dataPath, []byte("serving state"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			uid, gid := uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid()))
			identity, err := PrepareInitialInstallationIdentity(cfg, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if identity.Directory != cfg.Embedded.StoreDir || identity.ServerName != test.name ||
				!validNodeID(identity.RaftNodeID) || test.existing && identity.RaftNodeID != nodeID ||
				identity.HostSigner == "" || identity.RoleSigner == "" {
				t.Fatalf("installed identity changed physical names or omitted signing scopes: %+v", identity)
			}
			pins := make(map[string]unix.Stat_t)
			for _, name := range []string{storeIdentityFile, nodeIdentityFile} {
				path := filepath.Join(cfg.Embedded.StoreDir, name)
				stat := installationStat(t, path)
				if stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid {
					t.Fatalf("unsafe published pin %s: %+v", name, stat)
				}
				pins[path] = stat
			}
			if mode := installationStat(t, cfg.Embedded.StoreDir).Mode & 0o7777; mode != 0o700 {
				t.Fatalf("store mode = %o", mode)
			}
			observed, err := ObserveInstalledIdentity(cfg)
			if err != nil || observed != identity {
				t.Fatalf("observe current identity: %+v, %v", observed, err)
			}
			retried, err := PrepareInitialInstallationIdentity(cfg, uid, gid)
			if err != nil || retried != identity {
				t.Fatalf("retry changed identity: %+v, %v", retried, err)
			}
			for path, before := range pins {
				if after := installationStat(t, path); after.Ino != before.Ino {
					t.Fatalf("retry replaced pin %s", path)
				}
			}
			if test.existing {
				wire, err := os.ReadFile(dataPath)
				if err != nil || string(wire) != "serving state" {
					t.Fatalf("current store changed: %q, %v", wire, err)
				}
			}
		})
	}
}

func TestPrepareInitialInstallationIdentityRejectsIndirectDirectories(t *testing.T) {
	for _, kind := range []string{"store symlink", "ancestor symlink", "dangling symlink", "file ancestor", "unclean", "relative", "root"} {
		t.Run(kind, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			root := filepath.Dir(cfg.Embedded.StoreDir)
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "store symlink", "ancestor symlink", "dangling symlink":
				linkTarget := target
				if kind == "dangling symlink" {
					linkTarget = filepath.Join(target, "missing")
				}
				if err := os.Symlink(linkTarget, cfg.Embedded.StoreDir); err != nil {
					t.Fatal(err)
				}
				if kind == "ancestor symlink" {
					cfg.Embedded.StoreDir = filepath.Join(cfg.Embedded.StoreDir, "missing", "store")
				}
			case "file ancestor":
				if err := os.WriteFile(cfg.Embedded.StoreDir, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.Embedded.StoreDir += "/missing"
			case "unclean":
				cfg.Embedded.StoreDir = target + "/../target"
			case "relative":
				cfg.Embedded.StoreDir = "relative-store"
			case "root":
				cfg.Embedded.StoreDir = "/"
			}
			before := installationStat(t, target)
			if _, err := PrepareInitialInstallationIdentity(cfg, uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid()))); err == nil {
				t.Fatal("indirect store path accepted")
			}
			if kind != "root" {
				if _, err := ObserveInstalledIdentity(cfg); err == nil {
					t.Fatal("indirect store path observed")
				}
			}
			if after := installationStat(t, target); after != before {
				t.Fatal("rejected path changed target metadata")
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected path created target state: %v, %v", entries, err)
			}
		})
	}
}

func TestPrepareInitialInstallationIdentityRejectsUnsafePinsWithoutMutation(t *testing.T) {
	for _, name := range []string{storeIdentityFile, nodeIdentityFile} {
		for _, kind := range []string{"symlink", "dangling symlink", "hardlink", "mismatch", "permissions", "directory", "fifo", "oversized"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				cfg := installationIdentityFixture(t)
				existingInstallationPins(t, cfg)
				path := filepath.Join(cfg.Embedded.StoreDir, name)
				other := filepath.Join(filepath.Dir(cfg.Embedded.StoreDir), "other-pin")
				switch kind {
				case "symlink", "dangling symlink":
					if err := os.Rename(path, other); err != nil {
						t.Fatal(err)
					}
					target := other
					if kind == "dangling symlink" {
						target += ".missing"
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(path, other); err != nil {
						t.Fatal(err)
					}
				case "mismatch":
					wire := []byte(ServerName(cfg.Cell, cfg.Instance) + "\nextra")
					if name == nodeIdentityFile {
						wire = []byte(`{"version":1,"cell":"sjc","instance":"broker-a","node_id":"abc123XY"}`)
					}
					if err := os.WriteFile(path, wire, 0o600); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
				case "directory", "fifo":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if kind == "directory" {
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					} else if err := unix.Mkfifo(path, 0o600); err != nil {
						t.Fatal(err)
					}
				case "oversized":
					if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 4097), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				before := map[string]unix.Stat_t{}
				for _, candidate := range []string{cfg.Embedded.StoreDir, filepath.Join(cfg.Embedded.StoreDir, storeIdentityFile),
					filepath.Join(cfg.Embedded.StoreDir, nodeIdentityFile)} {
					before[candidate] = installationStat(t, candidate)
				}
				if kind == "symlink" || kind == "dangling symlink" || kind == "hardlink" {
					before[other] = installationStat(t, other)
				}
				if _, err := PrepareInitialInstallationIdentity(cfg, uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid()))); err == nil {
					t.Fatal("unsafe pin accepted")
				}
				if _, err := ObserveInstalledIdentity(cfg); err == nil {
					t.Fatal("unsafe pin observed")
				}
				for candidate, stat := range before {
					if after := installationStat(t, candidate); after != stat {
						t.Fatalf("rejected pin changed metadata at %s", candidate)
					}
				}
			})
		}
	}
}

func TestPrepareInitialInstallationIdentityChecksBothPinsBeforePublishing(t *testing.T) {
	for _, bad := range []string{storeIdentityFile, nodeIdentityFile} {
		t.Run(bad, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			existingInstallationPins(t, cfg)
			for _, name := range []string{storeIdentityFile, nodeIdentityFile} {
				path := filepath.Join(cfg.Embedded.StoreDir, name)
				if name == bad {
					if err := os.WriteFile(path, []byte("another installation"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			before := installationStat(t, cfg.Embedded.StoreDir)
			// Invalid identity must win over a chown to an unauthorized service user.
			if _, err := PrepareInitialInstallationIdentity(cfg, uint32(os.Getuid()+1), uint32(os.Getgid()+1)); !errors.Is(err, ErrStoreIdentity) {
				t.Fatalf("mismatch was not checked before ownership changes: %v", err)
			}
			if after := installationStat(t, cfg.Embedded.StoreDir); after != before {
				t.Fatal("mismatch changed store metadata")
			}
			entries, err := os.ReadDir(cfg.Embedded.StoreDir)
			if err != nil || len(entries) != 1 || entries[0].Name() != bad {
				t.Fatalf("mismatch published missing pin: %v, %v", entries, err)
			}
		})
	}
}

func TestPrepareInitialInstallationIdentityRefusesUnpinnedJetStreamState(t *testing.T) {
	for _, instance := range []string{"controller-a", "seed-a"} {
		for _, existing := range []string{"none", storeIdentityFile, nodeIdentityFile} {
			for _, kind := range []string{"populated", "symlink"} {
				t.Run(instance+"/"+existing+"/"+kind, func(t *testing.T) {
					cfg := installationIdentityFixture(t)
					cfg.Instance, cfg.Embedded.BrokerIDs = instance, []string{instance}
					var before unix.Stat_t
					var pinWire []byte
					if existing != "none" {
						existingInstallationPins(t, cfg)
						for _, name := range []string{storeIdentityFile, nodeIdentityFile} {
							path := filepath.Join(cfg.Embedded.StoreDir, name)
							if name == existing {
								before = installationStat(t, path)
								var err error
								pinWire, err = os.ReadFile(path)
								if err != nil {
									t.Fatal(err)
								}
							} else if err := os.Remove(path); err != nil {
								t.Fatal(err)
							}
						}
					}
					path := filepath.Join(cfg.Embedded.StoreDir, "jetstream")
					if err := os.MkdirAll(path, 0o700); err != nil {
						t.Fatal(err)
					}
					if kind == "symlink" {
						if err := os.Rename(path, path+".other"); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(path+".other", path); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(filepath.Join(path, "serving"), []byte("current state"), 0o600); err != nil {
						t.Fatal(err)
					}
					if _, err := PrepareInitialInstallationIdentity(cfg, uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid()))); err == nil {
						t.Fatal("unidentified or indirect serving store was claimed")
					}
					for _, name := range []string{storeIdentityFile, nodeIdentityFile} {
						if name == existing {
							path := filepath.Join(cfg.Embedded.StoreDir, name)
							wire, err := os.ReadFile(path)
							if err != nil || !bytes.Equal(wire, pinWire) || installationStat(t, path) != before {
								t.Fatal("refusal changed the existing pin")
							}
							continue
						}
						if _, err := os.Lstat(filepath.Join(cfg.Embedded.StoreDir, name)); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("unidentified store gained %s: %v", name, err)
						}
					}
				})
			}
		}
	}
}

func TestPrepareInitialInstallationIdentityRecoversPinsOnlyOnEmptyStore(t *testing.T) {
	for _, missing := range []string{storeIdentityFile, nodeIdentityFile} {
		t.Run(missing, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			node := existingInstallationPins(t, cfg)
			if err := os.Remove(filepath.Join(cfg.Embedded.StoreDir, missing)); err != nil {
				t.Fatal(err)
			}
			identity, err := PrepareInitialInstallationIdentity(cfg, uint32(max(1, os.Getuid())), uint32(max(1, os.Getgid())))
			if err != nil || identity.RaftNodeID != node {
				t.Fatalf("interrupted empty-store preparation: %+v, %v", identity, err)
			}
		})
	}
}

func TestObserveInstalledIdentityDoesNotCreateOrRepairPins(t *testing.T) {
	for _, missing := range []string{"store", storeIdentityFile, nodeIdentityFile, "none"} {
		t.Run(missing, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			if missing == "store" {
				if _, err := ObserveInstalledIdentity(cfg); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing store: %v", err)
				}
				if _, err := os.Lstat(cfg.Embedded.StoreDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("observation created store: %v", err)
				}
				return
			}
			existingInstallationPins(t, cfg)
			if missing != "none" {
				if err := os.Remove(filepath.Join(cfg.Embedded.StoreDir, missing)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(cfg.Embedded.StoreDir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(cfg.Embedded.StoreDir, 0o700) })
			before := installationStat(t, cfg.Embedded.StoreDir)
			_, err := ObserveInstalledIdentity(cfg)
			if missing == "none" && err != nil || missing != "none" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read-only observation: %v", err)
			}
			if after := installationStat(t, cfg.Embedded.StoreDir); after != before {
				t.Fatal("observation changed read-only store")
			}
			if missing != "none" {
				if _, err := os.Lstat(filepath.Join(cfg.Embedded.StoreDir, missing)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("observation created %s: %v", missing, err)
				}
			}
		})
	}
}

func TestInstallationPinPublicationCannotReplaceConcurrentOwner(t *testing.T) {
	dir, err := openInstallationDirectory(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	var workers sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		workers.Go(func() {
			file, err := publishInstallationPin(dir, storeIdentityFile, []byte("owner\n"))
			if file != nil {
				err = errors.Join(err, file.Close())
			}
			errs <- err
		})
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if file, err := publishInstallationPin(dir, storeIdentityFile, []byte("another owner\n")); !errors.Is(err, ErrStoreIdentity) || file != nil {
		t.Fatalf("concurrent pin was replaced: %v, %v", file, err)
	}
	wire, err := readInstallationFileAt(dir, storeIdentityFile, 4096)
	if err != nil || string(wire) != "owner\n" {
		t.Fatalf("owner changed: %q, %v", wire, err)
	}
}

func TestInstallationPinPublicationUsesHeldDirectory(t *testing.T) {
	root := t.TempDir()
	path, moved, victim := filepath.Join(root, "store"), filepath.Join(root, "moved"), filepath.Join(root, "victim")
	for _, directory := range []string{path, victim} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := openInstallationDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	file, err := publishInstallationPin(dir, storeIdentityFile, []byte("owner\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if wire, err := os.ReadFile(filepath.Join(moved, storeIdentityFile)); err != nil || string(wire) != "owner\n" {
		t.Fatalf("held directory did not receive pin: %q, %v", wire, err)
	}
	if entries, err := os.ReadDir(victim); err != nil || len(entries) != 0 {
		t.Fatalf("replacement symlink target changed: %v, %v", entries, err)
	}
}
