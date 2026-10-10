package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

func TestInitialMaterialMountRequiresEmptyDirectoryAndKeepsSecretsInMemory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root private mount namespace")
	}
	if os.Getenv("TS_INITIAL_MATERIAL_MOUNT_HELPER") == "" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "unshare", "--mount", "--fork", "--", binary,
			"-test.v", "-test.run=^TestInitialMaterialMountRequiresEmptyDirectoryAndKeepsSecretsInMemory$")
		command.Env = append(os.Environ(), "TS_INITIAL_MATERIAL_MOUNT_HELPER=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("private initial material mount: %v\n%s", err, output)
		}
		return
	}
	// CI mounts /tmp as tmpfs; the refusal case needs a disk-backed directory.
	t.Setenv("TMPDIR", "/var/tmp")
	directory := t.TempDir()
	var fs unix.Statfs_t
	if err := unix.Statfs(directory, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type == unix.TMPFS_MAGIC {
		t.Fatal("disk fixture is already on tmpfs")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, 23456, 23456); err != nil {
		t.Fatal(err)
	}
	store := MaterialStore{installedDirectory: directory, serviceUID: 23456, serviceGID: 23456, allowUnsafeAncestors: true}
	secret := filepath.Join(directory, "unexpected.key")
	if err := os.WriteFile(secret, []byte("do not hide disk secrets"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.prepareInitialMemory(); err == nil {
		t.Fatal("initial mount hid a disk secret")
	}
	if contents, err := os.ReadFile(secret); err != nil || string(contents) != "do not hide disk secrets" {
		t.Fatalf("disk secret changed: %q, %v", contents, err)
	}
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := store.prepareInitialMemory(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Unmount(directory, 0) })
	dir, err := openMaterialDirectory(directory, 23456, 23456, 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	if !memoryFilesystem(dir) {
		t.Fatal("fresh credential directory is disk-backed")
	}
	if names, err := os.ReadDir(directory); err != nil || len(names) != 0 {
		t.Fatal("fresh tmpfs contains material before admission")
	}
	if err := os.WriteFile(secret, []byte("keep memory secrets"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.prepareInitialMemory(); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(secret); err != nil || string(contents) != "keep memory secrets" {
		t.Fatalf("tmpfs secret changed: %q, %v", contents, err)
	}
}

func TestRestoreIntactMaterialDoesNotReadVault(t *testing.T) {
	install := newGenerationInstall(t)
	store := install.store()
	refs := materialReferences(install.accepted, nil)
	reads := 0
	read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
		reads++
		return nil, errors.New("Vault unavailable")
	}
	contents, err := store.readRestoreReferences(t.Context(), refs, nil, read)
	defer clearContents(contents)
	if err != nil || reads != 0 || len(contents) != len(refs) {
		t.Fatalf("intact inventory required Vault: reads=%d, files=%d, error=%v", reads, len(contents), err)
	}
	for name := range refs {
		if !bytes.Equal(contents[name], install.read(name)) {
			t.Fatalf("installed material %s lost", name)
		}
	}
	missing := map[string]bootstrap.SecretReference{"ca.pem": refs["ca.pem"]}
	if _, err := store.readRestoreReferences(t.Context(), refs, missing, read); err == nil || reads != 1 {
		t.Fatalf("missing inventory bypassed Vault: reads=%d, error=%v", reads, err)
	}
}

func rebootArmedSuccessor(t *testing.T) (*spooledInstall, map[string][]byte, time.Time) {
	t.Helper()
	staged := newSpooledInstall(t)
	now := time.Now()
	chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	first, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.Add(time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	firstWire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first})
	if err != nil {
		t.Fatal(err)
	}
	staged.installer.store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	if err := os.WriteFile(staged.installer.store.chainCopy, firstWire, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged.installer.config, staged.config, 0o600); err != nil {
		t.Fatal(err)
	}
	generation.Generation = 2
	generation.Previous, err = trust.Fingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	staged.config = append(bytes.Clone(staged.config), '\n')
	for i := range generation.ControllerConfigs {
		if generation.ControllerConfigs[i].Slot == staged.installer.target.Slot {
			generation.ControllerConfigs[i].SHA256 = digest(staged.config)
			generation.ControllerConfigs[i].Size = int64(len(staged.config))
		}
	}
	second, err := bootstrap.SignMaterialGeneration(generation, now, now.Add(4*time.Hour), staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	staged.wire, err = bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{first, second})
	if err != nil {
		t.Fatal(err)
	}
	staged.fingerprint, _ = trust.Fingerprint(second)
	staged.spool(MaterialGenerationsFile, staged.wire)
	staged.spool(GenerationConfigFile(staged.installer.target.Slot), staged.config)
	staged.arm()
	vault := map[string][]byte{}
	for name := range materialReferences(staged.accepted, nil) {
		vault[name] = staged.read(name)
	}
	maps.Copy(vault, staged.files)
	names, err := os.ReadDir(staged.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.Remove(filepath.Join(staged.dir, name.Name())); err != nil {
			t.Fatal(err)
		}
	}
	return staged, vault, now.Add(2 * time.Hour)
}

func rebootDiskPredecessor(t *testing.T) (*spooledInstall, map[string][]byte, time.Time) {
	t.Helper()
	staged, vault, at := rebootArmedSuccessor(t)
	firstWire, err := os.ReadFile(staged.installer.store.chainCopy)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range vault {
		staged.write(name, content)
	}
	staged.write(MaterialGenerationsFile, firstWire)
	oldCA := vault["ca.pem"]
	vault[digest(oldCA)] = oldCA
	vault["ca.pem"] = append(bytes.Clone(oldCA), '\n')
	staged.files["ca.pem"] = vault["ca.pem"]
	staged.spool("ca.pem", vault["ca.pem"])
	chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	for i := range generation.Secrets {
		if generation.Secrets[i].TargetFile == "ca.pem" {
			generation.Secrets[i].SHA256 = digest(vault["ca.pem"])
			generation.Secrets[i].VersionNumber++
		}
	}
	chain[1], err = bootstrap.SignMaterialGeneration(generation, chain[1].IssuedAt, chain[1].ExpiresAt, staged.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	staged.wire, err = bootstrap.EncodeMaterialGenerationChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	staged.fingerprint, err = trust.Fingerprint(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	staged.spool(MaterialGenerationsFile, staged.wire)
	staged.arm()
	return staged, vault, at
}

func TestRebootSuccessorDiskCleanupRefusesUnverifiedPredecessor(t *testing.T) {
	t.Setenv("TMPDIR", "/var/tmp")
	for _, fault := range []string{"unknown file", "tampered secret", "fork", "old Vault unavailable"} {
		t.Run(fault, func(t *testing.T) {
			staged, vault, at := rebootDiskPredecessor(t)
			defer clearContents(vault)
			switch fault {
			case "unknown file":
				staged.write("stray.key", []byte("keep this"))
			case "tampered secret":
				staged.write("ca.pem", []byte("not the signed version"))
			case "fork":
				chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
				if err != nil {
					t.Fatal(err)
				}
				generation, err := bootstrap.MaterialGenerationPayload(chain[0])
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := bootstrap.SignMaterialGeneration(generation, chain[0].IssuedAt, chain[0].ExpiresAt.Add(time.Second), staged.rootKey)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{envelope})
				if err != nil {
					t.Fatal(err)
				}
				staged.write(MaterialGenerationsFile, wire)
			}
			before := map[string][]byte{}
			names, err := os.ReadDir(staged.dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				before[name.Name()] = staged.read(name.Name())
			}
			previous, err := os.ReadFile(staged.installer.store.chainCopy)
			if err != nil {
				t.Fatal(err)
			}
			config, err := os.ReadFile(staged.installer.config)
			if err != nil {
				t.Fatal(err)
			}
			read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
				if content, ok := vault[ref.SHA256]; ok {
					if fault == "old Vault unavailable" {
						return nil, errors.New("old Vault unavailable")
					}
					return bytes.Clone(content), nil
				}
				return bytes.Clone(vault[ref.TargetFile]), nil
			}
			if _, err := staged.installer.restoreDisk(t.Context(), staged.accepted, read, true, at); err == nil {
				t.Fatal("unverified disk predecessor was removed")
			}
			for name, content := range before {
				if !bytes.Equal(staged.read(name), content) {
					t.Fatalf("refusal changed disk %s", name)
				}
			}
			if current, err := os.ReadFile(staged.installer.store.chainCopy); err != nil || !bytes.Equal(current, previous) {
				t.Fatal("refusal changed durable chain")
			}
			if current, err := os.ReadFile(staged.installer.config); err != nil || !bytes.Equal(current, config) {
				t.Fatal("refusal changed config")
			}
		})
	}
}

func TestRebootArmedSuccessorDoesNotWriteSecretsBeforeMemoryMount(t *testing.T) {
	t.Setenv("TMPDIR", "/var/tmp")
	staged, _, at := rebootArmedSuccessor(t)
	dir, err := unix.Open(staged.dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	inMemory := memoryFilesystem(dir)
	unix.Close(dir)
	if inMemory {
		t.Skip("requires disk-backed /var/tmp")
	}
	previous, err := os.ReadFile(staged.installer.store.chainCopy)
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, err := os.ReadFile(staged.installer.config)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	read := func(context.Context, bootstrap.SecretReference) ([]byte, error) {
		reads++
		return nil, errors.New("Vault unavailable")
	}
	if _, err := staged.installer.restoreDisk(t.Context(), staged.accepted, read, false, at); err == nil || reads == 0 {
		t.Fatalf("fresh successor bypassed exact Vault reads: %d, %v", reads, err)
	}
	if names, err := os.ReadDir(staged.dir); err != nil || len(names) != 0 {
		t.Fatal("restoration wrote secrets or staging to disk before mounting tmpfs")
	}
	if current, err := os.ReadFile(staged.installer.store.chainCopy); err != nil || !bytes.Equal(current, previous) {
		t.Fatal("Vault refusal changed the durable generation")
	}
	if current, err := os.ReadFile(staged.installer.config); err != nil || !bytes.Equal(current, previousConfig) {
		t.Fatal("Vault refusal changed controller config")
	}
}

func TestRebootArmedSuccessorInstallsOnlyInMemory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root private mount namespace")
	}
	if os.Getenv("TS_REBOOT_SUCCESSOR_MOUNT_HELPER") == "" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "unshare", "--mount", "--fork", "--", binary,
			"-test.v", "-test.run=^TestRebootArmedSuccessorInstallsOnlyInMemory$")
		command.Env = append(os.Environ(), "TS_REBOOT_SUCCESSOR_MOUNT_HELPER=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("private successor mount: %v\n%s", err, output)
		}
		return
	}
	t.Setenv("TMPDIR", "/var/tmp")
	for _, state := range []string{"empty", "disk predecessor", "durable successor", "partial cleanup"} {
		t.Run(state, func(t *testing.T) {
			staged, vault, at := rebootArmedSuccessor(t)
			if state != "empty" {
				clearContents(vault)
				staged, vault, at = rebootDiskPredecessor(t)
				if state == "durable successor" || state == "partial cleanup" {
					if err := os.WriteFile(staged.installer.store.chainCopy, staged.wire, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(staged.installer.config, staged.config, 0o600); err != nil {
						t.Fatal(err)
					}
					if state == "partial cleanup" {
						if err := os.Remove(filepath.Join(staged.dir, "ca.pem")); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			defer clearContents(vault)
			read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
				if content, ok := vault[ref.SHA256]; ok {
					return bytes.Clone(content), nil
				}
				return bytes.Clone(vault[ref.TargetFile]), nil
			}
			if _, err := staged.installer.restoreDisk(t.Context(), staged.accepted, read, state != "empty", at); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { unix.Unmount(staged.dir, 0) })
			dir, err := unix.Open(staged.dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				t.Fatal(err)
			}
			inMemory := memoryFilesystem(dir)
			unix.Close(dir)
			if !inMemory {
				t.Fatal("successor private material is disk-backed")
			}
			if !bytes.Equal(staged.read(MaterialGenerationsFile), staged.wire) {
				t.Fatal("successor was not installed")
			}
			if err := verifyRestoreContents(staged.installer.target, staged.roots, staged.wire, vault, staged.installer.config, at); err != nil {
				t.Fatal(err)
			}
			if err := unix.Unmount(staged.dir, 0); err != nil {
				t.Fatal(err)
			}
			if names, err := os.ReadDir(staged.dir); err != nil || len(names) != 0 {
				t.Fatal("successor left private material beneath the tmpfs mount")
			}
		})
	}
}

func TestRebootArmedSuccessorRechecksExpiryAfterVaultRead(t *testing.T) {
	t.Setenv("TMPDIR", "/var/tmp")
	staged, vault, _ := rebootArmedSuccessor(t)
	defer clearContents(vault)
	chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
	if err != nil {
		t.Fatal(err)
	}
	at := chain[len(chain)-1].ExpiresAt.Add(-time.Second)
	waited := false
	read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
		if !waited {
			waited = true
			time.Sleep(1100 * time.Millisecond)
		}
		return bytes.Clone(vault[ref.TargetFile]), nil
	}
	if _, err := staged.installer.restoreDisk(t.Context(), staged.accepted, read, false, at); err == nil || !waited {
		t.Fatalf("expired successor admitted after Vault read: %v", err)
	}
	if names, err := os.ReadDir(staged.dir); err != nil || len(names) != 0 {
		t.Fatal("expired successor wrote disk material")
	}
	if _, err := os.Stat(staged.pending()); !os.IsNotExist(err) {
		t.Fatal("expired successor changed pending config")
	}
}

func TestRestoreAcceptsOlderDiskPrefixButRejectsDivergentChain(t *testing.T) {
	install := newGenerationInstall(t)
	firstWire, _ := install.signedGeneration()
	first, err := bootstrap.DecodeMaterialGenerationChain(firstWire)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := trust.Fingerprint(first[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 2, previous), time.Now().Add(-time.Minute), time.Now().Add(time.Hour), install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := bootstrap.EncodeMaterialGenerationChain(append(first, second))
	if err != nil {
		t.Fatal(err)
	}
	store := install.store()
	store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	if err := os.WriteFile(store.chainCopy, newer, 0o600); err != nil {
		t.Fatal(err)
	}
	install.write(MaterialGenerationsFile, firstWire)
	dir, err := openMaterialDirectory(install.dir, store.serviceUID, store.serviceGID, 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	if _, chain, err := store.restorePlan(dir, install.accepted, install.roots, time.Now()); err != nil || !bytes.Equal(chain, newer) {
		t.Fatalf("newer durable chain rejected: %v", err)
	}
	fork, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 1, ""), time.Now().Add(-time.Minute), time.Now().Add(2*time.Hour), install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	forkWire, err := bootstrap.EncodeMaterialGenerationChain([]trust.Envelope{fork})
	if err != nil {
		t.Fatal(err)
	}
	install.write(MaterialGenerationsFile, forkWire)
	if _, _, err := store.restorePlan(dir, install.accepted, install.roots, time.Now()); err == nil {
		t.Fatal("divergent disk chain admitted")
	}
}

func TestReadIdentityRekeyMaterialChecksFullVaultUnionAndPreservesImmutableFiles(t *testing.T) {
	for _, fault := range []string{"none", "response rotation", "root", "baseline", "reference", "immutable", "vault"} {
		t.Run(fault, func(t *testing.T) {
			install := newGenerationInstall(t)
			wire, generationFiles := install.signedGeneration()
			chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
			if err != nil {
				t.Fatal(err)
			}
			generation, err := bootstrap.MaterialGenerationPayload(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			accepted := install.accepted.Clone()
			accepted.MaterialGenerationSHA256, err = trust.Fingerprint(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			accepted.Broker.AccountSigner = generation.AccountSigner
			refs := materialReferences(accepted, nil)
			files := maps.Clone(generationFiles)
			for name := range refs {
				if files[name] == nil {
					files[name] = install.read(name)
				}
			}
			for _, ref := range generation.Secrets {
				refs[ref.TargetFile] = ref
			}
			accepted.MaterialReferences = nil
			for _, ref := range refs {
				accepted.MaterialReferences = append(accepted.MaterialReferences, ref)
			}
			roots := install.roots
			switch fault {
			case "response rotation":
				name := accepted.Slot + "-response.key"
				files[name] = []byte("root-authorized fresh response key")
				ref := refs[name]
				ref.VersionNumber++
				ref.SHA256 = digest(files[name])
				refs[name] = ref
				for i := range accepted.MaterialReferences {
					if accepted.MaterialReferences[i].TargetFile == name {
						accepted.MaterialReferences[i] = ref
					}
				}
			case "root":
				roots = newGenerationInstall(t).roots
			case "baseline":
				accepted.MaterialGenerationSHA256 = digest([]byte("different baseline"))
			case "reference":
				for i := range accepted.MaterialReferences {
					if accepted.MaterialReferences[i].TargetFile == "ca.pem" {
						accepted.MaterialReferences[i].VersionNumber++
					}
				}
			case "immutable":
				install.write("ticket.key", []byte("unapproved replacement"))
			}
			before, err := os.ReadDir(install.dir)
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
				reads++
				if ref != refs[ref.TargetFile] {
					t.Fatalf("reader received an unpinned reference: %s", ref.TargetFile)
				}
				if fault == "vault" && ref.TargetFile == "ticket.key" {
					return []byte("wrong Vault version"), nil
				}
				return bytes.Clone(files[ref.TargetFile]), nil
			}
			contents, err := install.store().ReadIdentityRekeyMaterial(t.Context(), accepted, wire, roots, read, time.Now())
			if fault == "none" || fault == "response rotation" {
				if err != nil || len(contents) != len(refs) || reads != len(refs) {
					t.Fatalf("full union: files=%d reads=%d error=%v", len(contents), reads, err)
				}
				for name, want := range files {
					if !bytes.Equal(contents[name], want) {
						t.Fatalf("missing baseline or generation file %s", name)
					}
				}
				if err := install.target().VerifyFiles(generation, materialReader(contents), time.Now()); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || contents != nil || fault != "vault" && reads != 0 {
				t.Fatalf("%s: reads=%d error=%v", fault, reads, err)
			}
			after, err := os.ReadDir(install.dir)
			if err != nil || len(before) != len(after) {
				t.Fatal("preinstall retrieval changed installed files")
			}
			if install.staged() {
				t.Fatal("preinstall retrieval created a stage")
			}
		})
	}
}

func TestRestoredOfflineControllerCredentialsPassRestartAdmission(t *testing.T) {
	staged := newSpooledInstall(t)
	staged.arm()
	if outcome := staged.install(); outcome != "installed generation 1" {
		t.Fatal(outcome)
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(staged.wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(chain, staged.roots, staged.expected)
	if err != nil {
		t.Fatal(err)
	}
	refs := materialReferences(staged.accepted, &verified[len(verified)-1])
	vault := map[string][]byte{}
	for name, ref := range refs {
		vault[ref.SHA256] = staged.read(name)
	}
	if !bytes.Equal(vault[refs["controller-a.creds"].SHA256], staged.files["controller-a.creds"]) {
		t.Fatal("restore planned founding credentials instead of generation pin")
	}
	read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
		return bytes.Clone(vault[ref.SHA256]), nil
	}
	contents, err := readReferences(t.Context(), refs, read)
	if err != nil {
		t.Fatal(err)
	}
	store := staged.installer.store
	if _, err := store.removeDiskCopies(contents, staged.wire); err != nil {
		t.Fatal(err)
	}
	if err := store.fill(contents, staged.wire); err != nil {
		t.Fatal(err)
	}
	staged.loaded = staged.config
	staged.credential.Config.Embedded.InterRegion = interRegionBlock(t, staged.config, staged.dir)
	if err := staged.verify(pinnedIP); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged.read("controller-a.creds"), staged.files["controller-a.creds"]) {
		t.Fatal("reboot reverted the rotated credentials")
	}
}

// After a reboot empties the in-memory credential directory, the exact Vault
// versions the manifest and the adopted generation pin, plus the chain's
// durable copy, are again what restart admission accepts (TS-745).
func TestRestoredMaterialPassesRestartAdmission(t *testing.T) {
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	store := install.store()
	store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	if err := store.AdoptGeneration(install.target(), install.roots, wire, files, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if kept, err := os.ReadFile(store.chainCopy); err != nil || !bytes.Equal(kept, wire) {
		t.Fatalf("durable chain copy = %v, want the adopted chain", err)
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(chain, install.roots, install.expected)
	if err != nil {
		t.Fatal(err)
	}
	refs := materialReferences(install.accepted, &verified[len(verified)-1])
	vault := map[string][]byte{}
	for name := range refs {
		vault[refs[name].SHA256] = install.read(name)
	}
	read := func(_ context.Context, reference bootstrap.SecretReference) ([]byte, error) {
		return bytes.Clone(vault[reference.SHA256]), nil
	}

	// A disk copy without a Vault version is never removed.
	install.write("stray.key", []byte("unrecovered"))
	contents, err := readReferences(t.Context(), refs, read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.removeDiskCopies(contents, wire); err == nil {
		t.Fatal("removed disk copies beside a file with no Vault copy")
	}
	if err := os.Remove(filepath.Join(install.dir, "stray.key")); err != nil {
		t.Fatal(err)
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("a refused removal changed the directory: %v", err)
	}
	removed, err := store.removeDiskCopies(contents, wire)
	if err != nil || removed != len(refs)+1 {
		t.Fatalf("removed %d disk copies, %v; want %d", removed, err, len(refs)+1)
	}

	// The reboot: an empty directory, filled from Vault and the copy.
	missing, err := store.missing(refs, nil)
	if err != nil || len(missing) != len(refs) {
		t.Fatalf("missing = %d, %v; want every pin", len(missing), err)
	}
	if err := store.fill(contents, wire); err != nil {
		t.Fatal(err)
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatalf("restart admission of the restored directory: %v", err)
	}
	if missing, err := store.missing(refs, nil); err != nil || len(missing) != 0 {
		t.Fatalf("missing after restore = %d, %v", len(missing), err)
	}
	// A live chain that is not its durable copy is never silently kept.
	if err := store.fill(nil, append(bytes.Clone(wire), ' ')); err == nil {
		t.Fatal("kept an installed chain that differs from its durable copy")
	}
	if note, err := store.checkRestore(t.Context(), refs, wire, read); err != nil {
		t.Fatalf("check after restore: %v", err)
	} else if note == "" {
		t.Fatal("check printed nothing")
	}
}

func TestRebootRestoresFullAcceptedBaselineWithoutRetiredFiles(t *testing.T) {
	install := newGenerationInstall(t)
	wire, files := install.signedGeneration()
	store := install.store()
	store.chainCopy = filepath.Join(t.TempDir(), MaterialGenerationsFile)
	if err := store.AdoptGeneration(install.target(), install.roots, wire, files, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	marker := testMarkerStore(t)
	acceptedWire, err := EncodeAcceptedIdentity(install.accepted)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(marker.directory, markerName), acceptedWire, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.json", "anchor.json", "controller-manifest.json"} {
		path := filepath.Join(marker.directory, name)
		if err := os.WriteFile(path, []byte("retired"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	accepted, err := marker.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := openMaterialDirectory(install.dir, store.serviceUID, store.serviceGID, 0o700, true)
	if err != nil {
		t.Fatal(err)
	}
	refs, chain, err := store.restorePlan(dir, accepted, install.roots, time.Now())
	unix.Close(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range accepted.MaterialReferences {
		if _, retained := refs[ref.TargetFile]; !retained {
			t.Fatalf("lost accepted baseline %s", ref.TargetFile)
		}
	}
	for _, name := range []string{"ticket.pub", "ticket.key", "route-password", "host-nats-issuer.seed", "controller-a-response.key"} {
		for _, baseline := range accepted.MaterialReferences {
			if baseline.TargetFile == name && refs[name] != baseline {
				t.Fatalf("immutable baseline %s was replaced", name)
			}
		}
	}
	vault := map[string][]byte{}
	for name, ref := range refs {
		vault[ref.SHA256] = install.read(name)
	}
	if _, err := store.removeDiskCopies(vaultContents(refs, vault), chain); err != nil {
		t.Fatal(err)
	}
	read := func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
		return bytes.Clone(vault[ref.SHA256]), nil
	}
	contents, err := readReferences(t.Context(), refs, read)
	if err != nil {
		t.Fatal(err)
	}
	defer clearContents(contents)
	if err := verifyRestoreContents(install.target(), install.roots, chain, contents, install.configPath, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.fill(contents, chain); err != nil {
		t.Fatal(err)
	}
	if err := install.verify(pinnedIP); err != nil {
		t.Fatal(err)
	}
	if len(contents) != len(refs) {
		t.Fatal("reboot did not restore the full inventory")
	}
}

func vaultContents(refs map[string]bootstrap.SecretReference, vault map[string][]byte) map[string][]byte {
	contents := map[string][]byte{}
	for name, ref := range refs {
		contents[name] = vault[ref.SHA256]
	}
	return contents
}

// A release that predates the durable chain copy adopts a generation without
// updating it: restore keeps the installed chain that extends the copy, and
// never a shorter or unrelated one.
func TestRestoreKeepsTheNewerInstalledChain(t *testing.T) {
	install := newGenerationInstall(t)
	first, _ := install.signedGeneration()
	chain, err := bootstrap.DecodeMaterialGenerationChain(first)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := trust.Fingerprint(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	next, err := bootstrap.SignMaterialGeneration(install.material.Generation(install.expected, 2, previous),
		time.Now().Add(-time.Minute), time.Now().AddDate(0, 6, 0), install.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	both, err := bootstrap.EncodeMaterialGenerationChain(append(chain, next))
	if err != nil {
		t.Fatal(err)
	}
	if kept, newer := newerChain(first, both); !newer || !bytes.Equal(kept, both) {
		t.Fatal("restore kept a durable copy older than the installed chain")
	}
	for _, installed := range [][]byte{first, []byte("not a chain"), nil} {
		if kept, newer := newerChain(both, installed); newer || !bytes.Equal(kept, both) {
			t.Fatalf("restore replaced the durable copy with %q", installed)
		}
	}
}
