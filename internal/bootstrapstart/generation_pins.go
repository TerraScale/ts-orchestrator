package bootstrapstart

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// MaterialGenerationsFile is the controller's adopted material generation
// chain (TS-568), kept in the credential directory beside the files it pins.
const MaterialGenerationsFile = "material-generations.json"

// MaterialPins is what restart admission expects in the credential directory.
// Before a material generation is adopted it is exactly the manifest's
// digests. With one, the newest generation's digests replace the manifest's
// for the renewable files and add its controller issuers, its interregion
// files (of the slot-bound ones, only this slot's) and the chain file itself,
// and the slot's issued files (TLS leaf, key, NATS credentials) are checked by
// the generation's issuance rules instead of a digest. An issued file still
// byte-identical to its manifest pin is accepted too, until the slot's first
// renewal. Without controller issuers (schema 2) nothing is issued: the
// issued files keep their manifest pins.
type MaterialPins struct {
	Digests map[string]string
	// Issued maps each issued file to its manifest digest; empty before a
	// generation with controller issuers is adopted.
	Issued     map[string]string
	Generation *bootstrap.VerifiedMaterialGeneration
	slot       string
	identity   bootstrapmaterial.LeafIdentity
	// config is the loaded controller config, which a schema-2 generation
	// pins as controller-<slot>.json (TS-668).
	config []byte
}

// ManifestPins pins exactly the manifest's material.
func ManifestPins(digests map[string]string) MaterialPins { return MaterialPins{Digests: digests} }

// known reports whether a file belongs in the credential directory.
func (pins MaterialPins) known(name string) bool {
	_, issued := pins.Issued[name]
	return pins.Digests[name] != "" || issued
}

func (pins MaterialPins) size() int { return len(pins.Digests) + len(pins.Issued) }

// interRegion reports whether the adopted generation pins name as an
// interregion file this slot holds.
func (pins MaterialPins) interRegion(name string) bool {
	if pins.Generation == nil || pins.Digests[name] == "" {
		return false
	}
	for _, secret := range pins.Generation.Generation().Secrets {
		if secret.TargetFile == name {
			return secret.Purpose == bootstrap.SecretInterRegion
		}
	}
	return false
}

// restartPins reads the adopted chain, if any, from the open credential
// directory and builds the pins for one slot of the manifest. The chain is
// verified as adopted: by its links and the newest generation's signature
// under roots, which may include roots rotated out since.
func restartPins(dir int, uid, gid uint32, manifest bootstrap.Manifest, roots trust.Keyring, privateIP string,
) (MaterialPins, error) {
	digests := expectedMaterials(manifest, manifest.Slot)
	wire, err := readUnpinned(dir, MaterialGenerationsFile, uid, gid,
		bootstrap.MaxMaterialGenerations*(bootstrap.MaxMaterialGenerationBytes+16<<10))
	if errors.Is(err, os.ErrNotExist) {
		return ManifestPins(digests), nil
	}
	if err != nil {
		return MaterialPins{}, fmt.Errorf("read adopted material generations: %w", err)
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return MaterialPins{}, err
	}
	verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(chain, roots, bootstrap.MaterialGenerationExpectation{
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
		Cell: manifest.Cell, ControllerSlots: manifest.ControllerSlots})
	if err != nil {
		return MaterialPins{}, fmt.Errorf("verify adopted material generations: %w", err)
	}
	newest := verified[len(verified)-1]
	pins := MaterialPins{Digests: map[string]string{}, Issued: map[string]string{}, Generation: &newest,
		slot: manifest.Slot, identity: bootstrapmaterial.ControllerLeafIdentity(strings.ToLower(string(manifest.Cell)), manifest.Slot, privateIP)}
	for name, want := range digests {
		pins.Digests[name] = want
	}
	generation := newest.Generation()
	for _, name := range bootstrapmaterial.IssuedFiles(manifest.Slot) {
		if digests[name] == "" {
			return MaterialPins{}, fmt.Errorf("%w: issued file %s is not part of this install", ErrMaterial, name)
		}
		if generation.AccountSigner != "" {
			pins.Issued[name] = digests[name]
			delete(pins.Digests, name)
		}
	}
	for _, secret := range generation.Secrets {
		if secret.Slot == "" || secret.Slot == manifest.Slot {
			pins.Digests[secret.TargetFile] = secret.SHA256
		}
	}
	pins.Digests[MaterialGenerationsFile] = digest(wire)
	return pins, nil
}

// controllerConfigSHA256 is the controller config digest a restart of the
// manifest's slot expects (TS-668): the newest adopted generation's config
// for the slot when it pins one, which must be bound to manifestSHA256, the
// accepted manifest; otherwise the manifest's own.
func (pins MaterialPins) controllerConfigSHA256(manifest bootstrap.Manifest, manifestSHA256 string) (string, error) {
	if pins.Generation != nil {
		for _, config := range pins.Generation.Generation().ControllerConfigs {
			if config.Slot != manifest.Slot {
				continue
			}
			if config.ManifestSHA256 != manifestSHA256 {
				return "", fmt.Errorf("%w: the adopted generation's controller config for %s is bound to another manifest",
					ErrMaterial, config.Slot)
			}
			return config.SHA256, nil
		}
	}
	return manifest.ControllerConfigSHA256, nil
}

// verifyGeneration checks the newest generation's pinned files again at now,
// with the rules they were signed under (CA bundle, issuers, JWTs, system
// credentials, interregion files and the loaded controller config, all
// current), then the slot's issued files.
func (pins MaterialPins) verifyGeneration(dir int, uid, gid uint32, now time.Time) error {
	if pins.Generation == nil {
		return nil
	}
	// The generation is the authority for its material: past its signed
	// expiry the owner must sign the next one, as continuity requires.
	if !now.Before(pins.Generation.ExpiresAt()) {
		return fmt.Errorf("%w: the adopted material generation expired at %s", ErrMaterial,
			pins.Generation.ExpiresAt().Format(time.RFC3339))
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(pins.Generation.Generation(), func(name string) ([]byte, error) {
		if name == "controller-"+pins.slot+".json" {
			return pins.config, nil
		}
		if pins.Digests[name] == "" {
			// Another slot's leaf TLS or config: never held here.
			return nil, fs.ErrNotExist
		}
		return readMaterial(dir, name, uid, gid, pins.Digests[name], bootstrap.MaxSecretBytes)
	}, now); err != nil {
		return fmt.Errorf("%w: adopted material generation: %w", ErrMaterial, err)
	}
	return pins.verifyIssued(dir, uid, gid, now)
}

// verifyIssued checks the slot's issued files against the newest generation,
// whose pinned issuer and bundle are read from the same directory. Without
// controller issuers they are pinned by digest instead.
func (pins MaterialPins) verifyIssued(dir int, uid, gid uint32, now time.Time) error {
	if pins.Generation == nil || len(pins.Issued) == 0 {
		return nil
	}
	files := map[string][]byte{}
	defer func() {
		for _, content := range files {
			clear(content)
		}
	}()
	for name := range pins.Issued {
		content, err := readUnpinned(dir, name, uid, gid, bootstrap.MaxSecretBytes)
		if err != nil {
			return fmt.Errorf("read issued %s: %w", name, err)
		}
		files[name] = content
	}
	for _, name := range []string{"controller-tls-issuer-cert.pem", "ca.pem"} {
		content, err := readMaterial(dir, name, uid, gid, pins.Digests[name], bootstrap.MaxSecretBytes)
		if err != nil {
			return fmt.Errorf("read generation %s: %w", name, err)
		}
		files[name] = content
	}
	generation := pins.Generation.Generation()
	names := bootstrapmaterial.IssuedFiles(pins.slot)
	certName, keyName, credsName := names[0], names[1], names[2]
	original := func(name string) bool { return digest(files[name]) == pins.Issued[name] }
	if !original(certName) || !original(keyName) {
		if err := bootstrapmaterial.CheckIssuedTLS(generation, files["controller-tls-issuer-cert.pem"], files["ca.pem"],
			files[certName], files[keyName], pins.identity, now); err != nil {
			return fmt.Errorf("%w: %w", ErrMaterial, err)
		}
	}
	if !original(credsName) {
		if err := bootstrapmaterial.CheckIssuedCredentials(generation, files[credsName], now); err != nil {
			return fmt.Errorf("%w: %w", ErrMaterial, err)
		}
	}
	return nil
}

// readUnpinned reads a service-owned credential file whose digest is not
// pinned, with readMaterial's ownership, mode, link and size checks.
func readUnpinned(dir int, name string, uid, gid uint32, maximum int64) ([]byte, error) {
	if !markerNameRE.MatchString(name) || maximum <= 0 {
		return nil, ErrMaterial
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 ||
		stat.Size <= 0 || stat.Size > maximum {
		return nil, ErrMaterial
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum {
		clear(content)
		return nil, ErrMaterial
	}
	return content, nil
}
