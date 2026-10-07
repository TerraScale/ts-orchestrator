package cli

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// signMaterialGenerationAt signs the next material generation of a cell
// under the offline root after checking every file it pins, and writes the
// chain with it appended. Only the new generation's signature is checked
// against --root-key: earlier ones are covered by its hash links, so the
// chain can be extended after the roots that signed them were rotated.
func (c command) signMaterialGenerationAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-material-generation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed unsigned material generation JSON")
	materialDir := flags.String("material", "", "directory holding every pinned file under its target name, "+
		"and each pinned controller config as controller-<slot>.json")
	chainPath := flags.String("chain", "", "the cell's signed generation chain; required after generation 1")
	rootPublicPath := flags.String("root-key", "", "offline root Ed25519 public key PEM")
	rootPrivatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new signed generation chain")
	validFor := flags.Duration("valid-for", 365*24*time.Hour, "generation validity, bounded by the first expiry it pins")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *materialDir == "" || *rootPublicPath == "" || *rootPrivatePath == "" ||
		*outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-material-generation requires --candidate, --material, --root-key, --signing-key and --out")
	}
	if *validFor <= 0 || *validFor > bootstrap.MaxMaterialGenerationLifetime {
		return fmt.Errorf("generation validity must be positive and no longer than %s", bootstrap.MaxMaterialGenerationLifetime)
	}
	now = now.Round(0).UTC()
	candidateWire, err := c.readBoundedRegular(*candidatePath, bootstrap.MaxMaterialGenerationBytes)
	if err != nil {
		return err
	}
	var generation bootstrap.MaterialGeneration
	if err := protocol.DecodeStrict(candidateWire, &generation, bootstrap.MaxMaterialGenerationBytes); err != nil {
		return fmt.Errorf("decode candidate generation: %w", err)
	}
	// The owner checks every file, so a missing slot file or controller
	// config is an error here, never skipped.
	firstExpiry, err := bootstrapmaterial.CheckGenerationFiles(generation, func(name string) ([]byte, error) {
		data, err := c.readBoundedRegular(filepath.Join(*materialDir, name), bootstrap.MaxSecretBytes)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s is missing from the material directory", name)
		}
		return data, err
	}, now)
	if err != nil {
		return err
	}
	rootPublic, err := readRootPublicKey(*rootPublicPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		return fmt.Errorf("parse root trust key: %w", err)
	}
	rootPrivate, err := readRootPrivateKey(*rootPrivatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match the supplied root public key")
	}
	expected := bootstrap.MaterialGenerationExpectation{DeploymentID: generation.DeploymentID,
		Environment: generation.Environment, ClusterID: generation.ClusterID, Cell: generation.Cell,
		ControllerSlots: generation.ControllerSlots}
	var chain []trust.Envelope
	if *chainPath != "" {
		wire, err := c.readBoundedRegular(*chainPath, bootstrap.MaxMaterialGenerations*(bootstrap.MaxMaterialGenerationBytes+16<<10))
		if err != nil {
			return err
		}
		if chain, err = bootstrap.DecodeMaterialGenerationChain(wire); err != nil {
			return err
		}
	}
	if uint64(len(chain))+1 != generation.Generation {
		return fmt.Errorf("generation %d needs a chain of exactly %d earlier generations", generation.Generation, generation.Generation-1)
	}
	expiresAt := minTime(now.Add(*validFor), firstExpiry)
	if expiresAt.Sub(now) < bootstrap.MinimumManifestWindow {
		return fmt.Errorf("the pinned material leaves less than %s of generation validity", bootstrap.MinimumManifestWindow)
	}
	signed, err := bootstrap.SignMaterialGeneration(generation, now, expiresAt, rootPrivate)
	if err != nil {
		return fmt.Errorf("sign material generation: %w", err)
	}
	chain = append(chain, signed)
	verified, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, expected, now)
	if err != nil {
		return fmt.Errorf("verify the new generation chain: %w", err)
	}
	encoded, err := bootstrap.EncodeMaterialGenerationChain(chain)
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	newest := verified[len(verified)-1]
	fmt.Fprintf(c.output, "signed material generation %d cell=%s fingerprint=%s expires=%s\n",
		generation.Generation, generation.Cell, newest.Fingerprint(), expiresAt.Format(time.RFC3339))
	return nil
}
