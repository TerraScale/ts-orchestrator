package cli

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) verifyProductionArtifacts(evidenceDir string, roots trust.Keyring, cell, environment string, binaries map[string]binaryReceipt, now time.Time) error {
	if len(binaries) == 0 {
		return fmt.Errorf("%w: no candidate artifacts", release.ErrProductionQualification)
	}
	for architecture, binary := range binaries {
		if err := binary.Validate(); err != nil {
			return fmt.Errorf("%w: %w", release.ErrProductionQualification, err)
		}
		if binary.GOARCH != architecture {
			return fmt.Errorf("%w: artifact architecture", release.ErrProductionQualification)
		}
		expected := release.ProductionExpectation{SourceRevision: binary.SourceRevision, ArtifactSHA256: binary.SHA256,
			QualificationSHA256: binary.QualificationSHA256, Cell: cell, Environment: environment,
			Runtime: release.ProductionRuntime, Architecture: architecture, Role: "orchestrator"}
		if err := c.verifyProductionCandidate(evidenceDir, roots, expected, now); err != nil {
			return err
		}
	}
	return c.ctx.Err()
}

// verifyProductionCandidate consumes only signed qualification and retained bytes.
func (c command) verifyProductionCandidate(evidenceDir string, roots trust.Keyring, expected release.ProductionExpectation, now time.Time) error {
	directory := filepath.Join(evidenceDir, expected.Cell, expected.Architecture)
	wire, err := readBoundedRegular(filepath.Join(directory, "production.json"), trust.MaxEnvelopeBytes)
	if err != nil {
		return fmt.Errorf("%w: %s %s record: %w", release.ErrProductionQualification, expected.Cell, expected.Architecture, err)
	}
	delegation, err := readBoundedRegular(filepath.Join(directory, "delegation.json"), trust.MaxEnvelopeBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: qualification delegation: %w", release.ErrProductionQualification, err)
	}
	if _, err := release.VerifyProductionCurrent(wire, delegation, roots, expected, time.Now().UTC()); err != nil {
		return fmt.Errorf("%s %s current admission: %w", expected.Cell, expected.Architecture, err)
	}
	qualification, err := release.VerifyProductionCurrent(wire, delegation, roots, expected, now)
	if err != nil {
		return fmt.Errorf("%s %s: %w", expected.Cell, expected.Architecture, err)
	}
	for _, evidence := range qualification.Evidence {
		file, size, digest, err := c.openHashedArtifact(filepath.Join(evidenceDir, "objects", evidence.SHA256), release.MaxProductionEvidenceBytes)
		if err != nil {
			return fmt.Errorf("%w: %s %s evidence: %w", release.ErrProductionQualification, expected.Cell, evidence.Gate, err)
		}
		if err := file.Close(); err != nil {
			return err
		}
		if size != evidence.Bytes || hex.EncodeToString(digest) != evidence.SHA256 {
			return fmt.Errorf("%w: %s %s retained evidence bytes differ", release.ErrProductionQualification, expected.Cell, evidence.Gate)
		}
	}
	return c.ctx.Err()
}

func (c command) verifyProduction(args []string) error {
	flags := flag.NewFlagSet("verify-production", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "retained candidate binaries and qualification.json")
	evidenceDir := flags.String("evidence-dir", "", "retained signed production evidence; default DIR/production")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM")
	environment := flags.String("environment", "production", "target admitted environment")
	var cells, architectures stringList
	flags.Var(&cells, "cell", "target region; repeatable")
	flags.Var(&architectures, "arch", "target architecture; repeatable; default both Linux architectures")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *rootPath == "" || !validEnvironment(*environment) || flags.NArg() != 0 {
		return errors.New("verify-production requires --dir and --root-key")
	}
	cells, err := deploymentCells(c.ctx, cells, discoverServingCells)
	if err != nil {
		return err
	}
	if len(architectures) == 0 {
		architectures = []string{"amd64", "arm64"}
	}
	if *evidenceDir == "" {
		*evidenceDir = filepath.Join(*directory, "production")
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	qualification, digest, err := readQualification(filepath.Join(*directory, "qualification.json"))
	if err != nil {
		return err
	}
	binaries := make(map[string]binaryReceipt, len(architectures))
	for _, architecture := range architectures {
		if !slices.Contains([]string{"amd64", "arm64"}, architecture) || binaries[architecture].SHA256 != "" {
			return errors.New("unsupported or duplicate architecture")
		}
		binary, err := c.inspectBinary(binaryPath(*directory, architecture), qualification.GoVersion, qualification.SourceRevision)
		if err != nil {
			return err
		}
		binary.QualificationSHA256 = digest
		if err := qualification.MatchBinary(binary, digest); err != nil {
			return err
		}
		binaries[architecture] = binary
	}
	var failures []error
	for _, cell := range cells {
		result := struct {
			Schema         string   `json:"schema"`
			Cell           string   `json:"cell"`
			SourceRevision string   `json:"source_revision"`
			Architectures  []string `json:"architectures"`
			State          string   `json:"state"`
			Error          string   `json:"error,omitempty"`
		}{"terrascale.release.production-admission.v1", cell, qualification.SourceRevision, architectures, "qualified", ""}
		if err := c.verifyProductionArtifacts(*evidenceDir, roots, cell, *environment, binaries, time.Now().UTC()); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", cell, err))
			result.State, result.Error = "refused", err.Error()
		}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(c.output, "%s\n", wire); err != nil {
			return errors.Join(append(failures, err)...)
		}
	}
	return errors.Join(failures...)
}

func readProductionProof(evidenceDir, cell, architecture string) (release.ProductionProof, error) {
	directory := filepath.Join(evidenceDir, cell, architecture)
	wire, err := readBoundedRegular(filepath.Join(directory, "production.json"), trust.MaxEnvelopeBytes)
	if err != nil {
		return release.ProductionProof{}, err
	}
	delegation, err := readBoundedRegular(filepath.Join(directory, "delegation.json"), trust.MaxEnvelopeBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return release.ProductionProof{}, err
	}
	return release.ProductionProof{Qualification: wire, Delegation: delegation}, nil
}
