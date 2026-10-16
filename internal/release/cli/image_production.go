package cli

import (
	"errors"
	"flag"
	"io"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// verifyImageProduction authorizes the final disk before OCI import or signing.
func (c command) verifyImageProduction(args []string) error {
	flags := flag.NewFlagSet("verify-image-production", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	imageFile := flags.String("image-file", "", "exact final QCOW2 image")
	qualificationPath := flags.String("qualification", "", "retained binary CI qualification manifest")
	rootPath := flags.String("root-key", "", "existing trusted root public key PEM")
	evidenceDir := flags.String("production-evidence-dir", "", "retained signed final image evidence; default qualification sibling image-production")
	cell := flags.String("cell", "", "target region")
	architecture := flags.String("arch", "", "image architecture")
	environment := flags.String("environment", "production", "target admitted environment")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *imageFile == "" || *qualificationPath == "" || *rootPath == "" || !validRegion(*cell) ||
		(*architecture != "amd64" && *architecture != "arm64") || !validEnvironment(*environment) || flags.NArg() != 0 {
		return errors.New("verify-image-production requires --image-file, --qualification, --root-key, --cell, and --arch")
	}
	qualification, digest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	imageDigest, _, err := c.hashQcow2(*imageFile)
	if err != nil {
		return err
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	if *evidenceDir == "" {
		*evidenceDir = filepath.Join(filepath.Dir(*qualificationPath), "image-production")
	}
	expected := release.ProductionExpectation{SourceRevision: qualification.SourceRevision, ArtifactSHA256: imageDigest,
		QualificationSHA256: digest, Cell: *cell, Environment: *environment,
		Runtime: release.ProductionRuntime, Architecture: *architecture, Role: "orchestrator"}
	return c.verifyProductionCandidate(*evidenceDir, roots, expected, time.Now().UTC())
}
