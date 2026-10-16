package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// runRoleClaim signs the cell account claim with the role signer added
// (TS-651), for operator broker-claim-apply.
func (c command) runRoleClaim(args []string) error {
	flags := flag.NewFlagSet("role-claim", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	materialDirectory := flags.String("material-directory", "", "this region's controller material directory")
	currentPath := flags.String("cell-jwt", "", "the cell account JWT the brokers hold now (the material's cell.jwt until a claim is applied)")
	outputPath := flags.String("out", "", "new file for the signed cell account JWT")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *materialDirectory == "" || *currentPath == "" || *outputPath == "" || flags.NArg() != 0 ||
		!filepath.IsAbs(*materialDirectory) || !filepath.IsAbs(*outputPath) || pathInside(*materialDirectory, *outputPath) {
		return errors.New("role-claim requires --material-directory, --cell-jwt and --out outside the material directory")
	}
	current, err := c.readBoundedRegular(*currentPath, 64<<10)
	if err != nil {
		return err
	}
	raw, signer, err := bootstrapmaterial.RoleClaim(*materialDirectory, strings.TrimSpace(string(current)))
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, []byte(raw), 0o644); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(raw))
	fmt.Fprintf(c.output, "role claim ready file=%s role-signer=%s sha256=%s\n", *outputPath, signer, hex.EncodeToString(digest[:]))
	return nil
}
