package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

type containerSource = delivery.ArtifactSource

func validateContainerSource(source containerSource) error {
	parsed, err := url.Parse(source.Repository)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(source.Repository) > 512 || !release.ValidSourceRevision(source.Commit) || !digestPatternCLI(source.TreeDigest) {
		return fmt.Errorf("invalid container source identity")
	}
	return nil
}

func digestPatternCLI(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func containerEvidenceReader(directory string) func(context.Context, string) (io.ReadCloser, error) {
	return func(ctx context.Context, digest string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !digestPatternCLI(digest) {
			return nil, fmt.Errorf("invalid retained evidence digest")
		}
		return os.Open(filepath.Join(directory, "objects", digest))
	}
}
