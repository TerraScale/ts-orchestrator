package imagetrust

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
)

const verifyProvenanceUsage = "usage: ts-orch release verify-provenance --image <repo@sha256:...> --workflow <owner/repo/.github/workflows/x.yml@refs/heads/main> --revision <40 hex>"

func VerifyImage(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release verify-provenance", flag.ContinueOnError)
	flags.SetOutput(output)
	image := flags.String("image", "", "digest reference of the released image")
	workflow := flags.String("workflow", "", "signer workflow: <owner/repo/.github/workflows/x.yml@refs/heads/main>")
	revision := flags.String("revision", "", "source commit the workflow signed for")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *image == "" || *workflow == "" || *revision == "" || flags.NArg() != 0 {
		return errors.New(verifyProvenanceUsage)
	}
	if err := Verify(ctx, *image, *workflow, *revision, authn.DefaultKeychain); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "ok")
	return err
}
