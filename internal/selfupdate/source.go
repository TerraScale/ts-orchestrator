package selfupdate

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/nats-io/nats.go/jetstream"
)

// ArtifactStore is the subset of the signed delivery artifact store that a
// controller uses to fetch a binary by digest.
type ArtifactStore interface {
	GetInfo(context.Context, string, ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error)
}

// StageFromArtifactStore fetches the binary named by the verified receipt
// from the content-addressed delivery store over NATS, checking every chunk
// and the object digest, then stages it. The receipt is verified before any
// byte is fetched, and again by Stage against the downloaded bytes.
func StageFromArtifactStore(ctx context.Context, layout Layout, js jetstream.JetStream, store ArtifactStore,
	receiptWire, delegationWire []byte, verifier Verifier, now time.Time,
) (string, error) {
	if js == nil || store == nil || verifier == nil {
		return "", fmt.Errorf("%w: artifact store and verifier are required", ErrInvalid)
	}
	verified, err := verifier.Verify(receiptWire, delegationWire, now)
	if err != nil {
		return "", fmt.Errorf("verify release receipt: %w", err)
	}
	receipt := verified.Receipt()
	if err := layout.ensureDirs(); err != nil {
		return "", err
	}
	spool, err := os.CreateTemp(layout.releasesPath(), ".download-")
	if err != nil {
		return "", err
	}
	defer os.Remove(spool.Name())
	defer spool.Close()
	if err := artifact.ReadVerified(ctx, js, store, delivery.ArtifactBucket, "sha256-"+receipt.SHA256,
		receipt.SHA256, receipt.Bytes, MaxBinaryBytes, spool); err != nil {
		return "", fmt.Errorf("fetch release binary: %w", err)
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return Stage(layout, spool, receiptWire, delegationWire, verifier, now)
}
