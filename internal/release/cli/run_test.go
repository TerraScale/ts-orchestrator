package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifiedBinaryWritesToCommandOutput(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.verifyBinaryWithInspect([]string{
		"--receipt", fixture.receiptPath, "--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath, "--binary", "retained-binary",
		"--qualification", fixture.qualificationPath, "--environment", "canary",
	}, func(string, string, string) (binaryReceipt, error) { return testBinaryReceipt(), nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "verified binary revision="+testRevision) {
		t.Fatalf("verification output was not routed to the command writer: %q", output.String())
	}
}

func TestGuestExtractionUsesCommandCancellation(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "virt-cat"), []byte("#!/bin/sh\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := command{ctx: ctx}
	file, err := c.extractGuestBinary("image.qcow2", "/usr/local/bin/terrascale-orchestrator", 10)
	if file != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("extraction = %v, error = %v, want command cancellation", file, err)
	}
}
