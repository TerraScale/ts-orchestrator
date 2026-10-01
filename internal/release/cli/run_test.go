package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
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

type rejectedOutput struct{}

func (rejectedOutput) Write([]byte) (int, error) { return 0, os.ErrClosed }

type shortOutput struct{}

func (shortOutput) Write(contents []byte) (int, error) { return len(contents) - 1, nil }

func TestRunReportsOutputFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		output io.Writer
		want   error
	}{
		{name: "rejected", output: rejectedOutput{}, want: os.ErrClosed},
		{name: "short", output: shortOutput{}, want: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := Run(t.Context(), []string{"--help"}, test.output); !errors.Is(err, test.want) {
				t.Fatalf("Run() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifiedBinaryReportsOutputFailure(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	c := command{ctx: t.Context(), output: rejectedOutput{}}
	err := c.verifyBinaryWithInspect([]string{
		"--receipt", fixture.receiptPath, "--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath, "--binary", "retained-binary",
		"--qualification", fixture.qualificationPath, "--environment", "canary",
	}, func(string, string, string) (binaryReceipt, error) { return testBinaryReceipt(), nil })
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("verification error = %v, want output failure", err)
	}
}

func TestBinaryVerificationCancellationDoesNotEmitSuccess(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output bytes.Buffer
	c := command{ctx: ctx, output: &output}
	err := c.verifyBinaryWithInspect([]string{
		"--receipt", fixture.receiptPath, "--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath, "--binary", "retained-binary",
		"--qualification", fixture.qualificationPath, "--environment", "canary",
	}, func(string, string, string) (binaryReceipt, error) {
		cancel()
		return testBinaryReceipt(), nil
	})
	if !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("canceled verification error = %v, output = %q", err, output.String())
	}
}

func TestBinarySigningCancellationDoesNotWriteReceipt(t *testing.T) {
	for _, stage := range []string{"inspection", "admission"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newSignedBinaryFixture(t, time.Hour)
			directory := filepath.Dir(fixture.rootPath)
			candidate := filepath.Join(directory, "candidate.json")
			writeFixtureFile(t, candidate, mustEncodeBinaryReceipt(t, testBinaryReceipt()), 0o600)
			signed := filepath.Join(directory, "signed.json")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c := command{ctx: ctx, output: io.Discard}
			checked := false
			err := c.signBinaryWithCheck([]string{
				"--candidate", candidate, "--binary", "retained-binary",
				"--qualification", fixture.qualificationPath, "--delegation", fixture.delegationPath,
				"--root-key", fixture.rootPath, "--signing-key", fixture.privatePath,
				"--environment", "canary", "--out", signed,
			}, func(release.Qualification, string) error {
				checked = true
				cancel()
				return nil
			}, func(string, string, string) (binaryReceipt, error) {
				if stage == "inspection" {
					cancel()
				}
				return testBinaryReceipt(), nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("signing error = %v, want cancellation", err)
			}
			if checked != (stage == "admission") {
				t.Fatalf("admission called = %t after cancellation during %s", checked, stage)
			}
			if _, err := os.Stat(signed); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("canceled signing produced a receipt: %v", err)
			}
		})
	}
}

type cancelArtifactReader struct {
	cancel context.CancelFunc
	reads  int
}

func (reader *cancelArtifactReader) Read(contents []byte) (int, error) {
	reader.reads++
	reader.cancel()
	return copy(contents, "artifact chunk"), nil
}

func TestArtifactHashStopsWhenReadCancelsCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader := &cancelArtifactReader{cancel: cancel}
	c := command{ctx: ctx}
	digest, _, err := c.hashArtifact(reader)
	if !errors.Is(err, context.Canceled) || digest != nil || reader.reads != 1 {
		t.Fatalf("hash = %x, error = %v, reads = %d; want cancellation before another read", digest, err, reader.reads)
	}
}

func TestCanceledCommandDoesNotCreateOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	path := filepath.Join(t.TempDir(), "receipt.json")
	c := command{ctx: ctx}
	if err := c.writeNew(path, []byte("receipt"), 0o644); !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v, want cancellation", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled write produced output: %v", err)
	}
}

func TestCanceledPublicationDoesNotUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	asset := []byte("release asset")
	digest := sha256.Sum256(asset)
	client := &fakeObjectClient{}
	err := putImmutable(ctx, client, "namespace", "bucket", "receipt", bytes.NewReader(asset), int64(len(asset)), digest[:])
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("publish error = %v, want cancellation", err)
	}
	if client.lastPut.ObjectName != nil || client.stored != nil {
		t.Fatal("canceled publication attempted an upload")
	}
}
