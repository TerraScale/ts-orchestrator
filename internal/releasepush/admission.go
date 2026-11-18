package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
)

func admissionFile(state, digest string) string {
	return filepath.Join(state, "nats", "release-admissions", digest+".json")
}

func ReadAdmission(state, binary string) (*releasegate.Receipt, error) {
	installed, err := binaryIdentity(binary)
	if err != nil {
		return nil, err
	}
	var receipt releasegate.Receipt
	present, err := readRecord(admissionFile(state, installed.SHA256), &receipt)
	if err != nil || !present {
		return nil, err
	}
	if receipt.Binaries[runtime.GOARCH] != installed.SHA256 {
		return nil, errors.New("release admission differs from the installed binary")
	}
	return &receipt, nil
}

func AdmissionDetail(state, binary string) (bool, string) {
	receipt, err := ReadAdmission(state, binary)
	if err != nil {
		return false, "release admission record unreadable"
	}
	if receipt == nil {
		return true, "no retained release admission"
	}
	return true, receipt.Message()
}

func (h *Handler) admit(ctx context.Context, region string, release releaseattest.Release, binary Binary) error {
	verifier := h.Admission
	verifier.Client, verifier.Attest = h.Client, h.Attest
	receipt, err := verifier.Check(ctx, region, release, releasegate.Receiver)
	if err != nil {
		return err
	}
	path := admissionFile(filepath.Dir(filepath.Dir(h.TrialFile)), binary.SHA256)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create release admission directory: %w", err)
	}
	if err := writeJSON(path, receipt); err != nil {
		return fmt.Errorf("persist release admission: %w", err)
	}
	if receipt.RunID != "" {
		slog.WarnContext(ctx, receipt.Message(), "region", region, "release", release.Tag(), "sha256", binary.SHA256)
	}
	return nil
}

func (h *Handler) CompleteBootAdmission(ctx context.Context, region, launch string) error {
	path := filepath.Join(filepath.Dir(h.TrialFile), "release-boot-admission.json")
	var pending releasegate.Receipt
	present, err := readRecord(path, &pending)
	if err != nil {
		return err
	}
	if !present {
		if launch == "" {
			return nil
		}
		if err := json.Unmarshal([]byte(launch), &pending); err != nil {
			return fmt.Errorf("decode launch admission: %w", err)
		}
	}
	prefix := "ci-" + h.Revision + "-run-"
	run, matches := strings.CutPrefix(pending.Tag, prefix)
	if !matches || run == "" || pending.Region != region || pending.Binaries[runtime.GOARCH] != h.Digest {
		return errors.New("boot admission differs from this region or binary")
	}
	release := releaseattest.Release{SHA: h.Revision, RunID: run, Binaries: map[string]releaseattest.Artifact{}}
	for arch, digest := range pending.Binaries {
		release.Binaries[arch] = releaseattest.Artifact{SHA256: digest}
	}
	if err := h.admit(ctx, region, release, Binary{SHA256: h.Digest}); err != nil {
		return err
	}
	if present {
		return removeDurable(path)
	}
	return nil
}
