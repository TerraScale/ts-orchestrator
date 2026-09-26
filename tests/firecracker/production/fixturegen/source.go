package fixturegen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// These files define the public signing, ledger, admission, simulator, and
// packet boundaries consumed by a production restart fixture. Additional
// source pins are allowed, but none of this baseline may be omitted.
var requiredSourcePaths = []string{
	"deploy/image/build-offline.sh",
	"deploy/systemd/terrascale-orchestrator-bootstrap.service",
	"deploy/systemd/terrascale-orchestrator-controller.service",
	"deploy/systemd/terrascale-orchestrator-host.service",
	"internal/app/bootstrap_controller.go",
	"internal/app/config.go",
	"internal/bootstrap/anchor.go",
	"internal/bootstrap/founder_plan.go",
	"internal/bootstrap/ledger.go",
	"internal/bootstrap/ledger_head.go",
	"internal/bootstrap/ledger_oci.go",
	"internal/bootstrap/ledger_records.go",
	"internal/bootstrap/managed_recovery.go",
	"internal/bootstrap/manifest.go",
	"internal/bootstrap/receipt.go",
	"internal/bootstrapstart/admission.go",
	"internal/bootstrapstart/baked.go",
	"internal/bootstrapstart/binary.go",
	"internal/bootstrapstart/founder_oci.go",
	"internal/bootstrapstart/founder_provision.go",
	"internal/bootstrapstart/founder_runtime.go",
	"internal/bootstrapstart/founder_selection.go",
	"internal/bootstrapstart/ledger.go",
	"internal/bootstrapstart/marker.go",
	"internal/release/receipt.go",
	"internal/trust/envelope.go",
	"tests/firecracker/production/simulator.go",
	"tests/firecracker/production/fixturegen/capture.go",
	"tests/firecracker/production/fixturegen/cmd/main.go",
	"tests/firecracker/production/fixturegen/emit.go",
	"tests/firecracker/production/fixturegen/histories.go",
	"tests/firecracker/production/fixturegen/packet.go",
	"tests/firecracker/production/fixturegen/routes.go",
	"tests/firecracker/production/fixturegen/source.go",
}

func RequiredSourcePaths() []string {
	paths := slices.Clone(requiredSourcePaths)
	slices.Sort(paths)
	return paths
}

// VerifySourcePins binds a packet recipe to the exact local source files used
// by its signing, ledger, admission, and simulator APIs before emission.
func VerifySourcePins(sourceRoot string, pins []SourcePin) error {
	if len(pins) < len(requiredSourcePaths) || len(pins) > 128 {
		return errors.New("source pin inventory is absent or oversized")
	}
	for _, required := range requiredSourcePaths {
		if !slices.ContainsFunc(pins, func(pin SourcePin) bool { return pin.Path == required }) {
			return fmt.Errorf("source pins omit required code %q", required)
		}
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("source root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return errors.New("source root has a symlink ancestor")
	}
	previous := ""
	for _, pin := range pins {
		if !canonicalPath(pin.Path) || pin.Path <= previous || !validDigest(pin.SHA256) {
			return fmt.Errorf("invalid source pin %q", pin.Path)
		}
		previous = pin.Path
		name := filepath.Join(root, filepath.FromSlash(pin.Path))
		parent := filepath.Dir(name)
		for parent != root {
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("source pin has non-directory or symlink ancestor: %q", pin.Path)
			}
			parent = filepath.Dir(parent)
		}
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("source pin is missing or nonregular: %q", pin.Path)
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if hex.EncodeToString(digest.Sum(nil)) != pin.SHA256 {
			return fmt.Errorf("source pin digest mismatch: %q", pin.Path)
		}
	}
	return nil
}
