package app

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

const (
	controllerUnit = selfupdate.ControllerUnit
	hostUnit       = selfupdate.HostUnit
)

// emitSelfUpdateProof confirms a pending self-update activation once the
// process is ready. It never fails the runtime: a missing proof only lets
// the root watchdog roll the activation back at its deadline.
func emitSelfUpdateProof(proofFile, root, keyFile, unit string, output io.Writer) {
	key, err := readPrivateKey(keyFile)
	if err != nil {
		slog.Warn("self-update version proof key unavailable", "error", err)
		return
	}
	emitSelfUpdateProofWithKey(proofFile, root, key, unit, output)
}

// selfUpdateRoot returns the configured release root, which must be the
// --root the unit's prepare and watchdog steps use.
func selfUpdateRoot(root string) string {
	if root == "" {
		return selfupdate.DefaultRoot
	}
	return root
}

// selfUpdateProofFile returns the configured proof file or, when it is
// unset, the default file the image's watchdog reads, so self-update needs
// no config field.
func selfUpdateProofFile(proofFile, root, unit string) string {
	if proofFile == "" {
		return selfupdate.DefaultProofFile(selfUpdateRoot(root), unit)
	}
	return proofFile
}

func emitSelfUpdateProofWithKey(proofFile, root string, key ed25519.PrivateKey, unit string, output io.Writer) {
	proofFile = selfUpdateProofFile(proofFile, root, unit)
	emitted, err := selfupdate.EmitProof(selfupdate.NewLayout(selfUpdateRoot(root)), unit, proofFile, key, time.Now())
	if err != nil {
		slog.Warn("self-update version proof failed", "error", err)
		return
	}
	if emitted {
		fmt.Fprintf(output, "self-update version proof written to %s\n", proofFile)
	}
}
