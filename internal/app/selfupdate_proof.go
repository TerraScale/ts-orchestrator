package app

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
)

const (
	controllerUnit = "terrascale-orchestrator-controller.service"
	hostUnit       = "terrascale-orchestrator-host.service"
)

// emitSelfUpdateProof confirms a pending self-update activation once the
// process is ready. It never fails the runtime: a missing proof only lets
// the root watchdog roll the activation back at its deadline.
func emitSelfUpdateProof(proofFile, keyFile, unit string, output io.Writer) {
	if proofFile == "" {
		return
	}
	key, err := readPrivateKey(keyFile)
	if err != nil {
		slog.Warn("self-update version proof key unavailable", "error", err)
		return
	}
	emitSelfUpdateProofWithKey(proofFile, key, unit, output)
}

func emitSelfUpdateProofWithKey(proofFile string, key ed25519.PrivateKey, unit string, output io.Writer) {
	if proofFile == "" {
		return
	}
	emitted, err := selfupdate.EmitProof(selfupdate.NewLayout(selfupdate.DefaultRoot), unit, proofFile, key, time.Now())
	if err != nil {
		slog.Warn("self-update version proof failed", "error", err)
		return
	}
	if emitted {
		fmt.Fprintf(output, "self-update version proof written to %s\n", proofFile)
	}
}
