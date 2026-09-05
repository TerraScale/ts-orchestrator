package controlcandidatecli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func candidateCommandConfig() transitiongrant.Config {
	return transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "transition-1", NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem"}
}

type candidateCancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *candidateCancelWriter) Write(raw []byte) (int, error) {
	n, err := w.Buffer.Write(raw)
	w.cancel()
	return n, err
}

func TestCandidateProcessPublishesOnlyAdmissionAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	output := &candidateCancelWriter{cancel: cancel}
	receipt := nodeauthority.CandidatePreparationReceipt{Phase: "admitted", TransitionID: "transition-1", NodeID: "sfo-1", ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := waitControlCandidate(ctx, candidateCommandConfig(), output, func(context.Context, transitiongrant.Config) (nodeauthority.CandidatePreparationReceipt, error) {
		return receipt, nil
	}); err != nil {
		t.Fatal(err)
	}
	var actual nodeauthority.CandidatePreparationReceipt
	if err := json.Unmarshal(output.Bytes(), &actual); err != nil || actual.Phase != "admitted" || actual.TransitionID != receipt.TransitionID {
		t.Fatalf("admission receipt: %+v %v", actual, err)
	}
}

func TestCandidateProcessRejectsAdmissionLossAndExpiry(t *testing.T) {
	for _, mode := range []string{"missing", "expired", "changed", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			receipt := nodeauthority.CandidatePreparationReceipt{Phase: "admitted", TransitionID: "transition-1", NodeID: "sfo-1", ExpiresAt: time.Now().UTC().Add(time.Minute)}
			if mode == "expired" {
				receipt.ExpiresAt = time.Now().Add(-time.Second)
			}
			calls := 0
			var output bytes.Buffer
			err := waitControlCandidate(ctx, candidateCommandConfig(), &output, func(context.Context, transitiongrant.Config) (nodeauthority.CandidatePreparationReceipt, error) {
				calls++
				if mode == "missing" || mode == "revoked" && calls > 1 {
					return nodeauthority.CandidatePreparationReceipt{}, errors.New("admission unavailable")
				}
				current := receipt
				if mode == "changed" && calls > 1 {
					current.GrantSHA256 = "different-grant"
				}
				return current, nil
			})
			if err == nil || ctx.Err() != nil {
				t.Fatalf("candidate did not reject %s admission before deadline: %v", mode, err)
			}
			if (mode == "missing" || mode == "expired") && output.Len() != 0 {
				t.Fatal("invalid admission emitted a receipt")
			}
		})
	}
}
