package controlcandidatecli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type syncDependencies struct {
	read   func(string) ([]byte, error)
	verify func(context.Context, transitiongrant.Config, []byte) (preliminarytransfer.VerifiedCandidate, nodeauthority.CandidatePreparationReceipt, error)
	within func(context.Context, transitiongrant.Config, func(context.Context) error) error
	run    func(context.Context, transitiongrant.Config, preliminarytransfer.VerifiedCandidate) ([]byte, error)
}

// Only fixed states and public digests are emitted. Worker errors may include
// transport details and protected paths and must never enter CLI status.
type syncStatus struct {
	Phase         string `json:"phase"`
	State         string `json:"state"`
	ScopeSHA256   string `json:"scopeSha256,omitempty"`
	RequestSHA256 string `json:"requestSha256,omitempty"`
	ReceiptSHA256 string `json:"receiptSha256,omitempty"`
}

type syncResult struct {
	receipt []byte
	err     error
}

func watchCandidate(ctx context.Context, config transitiongrant.Config, output io.Writer, receipt nodeauthority.CandidatePreparationReceipt, validate func(context.Context, transitiongrant.Config) (nodeauthority.CandidatePreparationReceipt, error), deps syncDependencies, poll <-chan time.Time) error {
	expiry := time.NewTimer(time.Until(receipt.ExpiresAt))
	defer expiry.Stop()
	var cancel context.CancelFunc
	var done chan syncResult
	stop := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel, done = nil, nil
		}
	}
	defer stop()
	var pinnedScope, requestDigest, completedDigest, completedReceiptDigest string
	var attempts int
	var retryAt time.Time
	var last syncStatus
	report := func(state, receiptDigest string) error {
		status := syncStatus{"preliminary-sync", state, pinnedScope, requestDigest, receiptDigest}
		if status == last {
			return nil
		}
		if err := json.NewEncoder(output).Encode(status); err != nil {
			return errors.New("candidate preliminary sync status could not be written")
		}
		last = status
		return nil
	}
	inspect := func() error {
		if config.Sync == nil {
			return nil
		}
		raw, err := deps.read(config.Sync.RequestFile)
		if err != nil {
			stop()
			if os.IsNotExist(err) {
				return report("idle", "")
			}
			return report("request-refused", "")
		}
		verified, current, err := deps.verify(ctx, config, raw)
		if err != nil || current != receipt || !verified.Authorization.ExpiresAt.After(time.Now()) {
			stop()
			return report("request-refused", "")
		}
		if pinnedScope != "" && pinnedScope != verified.Scope.Digest {
			stop()
			return report("scope-conflict", "")
		}
		pinnedScope = verified.Scope.Digest
		if requestDigest != verified.Digest {
			stop()
			requestDigest, attempts, retryAt = verified.Digest, 0, time.Time{}
		}
		if completedDigest == requestDigest {
			return report("complete", completedReceiptDigest)
		}
		if done != nil || attempts >= 3 || time.Now().Before(retryAt) {
			return nil
		}
		attempts++
		operation, release := context.WithTimeout(ctx, 10*time.Minute)
		operation, deadlineCancel := context.WithDeadline(operation, verified.Authorization.ExpiresAt)
		cancel = func() { deadlineCancel(); release() }
		done = make(chan syncResult, 1)
		resultChannel := done
		go func() {
			var signed []byte
			err := deps.within(operation, config, func(locked context.Context) error {
				fresh, readErr := deps.read(config.Sync.RequestFile)
				if readErr != nil {
					return errors.New("candidate preliminary request unavailable")
				}
				checked, proof, verifyErr := deps.verify(locked, config, fresh)
				if verifyErr != nil || proof != receipt || checked.Digest != verified.Digest || checked.Scope.Digest != verified.Scope.Digest {
					return errors.New("candidate preliminary request changed")
				}
				var runErr error
				signed, runErr = deps.run(locked, config, verified)
				return runErr
			})
			resultChannel <- syncResult{signed, err}
		}()
		return report("syncing", "")
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	if err := inspect(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-expiry.C:
			return errors.New("candidate preparation admission has expired")
		case result := <-done:
			cancel()
			cancel, done = nil, nil
			if result.err != nil {
				retryAt = time.Now().Add(time.Duration(attempts) * time.Second)
				if err := report("failed", ""); err != nil {
					return err
				}
				continue
			}
			// A worker returning success does not replace a fresh root proof check.
			current, err := validate(ctx, config)
			if err != nil || current != receipt {
				return errors.New("candidate preparation admission changed")
			}
			fresh, readErr := deps.read(config.Sync.RequestFile)
			checked, proof, verifyErr := deps.verify(ctx, config, fresh)
			if readErr != nil || verifyErr != nil || proof != receipt || checked.Digest != requestDigest || checked.Scope.Digest != pinnedScope {
				if err := report("request-refused", ""); err != nil {
					return err
				}
				continue
			}
			completedDigest, completedReceiptDigest = requestDigest, preliminarytransfer.Digest(result.receipt)
			if err := report("complete", completedReceiptDigest); err != nil {
				return err
			}
		case <-poll:
			current, err := validate(ctx, config)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			if current != receipt {
				return errors.New("candidate preparation admission changed")
			}
			if err := inspect(); err != nil {
				return err
			}
		}
	}
}
