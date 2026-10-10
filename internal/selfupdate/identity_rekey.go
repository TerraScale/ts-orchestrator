package selfupdate

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// InstallIdentityRekeyBaseline publishes an explicitly root-authorized baseline,
// rather than confirming an ordinary activation. Check must reverify the durable
// root plan, candidate contract and stopped service before each publication.
func InstallIdentityRekeyBaseline(layout Layout, candidate string, receipt, delegation []byte, verifier Verifier, now time.Time, check func(string) error) error {
	if check == nil || verifier == nil {
		return ErrInvalid
	}
	if _, err := verifier.Verify(receipt, delegation, now); err != nil {
		return err
	}
	if err := check(candidate); err != nil {
		return err
	}
	unlock, err := layout.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if _, pending, err := layout.Pending(); err != nil {
		return err
	} else if pending {
		return fmt.Errorf("%w: identity rekey refuses a pending activation", ErrInvalid)
	}
	entries, err := os.ReadDir(layout.Root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), restoreIntentPrefix) {
			return fmt.Errorf("%w: identity rekey refuses a pending restore", ErrInvalid)
		}
	}
	if err := check(candidate); err != nil {
		return err
	}
	source, err := os.Open(candidate)
	if err != nil {
		return err
	}
	defer source.Close()
	digest, err := Stage(layout, source, receipt, delegation, verifier, now)
	if err != nil {
		return err
	}
	for _, name := range []string{knownGoodLink, currentLink} {
		if err := check(layout.BinaryPath(digest)); err != nil {
			return err
		}
		if err := layout.flipLink(name, digest); err != nil {
			return err
		}
	}
	// The stopped controller owes no restart of a superseded deployment.
	if err := check(layout.BinaryPath(digest)); err != nil {
		return err
	}
	if err := layout.ClearRestartPending(ControllerUnit); err != nil {
		return err
	}
	return syncDir(layout.Root)
}
