package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// ConfirmedReleaseHistory protects the latest ten distinct node-confirmed
	// binaries independently of staging age. Fleet promotion is a separate gate.
	ConfirmedReleaseHistory = 10
	confirmedReleasesFile   = "confirmed-releases.json"
	confirmedReleasesSchema = "terrascale.selfupdate.confirmed-releases.v1"
)

type confirmedReleases struct {
	Schema   string   `json:"schema"`
	Releases []string `json:"releases"`
}

// ConfirmedReleases returns the newest-first recorded node confirmations.
// A release rejected since its confirmation is never an eligible target.
// shortcut: older root helpers ignore this index; qualify replacement before fleet retention.
func (layout Layout) ConfirmedReleases() ([]string, error) {
	if err := layout.validate(); err != nil {
		return nil, err
	}
	path := filepath.Join(layout.Root, confirmedReleasesFile)
	if err := layout.checkOwned(path, false); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	data, err := readBounded(path, maxStateBytes)
	if err != nil {
		return nil, err
	}
	var history confirmedReleases
	if err := protocol.DecodeStrict(data, &history, maxStateBytes); err != nil {
		return nil, err
	}
	if history.Schema != confirmedReleasesSchema || len(history.Releases) > ConfirmedReleaseHistory {
		return nil, fmt.Errorf("%w: confirmed release history", ErrInvalid)
	}
	seen := make(map[string]bool, len(history.Releases))
	for _, digest := range history.Releases {
		if !digestRE.MatchString(digest) || seen[digest] {
			return nil, fmt.Errorf("%w: confirmed release history", ErrInvalid)
		}
		seen[digest] = true
	}
	bad, err := layout.KnownBad()
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(history.Releases, func(digest string) bool { return bad[digest] }), nil
}

// rememberConfirmed runs only after Watch verified a live process's proof.
// The caller holds Lock and commits this before removing the activation.
func (layout Layout) rememberConfirmed(digest string) error {
	history, err := layout.ConfirmedReleases()
	if err != nil {
		return err
	}
	if err := layout.VerifyRelease(digest); err != nil {
		return err
	}
	history = slices.DeleteFunc(history, func(previous string) bool { return previous == digest })
	history = append([]string{digest}, history...)
	history = history[:min(len(history), ConfirmedReleaseHistory)]
	data, err := protocol.EncodeJSON(confirmedReleases{Schema: confirmedReleasesSchema, Releases: history})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(layout.Root, confirmedReleasesFile), data, 0o644)
}
