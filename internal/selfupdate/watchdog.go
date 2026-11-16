package selfupdate

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"time"
)

// Outcome is the watchdog's decision for one check.
type Outcome string

const (
	OutcomeIdle       Outcome = "idle"
	OutcomePending    Outcome = "pending"
	OutcomeConfirmed  Outcome = "confirmed"
	OutcomeRolledBack Outcome = "rolled-back"
)

// ProofCheck locates and authenticates the version proof of one unit.
type ProofCheck struct {
	File      string
	PublicKey ed25519.PublicKey
}

// OrphanedActivationGrace is how long past its deadline an activation of a
// unit no watchdog matches stays pending before any watchdog rolls it back.
// It covers the matching unit's watchdog timer running late.
const OrphanedActivationGrace = 5 * time.Minute

// StagedReleaseRetention keeps a release that is neither current nor part
// of a pending activation for this long after it was staged, so a release
// staged for an upcoming activation is not pruned before it is activated.
const StagedReleaseRetention = 24 * time.Hour

// PruneReleases removes settled release directories: everything except the
// current, known-good and retained confirmed releases, both sides of a pending
// activation, the image-baked release, and non-known-bad releases staged within
// StagedReleaseRetention.
// The caller holds Lock. It returns the removed digests.
func (layout Layout) PruneReleases(now time.Time) ([]string, error) {
	current, err := layout.Current()
	if err != nil {
		return nil, err
	}
	if current == "" {
		return nil, nil
	}
	keep := map[string]bool{current: true}
	if known, err := layout.KnownGood(); err != nil {
		return nil, err
	} else if known != "" {
		keep[known] = true
	}
	confirmed, err := layout.ConfirmedReleases()
	if err != nil {
		return nil, err
	}
	for _, digest := range confirmed {
		keep[digest] = true
	}
	activation, pending, err := layout.Pending()
	if err != nil {
		return nil, err
	}
	if pending {
		keep[activation.Target], keep[activation.Previous] = true, true
	}
	knownBad, err := layout.KnownBad()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(layout.releasesPath())
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, entry := range entries {
		digest := entry.Name()
		if !digestRE.MatchString(digest) || keep[digest] {
			continue
		}
		directory := layout.ReleaseDir(digest)
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, err := os.Lstat(filepath.Join(directory, bakedMarkerFile)); err == nil {
			continue
		}
		if !knownBad[digest] && now.Sub(info.ModTime()) < StagedReleaseRetention {
			continue
		}
		if err := layout.checkOwned(directory, true); err != nil {
			return removed, err
		}
		if err := os.RemoveAll(directory); err != nil {
			return removed, err
		}
		removed = append(removed, digest)
	}
	if len(removed) > 0 {
		return removed, syncDir(layout.releasesPath())
	}
	return removed, nil
}

// WatchdogUnit is the template unit that runs the watchdog for each role.
const WatchdogUnit = "terrascale-orchestrator-selfupdate-watchdog@.service"

// WatchdogLoggingDropin keeps systemd's own lines for each 15 s run out of the journal.
const WatchdogLoggingDropin = `[Service]
# Each 15 s run would log six systemd lines; keep notices and above.
LogLevelMax=notice
SyslogLevel=notice
`
