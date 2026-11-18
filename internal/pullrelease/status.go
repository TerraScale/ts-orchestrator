package pullrelease

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
)

const (
	PhaseIdle        = "idle"
	PhaseRolling     = "rolling"
	PhaseComplete    = "complete"
	PhaseRefused     = "refused"
	PhaseRollingBack = "rolling_back"
	PhaseRolledBack  = "rolled_back"
	PhaseWaiting     = "waiting"
	PhaseStalled     = "rollback_stalled"
	PhaseNewer       = "newer"

	HostPending    = "pending"
	HostInstalling = "installing"
	HostGating     = "gating"
	HostRestoring  = "restoring"
	HostDone       = "done"
	HostRolledBack = "rolled_back"
	HostNewer      = "newer"

	badLimit = 16
)

type HostProgress struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	State     string    `json:"state"`
	Version   string    `json:"version,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	Error     string    `json:"error,omitempty"`
	Installed time.Time `json:"installed,omitzero"`
	Ready     time.Time `json:"ready,omitzero"`
}

type Status struct {
	Region   string                 `json:"region"`
	Owner    string                 `json:"owner,omitempty"`
	Phase    string                 `json:"phase"`
	Target   *releaseattest.Release `json:"target,omitempty"`
	Hosts    []HostProgress         `json:"hosts,omitempty"`
	Reason   string                 `json:"reason,omitempty"`
	Bad      []string               `json:"bad,omitempty"`
	Since    time.Time              `json:"since,omitzero"`
	Healthy  time.Time              `json:"healthy,omitzero"`
	Failing  time.Time              `json:"failing,omitzero"`
	Failed   int                    `json:"failed,omitempty"`
	Failures int                    `json:"failures,omitempty"`
	Done     time.Time              `json:"done,omitzero"`
	Checked  time.Time              `json:"checked,omitzero"`
	Updated  time.Time              `json:"updated,omitzero"`
	Seq      uint64                 `json:"seq,omitempty"`
	Channel  uint64                 `json:"channel_seq,omitempty"`

	Published  time.Time `json:"published,omitzero"`
	Discovered time.Time `json:"discovered,omitzero"`
	Passed     time.Time `json:"passed,omitzero"`
	Baseline   *Baseline `json:"baseline,omitempty"`
	Restart    string    `json:"restart,omitempty"`
}

func statusFile(state string) string { return filepath.Join(state, "nats", "pull-rollout.json") }

func Read(state string) (*Status, error) {
	data, err := os.ReadFile(statusFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("pull rollout record damaged: %w", err)
	}
	return &status, nil
}

func write(state string, status Status) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	path := statusFile(state)
	file, err := os.CreateTemp(filepath.Dir(path), ".pull-rollout-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	if err = errors.Join(err, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func (s Status) active() bool {
	return s.Phase == PhaseRolling || s.Phase == PhaseWaiting || s.Phase == PhaseRollingBack
}

func (s Status) passed() bool {
	return !s.Passed.IsZero()
}

func (s Status) Timeline() []string {
	if s.Target == nil {
		return nil
	}
	stamp := func(stage string, at time.Time) string {
		if at.IsZero() {
			return stage + "\t-"
		}
		line := stage + "\t" + at.UTC().Format(time.RFC3339)
		if !s.Published.IsZero() {
			line += "\t+" + at.Sub(s.Published).Round(time.Second).String()
		}
		return line
	}
	lines := []string{s.Region + "\t" + s.Target.Tag() + "\t" + s.Phase, stamp("published", s.Published), stamp("discovered", s.Discovered)}
	for _, host := range s.Hosts {
		lines = append(lines, stamp(host.Host+" installed", host.Installed), stamp(host.Host+" ready", host.Ready))
	}
	lines = append(lines, stamp("gate start", s.Done), stamp("gate end", s.Passed))
	complete := s.Passed
	if s.Phase != PhaseComplete {
		complete = time.Time{}
	}
	return append(lines, stamp("complete", complete))
}

func (s *Status) bad(tag string) bool {
	for _, known := range s.Bad {
		if known == tag {
			return true
		}
	}
	return false
}

func (s *Status) markBad(tag string) {
	if s.bad(tag) {
		return
	}
	s.Bad = append(s.Bad, tag)
	if len(s.Bad) > badLimit {
		s.Bad = s.Bad[len(s.Bad)-badLimit:]
	}
}

func (s *Status) host(id string) *HostProgress {
	for i := range s.Hosts {
		if s.Hosts[i].ID == id {
			return &s.Hosts[i]
		}
	}
	return nil
}

func (s Status) String() string {
	line := "pull rollout " + s.Phase
	if s.Target != nil {
		line += " " + s.Target.Tag()
	}
	if s.Reason != "" {
		line += " (" + s.Reason + ")"
	}
	if s.Owner != "" {
		line += " by " + s.Owner
	}
	parts := []string{line}
	for _, host := range s.Hosts {
		row := "    " + host.Host + ": " + host.State
		if host.Version != "" {
			row += " on " + host.Version
		}
		if host.Error != "" {
			row += "; " + host.Error
		}
		parts = append(parts, row)
	}
	return strings.Join(parts, "\n")
}
