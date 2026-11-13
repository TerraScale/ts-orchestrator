package rolloutmaintenance

import (
	"context"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"os"
	"path/filepath"
)

// Candidate is recorded only by the existing authenticated release handler,
// after GitHub release admission. It stages provenance without publishing an intent.
type Candidate struct {
	Image      string `json:"image"`
	Repository string `json:"repository"`
	RunID      string `json:"runId"`
	RunAttempt uint64 `json:"runAttempt"`
	Revision   string `json:"revision"`
	Workflow   string `json:"workflow,omitempty"`
}

func (s *Store) RetainCandidate(ctx context.Context, c Candidate) error {
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	j, err := s.read()
	if err != nil {
		return err
	}
	if j == nil || j.Target.Image != c.Image {
		return ErrFenced
	}
	data, err := protocol.EncodeJSON(c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.root, ".candidate-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.root, "candidate.json")); err != nil {
		return err
	}
	return syncDir(s.root)
}
func (s *Store) Candidate(ctx context.Context) (*Candidate, error) {
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := os.Open(filepath.Join(s.root, "candidate.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var result Candidate
	data, err := os.ReadFile(f.Name())
	if err != nil {
		return nil, err
	}
	if err = protocol.DecodeStrict(data, &result, 64<<10); err != nil {
		return nil, err
	}
	return &result, nil
}
