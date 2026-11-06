package rolloutmaintenance

import (
	"context"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"os"
	"path/filepath"
)

// HoldIngress journals a regional barrier independently of the local replacement
// (the writer may be the worker, while the region's edge runs on the founder).
func (s *Store) HoldIngress(ctx context.Context, j Job) error {
	if err := j.validate(); err != nil {
		return err
	}
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(s.root, "ingress.json")
	data, err := os.ReadFile(path)
	if err == nil {
		var previous Job
		if err = protocolDecode(data, &previous); err != nil {
			return err
		}
		if previous.ID != j.ID || previous.Source != j.Source || previous.Owner != j.Owner || previous.Epoch != j.Epoch {
			return ErrFenced
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Same atomic/fsynced writer as the executor journal, in a separate namespace.
	temporary := &Store{root: filepath.Join(s.root, "ingress-stage")}
	if err = os.MkdirAll(temporary.root, 0700); err != nil {
		return err
	}
	if err = temporary.write(j); err != nil {
		return err
	}
	if err = os.Rename(filepath.Join(temporary.root, "job.json"), path); err != nil {
		return err
	}
	return syncDir(s.root)
}
func (s *Store) Ingress(ctx context.Context) (*Job, error) {
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	data, err := os.ReadFile(filepath.Join(s.root, "ingress.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Job
	if err = protocolDecode(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}
func (s *Store) ReleaseIngress(ctx context.Context, j Job) error {
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(filepath.Join(s.root, "ingress.json"))
	if err != nil {
		return err
	}
	var previous Job
	if err = protocolDecode(data, &previous); err != nil {
		return err
	}
	if previous.ID != j.ID || previous.Source != j.Source || previous.Owner != j.Owner || previous.Epoch != j.Epoch {
		return ErrFenced
	}
	if err = os.Remove(filepath.Join(s.root, "ingress.json")); err != nil {
		return err
	}
	return syncDir(s.root)
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func protocolDecode(data []byte, j *Job) error {
	if err := protocol.DecodeStrict(data, j, 64<<10); err != nil {
		return err
	}
	return j.validate()
}
