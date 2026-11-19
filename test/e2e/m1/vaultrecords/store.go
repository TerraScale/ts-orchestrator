package vaultrecords

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

type Store struct{ dir string }

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) version(name string, version int64) string {
	return filepath.Join(s.dir, name+"."+strconv.FormatInt(version, 10))
}

func (s *Store) Read(_ context.Context, name string) (string, int64, error) {
	value, version := "", int64(0)
	for {
		data, err := os.ReadFile(s.version(name, version+1))
		if errors.Is(err, fs.ErrNotExist) {
			return value, version, nil
		}
		if err != nil {
			return "", 0, err
		}
		value, version = string(data), version+1
	}
}

func (s *Store) write(name string, version int64, value string) error {
	staged, err := os.CreateTemp(s.dir, ".staged-")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if _, err := staged.WriteString(value); err != nil {
		staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	return os.Link(staged.Name(), s.version(name, version))
}

func (s *Store) Create(_ context.Context, name, value string) error {
	if err := s.write(name, 1, value); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

func (s *Store) Swap(ctx context.Context, name string, version int64, value string) error {
	if _, current, err := s.Read(ctx, name); err != nil || current != version {
		return errors.Join(err, fmt.Errorf("%s is at version %d, not %d", name, current, version))
	}
	return s.write(name, version+1, value)
}
