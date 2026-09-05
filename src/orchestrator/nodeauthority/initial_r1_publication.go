package nodeauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Private publication progress disambiguates a never-authorized interrupted
// initialization from disappearance of a once-admitted public record. Only the
// existing host EpochStore owner writes it. Public Ready stays false until the
// private commit is durable; committed publication never recreates missing state.
type initialR1Publication struct {
	Version   int               `json:"version"`
	Identity  InitialR1Identity `json:"identity"`
	Directory string            `json:"directory"`
	Committed bool              `json:"committed"`
}

func (s *EpochStore) readInitialR1Publication() (initialR1Publication, bool, error) {
	var progress initialR1Publication
	file, err := os.OpenFile(filepath.Join(filepath.Dir(s.path), "initial-r1-publication.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return progress, false, nil
	}
	if err != nil {
		return progress, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return progress, false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Size() > initialR1MaximumBytes {
		return progress, false, errors.New("nodeauthority: unsafe initial R1 private progress")
	}
	raw, err := io.ReadAll(io.LimitReader(file, initialR1MaximumBytes+1))
	if err != nil {
		return progress, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&progress) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return progress, false, errors.New("nodeauthority: corrupt initial R1 private progress")
	}
	canonical, err := json.Marshal(progress)
	if err != nil || !bytes.Equal(raw, canonical) || progress.Version != 1 || !validInitialR1Identity(progress.Identity) || !filepath.IsAbs(progress.Directory) || filepath.Clean(progress.Directory) != progress.Directory {
		return progress, false, errors.New("nodeauthority: invalid initial R1 private progress")
	}
	return progress, true, nil
}

func (s *EpochStore) writeInitialR1Publication(progress initialR1Publication) error {
	raw, err := json.Marshal(progress)
	if err != nil || len(raw) > initialR1MaximumBytes {
		return errors.New("nodeauthority: invalid initial R1 private progress size")
	}
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".initial-r1-publication-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "initial-r1-publication.json")); err != nil {
		return err
	}
	return syncEpochDirectory(dir)
}

func (s *EpochStore) publishInitialR1(ctx context.Context, directory string, identity InitialR1Identity, uid uint32, afterRename func() error) error {
	g, err := newInitialR1Guard(directory, identity, uid)
	if err != nil {
		return err
	}
	progress, found, err := s.readInitialR1Publication()
	if err != nil {
		return err
	}
	if found && (!sameInitialR1Identity(progress.Identity, identity) || progress.Directory != directory) {
		return errors.New("nodeauthority: initial R1 publication intent conflicts")
	}
	if !found {
		// Absence of private intent is allowed only before any public artifacts.
		dir, err := g.openDirectory()
		if err != nil {
			return err
		}
		for _, name := range []string{"initial-r1.json", "initial-r1.lock"} {
			var st unix.Stat_t
			err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if !errors.Is(err, unix.ENOENT) {
				dir.Close()
				return errors.New("nodeauthority: initial R1 public artifacts lack private intent")
			}
		}
		dir.Close()
		progress = initialR1Publication{Version: 1, Identity: identity, Directory: directory}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = s.writeInitialR1Publication(progress); err != nil {
			return err
		}
	}
	dir, lock, _, err := g.lock(ctx, true, !progress.Committed)
	if err != nil {
		return err
	}
	defer dir.Close()
	defer lock.Close()
	record, err := g.read(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if progress.Committed {
		if err != nil {
			return err
		}
		if record.Retirement != nil {
			return ErrInitialR1Retired
		}
		if err = syncEpochDirectory(filepath.Dir(s.path)); err != nil {
			return err
		}
		if record.Ready {
			return dir.Sync()
		}
	} else {
		if err == nil && (record.Ready || record.Retirement != nil) {
			return errors.New("nodeauthority: public initial R1 admission precedes private commit")
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = writeInitialR1(dir, initialR1Record{Version: 1, Identity: identity}, nil); err != nil {
			return err
		}
		progress.Committed = true
		if err = s.writeInitialR1Publication(progress); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	if now.Before(identity.IssuedAt) || !now.Before(identity.ExpiresAt) {
		return errors.New("nodeauthority: initial R1 grant expired before publication")
	}
	return writeInitialR1(dir, initialR1Record{Version: 1, Ready: true, Identity: identity}, afterRename)
}
