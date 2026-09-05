package nodeauthority

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

const candidateActivityName = "activity.lock"

func prepareCandidateActivity(directory string, uid uint32) error {
	f, err := openCandidateActivity(directory, uid, true)
	if err != nil {
		return err
	}
	err = f.Sync()
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return syncEpochDirectory(directory)
}

func openCandidateActivity(directory string, uid uint32, create bool) (*os.File, error) {
	if err := checkCandidateParents(directory, uid); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, candidateActivityName)
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	var f *os.File
	var err error
	if create {
		f, err = os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			if err = f.Chmod(0644); err != nil {
				f.Close()
				return nil, err
			}
		} else if !os.IsExist(err) {
			return nil, err
		}
	}
	if f == nil {
		f, err = os.OpenFile(path, flags, 0)
		if err != nil {
			return nil, err
		}
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || info.Size() != 0 || stat.Uid != uid || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("nodeauthority: candidate activity lock ownership or type differs")
	}
	return f, nil
}

// WithinPublishedCandidateMutation protects one finite local preparation effect
// from ordinary runtime admission. It grants no application or provider writes.
// The original root publication is checked after obtaining shared ownership.
func WithinPublishedCandidateMutation(ctx context.Context, config transitiongrant.Config, fn func(context.Context) error) error {
	return withinCandidateMutation(ctx, config, CandidatePreparationDirectory, 0, fn)
}

func withinCandidateMutation(ctx context.Context, config transitiongrant.Config, directory string, uid uint32, fn func(context.Context) error) error {
	if ctx == nil || fn == nil {
		return errors.New("nodeauthority: finite candidate effect requires context and callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := openCandidateActivity(directory, uid, false)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return errors.New("nodeauthority: candidate admission is changing")
	}
	publication, err := readPublishedCandidate(ctx, config, directory, uid)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	operation, stop := context.WithDeadline(bounded, publication.Receipt.ExpiresAt)
	defer stop()
	if err := fn(operation); err != nil {
		return err
	}
	if err := operation.Err(); err != nil {
		return err
	}
	current, err := readPublishedCandidate(operation, config, directory, uid)
	if err != nil {
		return err
	}
	if current.Receipt != publication.Receipt {
		return errors.New("nodeauthority: candidate admission changed during local effect")
	}
	return nil
}
