package cellscale

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	cellStateDirectory    = "/var/lib/ts-orch/cell-autoscaler"
	launchJournalName     = "launches.json"
	maxLaunchJournalBytes = 8 << 20
)

type launchJournalManifest struct {
	Schema   int              `json:"schema"`
	Cell     string           `json:"cell"`
	Region   string           `json:"region"`
	Launches []OCILaunchState `json:"launches"`
}

type launchJournal struct {
	directory *os.File
	config    FileConfig
	uid       uint32
}

func initialLaunchJournal(config FileConfig) launchJournalManifest {
	return launchJournalManifest{Schema: 1, Cell: config.Cell, Region: config.Template.Region, Launches: []OCILaunchState{}}
}

func cellStateName(config FileConfig) string {
	return strings.TrimSuffix(cellLockName(config), ".lock")
}

func launchJournalPath(config FileConfig) string {
	return filepath.Join(cellStateDirectory, cellStateName(config), launchJournalName)
}

func openLaunchJournal(config FileConfig) (*launchJournal, []OCILaunchState, error) {
	return openLaunchJournalAt(config, cellStateDirectory, 0, uint32(os.Geteuid()))
}

// The protected parent keeps a different runner UID from replacing the cell
// directory. Open existing state only: absence never authorizes a new token.
func openLaunchJournalAt(config FileConfig, parentPath string, provisioner, runner uint32) (*launchJournal, []OCILaunchState, error) {
	parent, err := os.OpenFile(parentPath, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open provisioned launch journal directory %s: %w", parentPath, err)
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Sys().(*syscall.Stat_t).Uid != provisioner || info.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("launch journal parent must be provisioner-owned and not group or world writable")
	}
	fd, err := syscall.Openat(int(parent.Fd()), cellStateName(config), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open existing cell launch state: %w", err)
	}
	directory := os.NewFile(uintptr(fd), filepath.Join(parentPath, cellStateName(config)))
	j := &launchJournal{directory: directory, config: config, uid: runner}
	states, err := j.read()
	if err != nil {
		directory.Close()
		return nil, nil, fmt.Errorf("read existing launch journal %s: %w", filepath.Join(directory.Name(), launchJournalName), err)
	}
	return j, states, nil
}

func (j *launchJournal) openExisting() (*os.File, error) {
	info, err := j.directory.Stat()
	if err != nil {
		return nil, err
	}
	if info.Sys().(*syscall.Stat_t).Uid != j.uid || info.Mode().Perm() != 0o700 {
		return nil, errors.New("cell launch state directory must be runner-owned mode 0700")
	}
	fd, err := syscall.Openat(int(j.directory.Fd()), launchJournalName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), launchJournalName)
	info, err = file.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != j.uid || info.Sys().(*syscall.Stat_t).Nlink != 1) {
		err = errors.New("launch journal must be a runner-owned regular mode 0600 file with one link")
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func (j *launchJournal) read() ([]OCILaunchState, error) {
	file, err := j.openExisting()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxLaunchJournalBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLaunchJournalBytes {
		return nil, errors.New("launch journal exceeds 8 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest launchJournalManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("launch journal must contain exactly one JSON value")
	}
	if manifest.Schema != 1 || manifest.Cell != j.config.Cell || manifest.Region != j.config.Template.Region || manifest.Launches == nil || len(manifest.Launches) > maxOrdinal {
		return nil, errors.New("launch journal has an invalid schema, cell, region or launches array")
	}
	return manifest.Launches, nil
}

// OCICloud serializes this callback. The cell lock spans load, replacement and
// all mutations; fsync failures must reach OCICloud before any POST.
func (j *launchJournal) save(states []OCILaunchState) error {
	existing, err := j.openExisting()
	if err != nil {
		return err
	}
	if err := existing.Close(); err != nil {
		return err
	}
	manifest := initialLaunchJournal(j.config)
	if states != nil {
		manifest.Launches = states
	}
	if len(manifest.Launches) > maxOrdinal {
		return errors.New("launch journal exceeds cell name bound")
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if len(data) > maxLaunchJournalBytes {
		return errors.New("launch journal exceeds 8 MiB")
	}
	temporary := ".launches-" + rand.Text()
	dir := int(j.directory.Fd())
	fd, err := syscall.Openat(dir, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(dir, temporary)
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(dir, temporary, dir, launchJournalName); err != nil {
		return err
	}
	return j.directory.Sync()
}
