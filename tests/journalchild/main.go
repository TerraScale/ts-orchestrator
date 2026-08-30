// Command journalchild is a deliberately self-contained process fixture for
// the control-plane journal contention test. It is not production code.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	barrierWait = 120 * time.Second
	lockWait    = 15 * time.Second
	maxPath     = 4096
	maxActor    = 128
	maxRecord   = 128 * 1024
)

const (
	exitBadArguments = 64
	exitBarrier      = 65
	exitFailure      = 66
)

const operationID = "op-contention"

type envelope struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Tag       string `json:"tag"`
}

type entry struct {
	Version     int    `json:"version"`
	OperationID string `json:"operationId"`
	Fingerprint string `json:"operationFingerprint"`
	Stage       string `json:"stage"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := run(ctx, os.Args[1:])
	if code == exitFailure {
		// Keep diagnostics deliberately generic: in particular, never print the
		// HMAC key or authenticated record bytes.
		_, _ = io.WriteString(os.Stderr, "journalchild: operation rejected\n")
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string) int {
	if len(args) != 5 {
		return exitBadArguments
	}

	directory, barrier, result, actor, err := validateArguments(args)
	if err != nil {
		return exitBadArguments
	}
	key, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil || len(key) == 0 || len(key) > 4096 {
		return exitBadArguments
	}
	defer clear(key)

	if err := writePrivateFile(result+".ready", []byte(actor), directory); err != nil {
		return exitFailure
	}
	if err := waitForBarrier(ctx, barrier, directory); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return exitBarrier
		}
		if errors.Is(err, context.Canceled) {
			return 130
		}
		return exitFailure
	}

	won, observed, err := compareExchange(ctx, directory, key)
	if err != nil {
		return exitFailure
	}
	status := "False"
	if won {
		status = "True"
	}
	verdict := fmt.Sprintf("%s|%s|%d|%s", actor, status, observed, operationID)
	if err := writePrivateFile(result, []byte(verdict), directory); err != nil {
		return exitFailure
	}
	if won {
		return 0
	}
	return 1
}

func validateArguments(args []string) (string, string, string, string, error) {
	directory, err := canonicalExistingDirectory(args[0])
	if err != nil {
		return "", "", "", "", err
	}
	barrier, err := canonicalOutputPath(args[2], directory)
	if err != nil {
		return "", "", "", "", err
	}
	result, err := canonicalOutputPath(args[3], directory)
	if err != nil {
		return "", "", "", "", err
	}
	actor := args[4]
	if actor == "" || len(actor) > maxActor || strings.ContainsAny(actor, "|\r\n\x00") {
		return "", "", "", "", errors.New("invalid actor")
	}
	for _, r := range actor {
		if r < 0x20 || r == 0x7f {
			return "", "", "", "", errors.New("invalid actor")
		}
	}
	return directory, barrier, result, actor, nil
}

func canonicalExistingDirectory(value string) (string, error) {
	path, err := canonicalAbsolute(value)
	if err != nil || rejectSymlinkComponents(path) != nil {
		return "", errors.New("invalid directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return "", errors.New("invalid directory")
	}
	return path, nil
}

func canonicalOutputPath(value, directory string) (string, error) {
	path, err := canonicalAbsolute(value)
	if err != nil {
		return "", errors.New("invalid path")
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path is outside directory")
	}
	parent := filepath.Dir(path)
	if err := rejectSymlinkComponents(parent); err != nil {
		return "", errors.New("path contains a symbolic link")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("invalid output path")
		}
	} else if !os.IsNotExist(err) {
		return "", errors.New("invalid output path")
	}
	return path, nil
}

func canonicalAbsolute(value string) (string, error) {
	if value == "" || len(value) > maxPath || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) {
		return "", errors.New("path must be absolute and bounded")
	}
	path := filepath.Clean(value)
	if path != value || len(path) > maxPath {
		return "", errors.New("path is not canonical")
	}
	return path, nil
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	remainder := strings.TrimPrefix(clean, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symbolic link")
		}
	}
	return nil
}

func waitForBarrier(ctx context.Context, barrier, directory string) error {
	timer := time.NewTimer(barrierWait)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		present, err := regularFileExists(barrier, directory)
		if err != nil {
			return err
		}
		if present {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return context.DeadlineExceeded
		case <-ticker.C:
		}
	}
}

func regularFileExists(path, directory string) (bool, error) {
	if _, err := canonicalOutputPath(path, directory); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("barrier is not a regular file")
	}
	return true, nil
}

func compareExchange(ctx context.Context, directory string, key []byte) (bool, int, error) {
	digest := sha256.Sum256([]byte(operationID))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	lockPath := path + ".lock"
	lock, err := acquireLock(ctx, lockPath, directory)
	if err != nil {
		return false, 0, err
	}
	defer func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}()

	current, err := readEntry(path, key, directory)
	if err != nil {
		return false, 0, err
	}
	if current != nil {
		return false, current.Version, nil
	}
	replacement := entry{Version: 1, OperationID: operationID, Fingerprint: "fingerprint", Stage: "prepared"}
	if err := writeEntry(path, replacement, key, directory); err != nil {
		return false, 0, err
	}
	return true, replacement.Version, nil
}

func acquireLock(ctx context.Context, path, directory string) (*os.File, error) {
	if _, err := canonicalOutputPath(path, directory); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			_ = file.Close()
			return nil, errors.New("invalid lock file")
		}
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		_ = file.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func readEntry(path string, key []byte, directory string) (*entry, error) {
	if _, err := canonicalOutputPath(path, directory); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || len(data) == 0 || len(data) > maxRecord {
		return nil, errors.New("journal record is invalid")
	}
	var record envelope
	if json.Unmarshal(data, &record) != nil || record.Algorithm != "HMAC-SHA256" || record.KeyID != "test" {
		return nil, errors.New("journal record is invalid")
	}
	payload, payloadErr := base64.StdEncoding.DecodeString(record.Payload)
	tag, tagErr := base64.StdEncoding.DecodeString(record.Tag)
	if payloadErr != nil || tagErr != nil || len(payload) == 0 || len(payload) > maxRecord || len(tag) != sha256.Size {
		return nil, errors.New("journal record is invalid")
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(payload)
	if !hmac.Equal(tag, digest.Sum(nil)) {
		return nil, errors.New("journal integrity check failed")
	}
	var value entry
	if json.Unmarshal(payload, &value) != nil || value.Version != 1 || value.OperationID != operationID || value.Fingerprint == "" || value.Stage != "prepared" {
		return nil, errors.New("journal record is invalid")
	}
	return &value, nil
}

func writeEntry(path string, value entry, key []byte, directory string) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(payload)
	record, err := json.Marshal(envelope{Algorithm: "HMAC-SHA256", KeyID: "test", Payload: base64.StdEncoding.EncodeToString(payload), Tag: base64.StdEncoding.EncodeToString(digest.Sum(nil))})
	if err != nil {
		return err
	}
	return atomicPrivateWrite(path, record, directory)
}

func writePrivateFile(path string, data []byte, directory string) error {
	if len(data) > maxRecord {
		return errors.New("file is too large")
	}
	return atomicPrivateWrite(path, data, directory)
}

func atomicPrivateWrite(path string, data []byte, directory string) error {
	if _, err := canonicalOutputPath(path, directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".journalchild-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if directoryFile, err := os.Open(directory); err == nil {
		_ = directoryFile.Sync()
		_ = directoryFile.Close()
	}
	return nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
