package netbird

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const hostsMarker = "# terrascale-netbird-manager"

func lockRuntime(directory string) (*os.File, error) {
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("cannot create NetBird enrollment runtime directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("NetBird runtime directory must be a root-only directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("NetBird runtime directory has an unexpected owner")
	}
	fd, err := syscall.Open(filepath.Join(directory, "enroll.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("cannot open NetBird enrollment lock")
	}
	lock := os.NewFile(uintptr(fd), "enroll.lock")
	info, err = lock.Stat()
	if err != nil || !ownedRegular(info, 0o077) {
		lock.Close()
		return nil, errors.New("NetBird enrollment lock must be root-only")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another NetBird enrollment is running")
	}
	return lock, nil
}

func removeSetupKey(directory string) error {
	path := filepath.Join(directory, "setup-key")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !ownedRegular(info, 0o077) {
		return errors.New("unsafe leftover NetBird setup-key file")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("cannot remove transient NetBird setup-key file")
	}
	return nil
}

func writeSetupKey(directory string, key []byte) (string, error) {
	path := filepath.Join(directory, "setup-key")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", errors.New("cannot create transient NetBird setup-key file")
	}
	file := os.NewFile(uintptr(fd), path)
	written, writeErr := file.Write(key)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(key) || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.New("cannot write transient NetBird setup-key file")
	}
	return path, nil
}

func hostsContent(original []byte, ip string) ([]byte, error) {
	var updated strings.Builder
	seenManaged := false
	for line := range strings.SplitSeq(string(original), "\n") {
		// Only the exact one-host entry bearing our marker is owned by us.
		addressPart, comment, _ := strings.Cut(line, "#")
		fields := strings.Fields(addressPart)
		managed := "#"+strings.TrimRight(comment, " \t\r") == hostsMarker
		if managed {
			if seenManaged || len(fields) != 2 || fields[1] != managerHostname {
				return nil, errors.New("unexpected NetBird managed hosts entry")
			}
			seenManaged = true
			continue
		}
		if len(fields) > 1 {
			for _, hostname := range fields[1:] {
				if strings.EqualFold(hostname, managerHostname) {
					return nil, errors.New("an unmanaged hosts entry already defines the NetBird manager")
				}
			}
		}
		updated.WriteString(line)
		updated.WriteByte('\n')
	}
	result := strings.TrimSuffix(updated.String(), "\n")
	if ip != "" {
		if result != "" && !strings.HasSuffix(result, "\n") {
			result += "\n"
		}
		result += ip + "\t" + managerHostname + "\t" + hostsMarker + "\n"
	}
	return []byte(result), nil
}

func readHosts(path string) ([]byte, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, errors.New("cannot open hosts file for NetBird manager resolution")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !ownedRegular(info, 0o022) || info.Size() > 1<<20 {
		return nil, nil, errors.New("hosts file must be a root-owned bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		return nil, nil, errors.New("cannot read bounded hosts file")
	}
	return body, info, nil
}

func updateHosts(path, ip string) error {
	original, info, err := readHosts(path)
	if err != nil {
		return err
	}
	body, err := hostsContent(original, ip)
	if err != nil || bytes.Equal(body, original) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".terrascale-netbird-hosts-*")
	if err != nil {
		return errors.New("cannot create atomic NetBird hosts update")
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	stat := info.Sys().(*syscall.Stat_t)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		return errors.New("cannot preserve hosts file mode")
	}
	if err := temporary.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return errors.New("cannot preserve hosts file ownership")
	}
	if _, err := temporary.Write(body); err != nil {
		return errors.New("cannot write atomic NetBird hosts update")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("cannot sync atomic NetBird hosts update")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("cannot close atomic NetBird hosts update")
	}
	current, currentInfo, err := readHosts(path)
	if err != nil || !os.SameFile(info, currentInfo) || !bytes.Equal(current, original) {
		return errors.New("hosts file changed during NetBird manager update")
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return errors.New("cannot atomically install NetBird hosts update")
	}
	parent, err := os.Open(directory)
	if err != nil {
		return errors.New("cannot sync hosts directory")
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return errors.New("cannot sync hosts directory")
	}
	return nil
}
