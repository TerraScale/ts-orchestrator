package rootsecret

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"golang.org/x/sys/unix"
)

func openSpool(uid, gid uint32) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, bootstrapstart.GenerationSpoolDirectory, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, ErrDelivery
	}
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != 0o700 ||
		unix.Fstatfs(fd, &filesystem) != nil || filesystem.Type != unix.TMPFS_MAGIC || !vaultsecret.SwapOff() {
		unix.Close(fd)
		return -1, ErrDelivery
	}
	return fd, nil
}

func install(directory int, name string, value []byte, uid, gid uint32, guard func() error) error {
	if name == "" || name == "." || filepath.Base(name) != name || strings.Contains(name, "..") || guard() != nil {
		return ErrDelivery
	}
	temporary := ".root-delivery-" + rand.Text()
	fd, err := unix.Openat(directory, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrDelivery
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	defer unix.Unlinkat(directory, temporary, 0)
	if unix.Fchown(fd, int(uid), int(gid)) != nil || file.Chmod(0o600) != nil {
		return ErrDelivery
	}
	count, err := file.Write(value)
	if err != nil || count != len(value) || file.Sync() != nil || guard() != nil {
		return ErrDelivery
	}
	if err := unix.Renameat(directory, temporary, directory, name); err != nil {
		return ErrDelivery
	}
	return unix.Fsync(directory)
}
