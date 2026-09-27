package app

import (
	"encoding/json/v2"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const bakedRuntimePriorityPath = "/etc/terrascale-orchestrator/runtime-priority.json"

type bakedRuntimePriorityProfile struct {
	Version            int    `json:"version"`
	ProfileID          string `json:"profile_id"`
	SystemReserveBytes uint64 `json:"system_reserve_bytes"`
}

// readBakedRuntimePriorityProfile reads the static profile packaged in the
// signed host image. The configured placement reserve must match this value.
func readBakedRuntimePriorityProfile() (uint64, error) {
	return readBakedRuntimePriorityProfileAt(bakedRuntimePriorityPath, 0, 0)
}

func readBakedRuntimePriorityProfileAt(path string, ownerUID, ownerGID uint32) (uint64, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return 0, errors.New("runtime priority profile path is invalid")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return 0, err
	}
	if !ownedRuntimePriorityPath(parentInfo, ownerUID, ownerGID, 0755, true) {
		return 0, errors.New("runtime priority profile directory is unsafe")
	}
	dirFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(dirFD)
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if !ownedRuntimePriorityPath(fileInfo, ownerUID, ownerGID, 0644, false) || fileInfo.Size() < 1 || fileInfo.Size() > 1024 {
		return 0, errors.New("runtime priority profile file is unsafe")
	}
	fd, err := unix.Openat(dirFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(fileInfo, openedInfo) ||
		!ownedRuntimePriorityPath(openedInfo, ownerUID, ownerGID, 0644, false) {
		return 0, errors.New("runtime priority profile changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return 0, err
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(openedInfo, finalInfo) || finalInfo.Size() != int64(len(data)) ||
		finalInfo.ModTime() != openedInfo.ModTime() {
		return 0, errors.New("runtime priority profile changed while reading")
	}
	var profile bakedRuntimePriorityProfile
	if err := json.Unmarshal(data, &profile, json.RejectUnknownMembers(true)); err != nil {
		return 0, errors.New("runtime priority profile JSON is invalid")
	}
	if profile.Version != 1 || !validRuntimePriorityProfileID(profile.ProfileID) ||
		profile.SystemReserveBytes == 0 || profile.SystemReserveBytes > math.MaxInt64 ||
		profile.SystemReserveBytes%uint64(os.Getpagesize()) != 0 {
		return 0, errors.New("runtime priority profile values are invalid")
	}
	return profile.SystemReserveBytes, nil
}

func ownedRuntimePriorityPath(info os.FileInfo, uid, gid uint32, mode os.FileMode, directory bool) bool {
	if info == nil || info.IsDir() != directory || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode()&os.ModeType != 0 && !directory || info.Mode().Perm() != mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid && stat.Mode&07777 == uint32(mode)
}

func validRuntimePriorityProfileID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' ||
			character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}
