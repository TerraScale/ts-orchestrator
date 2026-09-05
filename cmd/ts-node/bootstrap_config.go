package main

import (
	"errors"
	"io"
	"os"
	"syscall"
)

func readBootstrapConfigFile(path string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("ts-node: bootstrap file must be a bounded protected regular file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return nil, errors.New("ts-node: bootstrap file ownership or link count differs")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("ts-node: bootstrap file exceeds bound")
	}
	return data, nil
}
