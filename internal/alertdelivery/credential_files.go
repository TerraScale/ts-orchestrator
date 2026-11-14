package alertdelivery

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func readCredentialFiles(keys ...string) (map[string]string, error) {
	account, err := user.Lookup("ts-alerts")
	if err != nil {
		return nil, fmt.Errorf("alert credential account unavailable")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, fmt.Errorf("alert credential account invalid")
	}
	info, err := os.Lstat(credentialDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Gid != uint32(gid) {
		return nil, fmt.Errorf("alert credential directory must be root:ts-alerts mode 0750")
	}
	if err := vaultsecret.RequireMemoryFilesystem(credentialDirectory); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(credentialDirectory)
	if err != nil {
		return nil, fmt.Errorf("alert credential directory unavailable")
	}
	defer root.Close()
	values := make(map[string]string, len(keys))
	for _, key := range keys {
		name := strings.ToLower(key)
		info, err := root.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("alert credential file %s unavailable; run the root preparation step", key)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Gid != uint32(gid) {
			return nil, fmt.Errorf("alert credential file %s must be root:ts-alerts mode 0640", key)
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, fmt.Errorf("alert credential file %s unavailable; run the root preparation step", key)
		}
		value, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
		file.Close()
		if err != nil || len(value) == 0 || len(value) > 16<<10 {
			return nil, fmt.Errorf("alert credential file %s invalid", key)
		}
		values[key] = string(value)
		clear(value)
	}
	return values, nil
}
