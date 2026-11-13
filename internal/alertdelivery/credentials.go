package alertdelivery

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const credentialDirectory = "/run/ts-alert-delivery"

var credentialRefs = map[string]vaultsecret.Ref{
	"CLOUDFLARE_ACCOUNT_ID_FILE":  {Vault: vaultsecret.SharedVault, Name: "gru-1-cloudflare-account-id"},
	"CLOUDFLARE_EMAIL_TOKEN_FILE": {Vault: vaultsecret.SharedVault, Name: "gru-1-cloudflare-email-token"},
	"TS_ALERTS_NTFY_TOPIC_FILE":   {Vault: vaultsecret.SharedVault, Name: "gru-1-ts-alerts-ntfy-topic"},
}

func prepareCredentials(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("alert credential preparation requires root")
	}
	account, err := user.Lookup("ts-alerts")
	if err != nil {
		return errors.New("alert credential preparation requires the ts-alerts account")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := os.Mkdir(credentialDirectory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(credentialDirectory)
	if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm() != 0o750 {
		return errors.New("alert credentials require a root-owned mode 0750 directory")
	}
	if err := vaultsecret.RequireMemoryFilesystem(credentialDirectory); err != nil {
		return err
	}
	if err := os.Chown(credentialDirectory, 0, gid); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	values, err := vaultsecret.ReadInstanceSecrets(ctx, "ts-alerts", credentialRefs)
	if err != nil {
		return errors.New("alert credential preparation could not read the approved Vault references")
	}
	defer clear(values)
	root, err := os.OpenRoot(credentialDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	for key, value := range values {
		if err := writeCredential(root, key, value, gid); err != nil {
			return err
		}
	}
	return nil
}

func writeCredential(root *os.Root, key, value string, gid int) error {
	temporary := ".pending-" + rand.Text()
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	if err = file.Chown(0, gid); err == nil {
		_, err = io.WriteString(file, value)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return root.Rename(temporary, strings.ToLower(key))
}

func readCredentialFiles(keys ...string) (map[string]string, error) {
	values := make(map[string]string, len(keys))
	for _, key := range keys {
		file, err := os.Open(filepath.Join(credentialDirectory, strings.ToLower(key)))
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
