package alertdelivery

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const credentialDirectory = "/run/ts-alert-delivery"

var credentialRefs = vaultsecret.AlertDeliveryRefs()

func prepareCredentials(ctx context.Context) error {
	root, gid, err := openCredentialRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	values, err := vaultsecret.ReadInstanceSecrets(ctx, "ts-alerts", credentialRefs)
	if err != nil {
		return errors.New("alert credential preparation could not read the approved Vault references")
	}
	defer clear(values)
	for key, value := range values {
		if err := writeCredential(root, key, value, gid); err != nil {
			return err
		}
	}
	if err := writeMeshToken(root, gid); err != nil {
		slog.WarnContext(ctx, "mesh alert budget token unavailable; alert email stays withheld until the mesh runs", "error", err)
	}
	return nil
}

func copyMeshToken(context.Context) error {
	root, gid, err := openCredentialRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	return writeMeshToken(root, gid)
}

func openCredentialRoot() (*os.Root, int, error) {
	if os.Geteuid() != 0 {
		return nil, 0, errors.New("alert credential preparation requires root")
	}
	account, err := user.Lookup("ts-alerts")
	if err != nil {
		return nil, 0, errors.New("alert credential preparation requires the ts-alerts account")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, 0, err
	}
	if err := os.Mkdir(credentialDirectory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, 0, err
	}
	info, err := os.Lstat(credentialDirectory)
	if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm() != 0o750 {
		return nil, 0, errors.New("alert credentials require a root-owned mode 0750 directory")
	}
	if err := vaultsecret.RequireMemoryFilesystem(credentialDirectory); err != nil {
		return nil, 0, err
	}
	if err := os.Chown(credentialDirectory, 0, gid); err != nil {
		return nil, 0, err
	}
	root, err := os.OpenRoot(credentialDirectory)
	if err != nil {
		return nil, 0, err
	}
	return root, gid, nil
}

func writeMeshToken(root *os.Root, gid int) error {
	token, err := os.ReadFile(meshAlertsToken)
	if err != nil {
		return err
	}
	defer clear(token)
	return writeCredential(root, "TS_ALERTS_NATS_TOKEN_FILE", strings.TrimSpace(string(token)), gid)
}

func writeCredential(root *os.Root, key, value string, gid int) error {
	temporary := ".pending-" + rand.Text()
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	if err = file.Chmod(0o640); err == nil {
		err = file.Chown(0, gid)
	}
	if err == nil {
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
