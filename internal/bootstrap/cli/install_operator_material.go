package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

func (c command) installOperatorMaterialAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("install-operator-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recordPath := flags.String("material-record", "", "reviewed public material inventory")
	recordSHA := flags.String("material-record-sha256", "", "reviewed public inventory SHA-256")
	materialDirectory := flags.String("material-directory", "", "complete owner-only offline material source")
	configPath := flags.String("operator-config", "", "reviewed canonical operator config")
	configSHA := flags.String("operator-config-sha256", "", "reviewed operator config SHA-256")
	signingKeyPath := flags.String("operator-signing-key", "", "reviewed owner-only operator Ed25519 key PEM")
	signingKeySHA := flags.String("operator-signing-key-sha256", "", "reviewed operator key SHA-256")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || os.Geteuid() != 0 || !filepath.IsAbs(*materialDirectory) {
		return errors.New("install-operator-material requires root and an absolute owner-only source")
	}
	recordWire, err := readPinnedControllerFile(*recordPath, *recordSHA, 1<<20)
	if err != nil {
		return err
	}
	var record bootstrapmaterial.Record
	if err := protocol.DecodeStrict(recordWire, &record, 1<<20); err != nil {
		return err
	}
	live, err := bootstrapmaterial.Load(*materialDirectory)
	if err != nil || !reflect.DeepEqual(record, live) {
		return errors.New("owner-only operator source differs from reviewed material inventory")
	}
	if err := natscell.ValidateBrokerOperatorCredentials(filepath.Join(*materialDirectory, "operator.creds"),
		record.Config.Cell); err != nil {
		return err
	}
	configWire, err := readPinnedControllerFile(*configPath, *configSHA, 16<<10)
	if err != nil {
		return err
	}
	var cfg app.Config
	if err := protocol.DecodeStrict(configWire, &cfg, 16<<10); err != nil {
		return err
	}
	if len(cfg.Controller.TrustedSigners) != 1 {
		return errors.New("reviewed operator config must contain one signer grant")
	}
	expected, err := operatorConfigFromRecord(record, cfg.Controller.TrustedSigners[0], now)
	if err != nil {
		return err
	}
	canonical, err := protocol.EncodeJSON(expected)
	if err != nil || !bytes.Equal(canonical, configWire) {
		return errors.New("reviewed operator config differs from deterministic material record")
	}
	keyWire, err := readPinnedControllerFile(*signingKeyPath, *signingKeySHA, maxKeyFileBytes)
	if err != nil {
		return err
	}
	key, err := readRootPrivateKey(*signingKeyPath)
	if err != nil {
		return err
	}
	clear(keyWire)
	grantPublic, err := base64.StdEncoding.Strict().DecodeString(cfg.Controller.TrustedSigners[0].PublicKey)
	if err != nil || !bytes.Equal(key.Public().(ed25519.PublicKey), grantPublic) {
		clear(key)
		return errors.New("reviewed operator signing key differs from signed grant")
	}
	// The operator CLI reads the base64 Ed25519 key form every runtime key uses.
	runtimeKey := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	clear(key)
	sources := map[string][]byte{"operator-signing.key": runtimeKey, "operator.json": configWire}
	for _, name := range []string{"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem", "ca.pem", "ticket.pub"} {
		var file *bootstrapmaterial.File
		for index := range record.Files {
			if record.Files[index].Name == name {
				file = &record.Files[index]
				break
			}
		}
		if file == nil || file.MaxBytes <= 0 || file.MaxBytes > 64<<10 {
			return fmt.Errorf("reviewed operator source lacks bounded %s", name)
		}
		sources[name], err = readPinnedControllerFile(filepath.Join(*materialDirectory, name), file.SHA256, int(file.MaxBytes))
		if err != nil || int64(len(sources[name])) != file.MaxBytes {
			return fmt.Errorf("operator source %s differs from reviewed bytes: %w", name, err)
		}
	}
	if strings.TrimSpace(string(sources["ticket.pub"])) != record.Public.TicketSignerPublicKey {
		return errors.New("reviewed operator ticket public key differs from material")
	}
	defer func() {
		for _, body := range sources {
			clear(body)
		}
	}()
	directory := bootstrapstart.OperatorDirectory(record.Config.Cell)
	dir, err := c.openOperatorInstallDirectory(directory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	for _, name := range []string{"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem",
		"ca.pem", "ticket.pub", "operator-signing.key", "operator.json"} {
		if err := c.installOperatorExactFile(dir, name, sources[name]); err != nil {
			return err
		}
	}
	fmt.Fprintf(c.output, "operator material installed actor=%s config=%s/operator.json\n", cfg.Operator.Actor, directory)
	return nil
}

func (c command) openOperatorInstallDirectory(directory string) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return -1, err
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	for index, part := range parts {
		if err := c.ctx.Err(); err != nil {
			unix.Close(dir)
			return -1, err
		}
		if index == len(parts)-1 {
			if err := unix.Mkdirat(dir, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(dir)
				return -1, err
			}
		}
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return -1, err
		}
		dir = next
		var stat unix.Stat_t
		expectedMode := uint32(0o755)
		if index == len(parts)-1 {
			expectedMode = 0o700
		}
		if err := unix.Fstat(dir, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
			stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != expectedMode {
			unix.Close(dir)
			return -1, errors.New("operator install path ownership or mode is invalid")
		}
	}
	return dir, nil
}

func (c command) installOperatorExactFile(dir int, name string, wire []byte) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if name == "" || name != filepath.Base(name) || len(wire) == 0 {
		return errors.New("operator install file is invalid")
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Mode&0o777 != 0o600 ||
			stat.Size != int64(len(wire)) {
			return fmt.Errorf("operator file %s has wrong ownership, mode, or size", name)
		}
		stored, err := io.ReadAll(io.LimitReader(file, int64(len(wire))+1))
		if err != nil || !bytes.Equal(stored, wire) {
			return fmt.Errorf("operator file %s differs from reviewed exact bytes", name)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect operator file %s: %w", name, err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(nonce[:])
	fd, err = unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	if err := unix.Fchown(fd, 0, 0); err != nil {
		file.Close()
		return err
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		file.Close()
		return err
	}
	if count, err := file.Write(wire); err != nil || count != len(wire) {
		file.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("install operator file %s: %w", name, err)
	}
	return unix.Fsync(dir)
}
