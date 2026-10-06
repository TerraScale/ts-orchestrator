package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// SourceTreeDigest is the SHA-256 of `git archive` of commit in checkout:
// the source claim of a native service release (TerraBase, ts-auth), whose
// releases publish none. The operator's release commands and CI's
// service-deploy compute it the same way, whatever the local Git settings.
func SourceTreeDigest(ctx context.Context, checkout, commit string) (string, error) {
	if !ValidSourceRevision(commit) {
		return "", errors.New("--commit must be a full lowercase commit SHA")
	}
	// Archive from an empty repository that borrows the checkout's objects,
	// so no attributes from outside the commit (info/attributes,
	// core.attributesFile, the system file) apply, and pin the file modes.
	// No inherited GIT_* variable reaches git.
	env := []string{"GIT_ATTR_NOSYSTEM=1"}
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GIT_") {
			env = append(env, variable)
		}
	}
	git := func(args ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, "git", args...)
		command.Env = env
		return command
	}
	objects, err := git("-C", checkout, "rev-parse", "--path-format=absolute", "--git-path", "objects").Output()
	if err != nil {
		return "", fmt.Errorf("find the objects of %s: %w", checkout, err)
	}
	isolated, err := os.MkdirTemp("", "ts-source-tree-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(isolated)
	// The empty repository and its archive read no system or global
	// config (an init.templateDir could bring info/attributes) and no
	// template; reading the checkout may still need the user's safe.directory.
	isolate := func(command *exec.Cmd) *exec.Cmd {
		command.Env = append(command.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		return command
	}
	if out, err := isolate(git("init", "-q", "--bare", "--template=", isolated)).CombinedOutput(); err != nil {
		return "", fmt.Errorf("prepare the source archive: %w: %s", err, out)
	}
	command := isolate(git("--git-dir", isolated, "-c", "tar.umask=0002", "-c", "core.attributesFile=/dev/null",
		"archive", "--format=tar", commit+"^{commit}"))
	command.Env = append(command.Env, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+strings.TrimSpace(string(objects)))
	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := command.Start(); err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, stdout)
	if err := errors.Join(copyErr, command.Wait()); err != nil {
		return "", fmt.Errorf("archive source %s: %w", commit, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
