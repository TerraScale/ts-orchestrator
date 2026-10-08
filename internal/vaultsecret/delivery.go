package vaultsecret

import (
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/sdnotify"
)

// Deliver publishes named secrets only to a private memory-backed directory.
// A file's path stays stable; its bytes change atomically on a new CURRENT
// version. Services reopen it to pick up rotation without a redeploy.
func Deliver(ctx context.Context, cell, service, refsFile, directory string,
	interval time.Duration, once, fileNames bool, output io.Writer,
) error {
	file, err := os.Open(refsFile)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 32<<10+1))
	if err != nil || len(data) > 32<<10 {
		return errors.New("Vault references exceed 32 KiB or could not be read")
	}
	var refs map[string]Ref
	if err := json.Unmarshal(data, &refs, json.RejectUnknownMembers(true)); err != nil {
		return errors.New("Vault references must be a JSON map of keys to {vault, name}")
	}
	if len(refs) == 0 {
		return errors.New("Vault delivery needs at least one reference")
	}
	refs, names, err := deliveryNames(cell, service, refs, fileNames)
	if err != nil {
		return err
	}
	root, err := openMemoryDirectory(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	notifier := sdnotify.FromEnvironment()
	ready := false
	apply := func(snapshot map[string]Current) error {
		for key, secret := range snapshot {
			if err := writeMemoryFile(root, names[key], []byte(secret.Value())); err != nil {
				return err
			}
		}
		// Current's formatting and JSON contain OCIDs and versions only.
		if err := printLine(output, map[string]any{"directory": directory, "versions": snapshot}); err != nil {
			return err
		}
		if !ready {
			if err := notifier.Ready("Vault secrets delivered"); err != nil {
				return err
			}
			ready = true
		}
		return nil
	}
	if once {
		readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		snapshot, err := ReadCurrentRefs(readCtx, refs)
		if err != nil {
			return err
		}
		if err := apply(snapshot); err != nil {
			return errors.New("apply Vault secret snapshot failed")
		}
		return nil
	}
	return Watch(ctx, refs, interval, apply, func(err error) {
		// Values remain in memory during an outage; the next poll retries.
		_, _ = fmt.Fprintln(output, err)
	})
}

var deliveryFileRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// Existing signed controller paths keep their exact filenames. Only the
// keys change here; their regional service namespace remains validated.
func deliveryNames(cell, service string, refs map[string]Ref, fileNames bool) (map[string]Ref, map[string]string, error) {
	resolved, names := map[string]Ref{}, map[string]string{}
	for key, ref := range refs {
		alias, name := key, strings.ToLower(key)
		if fileNames {
			if !deliveryFileRE.MatchString(key) {
				return nil, nil, errors.New("Vault delivery requires simple lowercase filenames")
			}
			alias, name = fmt.Sprintf("FILE_%d_FILE", len(resolved)), key
		}
		resolved[alias], names[alias] = ref, name
	}
	if err := ValidateDeliveryRefs(cell, service, resolved, nil); err != nil {
		return nil, nil, err
	}
	return resolved, names, nil
}

func writeMemoryFile(root *os.Root, name string, data []byte) error {
	defer clear(data)
	if filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("Vault delivery requires a simple file name")
	}
	// The directory's ownership prevents another UID from changing this
	// temporary name; O_EXCL also refuses an existing file or symlink.
	temporary := "." + name + ".pending-" + rand.Text()
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return root.Rename(temporary, name)
}
