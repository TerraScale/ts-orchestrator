package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const FunctionMaterialDirectory = "/run/ts-orch/function"

// FunctionTaskBinding contains selectors, never authority or secret references.
type FunctionTaskBinding struct {
	TaskID, ServiceID, NodeID, InstanceID, Region, HostID, Fingerprint string
}

// FunctionMaterial is returned only by the trusted current-intent/Vault verifier.
// Files must remain immutable for the binding's lifetime; renewal replaces a task.
type FunctionMaterial struct {
	Binding   FunctionTaskBinding
	ExpiresAt time.Time
	Files     map[string][]byte
}

// FunctionMaterialProvider independently verifies current function intent, the
// assigned task, admitted recipient host and narrowly issued credentials. Task
// labels and fields are lookup hints and must never authorize credentials.
type FunctionMaterialProvider interface {
	CurrentFunctionMaterial(context.Context, FunctionTaskBinding) (FunctionMaterial, error)
}

// BindFunctionMaterial installs a trusted admission dependency on a dedicated
// function host. Admission comes from the verified host bootstrap, not a task.
func (e *Executor) BindFunctionMaterial(admitted Admission, provider FunctionMaterialProvider) error {
	if admitted.Role != "wasm" || admitted.InstanceID == "" || !intentName.MatchString(admitted.Region) || admitted.HostID == "" || provider == nil {
		return errors.New("function material requires a verified dedicated function host and current grant verifier")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.functionMaterial != nil {
		return errors.New("function host material authority is immutable")
	}
	e.functionIdentity = FunctionTaskBinding{InstanceID: admitted.InstanceID, Region: admitted.Region, HostID: admitted.HostID}
	e.functionMaterial = provider
	return nil
}

func (c *controller) functionMaterialPath() string {
	return filepath.Join(filepath.Dir(c.executor.logRoot), "function-material", c.id)
}

func (c *controller) functionMaterialMount(ctx context.Context) ([]runtimespec.Mount, error) {
	e := c.executor
	function := c.task.ServiceAnnotations.Labels[LabelRole] == "function-worker"
	if !function {
		if e.functionMaterial != nil {
			return nil, errors.New("dedicated function hosts refuse platform containers")
		}
		return nil, nil
	}
	if e.functionMaterial == nil || e.functionNodeID == "" || c.task.NodeID != e.functionNodeID || c.spec.User != "65532:65532" {
		return nil, errors.New("function task lacks current local host admission and material authority")
	}
	binding := e.functionIdentity
	binding.TaskID, binding.ServiceID, binding.NodeID, binding.Fingerprint = c.task.ID, c.task.ServiceID, e.functionNodeID, c.fingerprint
	material, err := e.functionMaterial.CurrentFunctionMaterial(ctx, binding)
	if err != nil {
		return nil, fmt.Errorf("resolve current function material: %w", err)
	}
	if material.Binding != binding || !material.ExpiresAt.After(time.Now()) {
		return nil, errors.New("function material does not bind this current task and host")
	}
	if err := c.stageFunctionMaterial(material.Files); err != nil {
		return nil, err
	}
	if !material.ExpiresAt.After(time.Now()) {
		return nil, errors.New("function material expired during preparation")
	}
	return []runtimespec.Mount{{Destination: FunctionMaterialDirectory, Type: "bind", Source: c.functionMaterialPath(), Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}}}, nil
}

var functionMaterialLimits = map[string]int{
	"deployment.json": 16 << 10, "module.wasm": 8 << 20, "receipt.json": 64 << 10,
	"delegation.json": 64 << 10, "root.pub": 32, "ingress-cert.pem": 64 << 10,
	"ingress-key.pem": 64 << 10, "ingress-ca.pem": 64 << 10, "broker-ca.pem": 64 << 10, "broker.creds": 64 << 10,
}

func (c *controller) stageFunctionMaterial(input map[string][]byte) error {
	if len(input) != len(functionMaterialLimits) {
		return errors.New("function material file set is incomplete")
	}
	files := make(map[string][]byte, len(input))
	defer func() {
		for _, value := range files {
			clear(value)
		}
	}()
	for name, limit := range functionMaterialLimits {
		value := input[name]
		if len(value) == 0 || len(value) > limit || name == "root.pub" && len(value) != 32 {
			return fmt.Errorf("invalid function material %s", name)
		}
		files[name] = slices.Clone(value)
	}
	destination := c.functionMaterialPath()
	if _, err := os.Lstat(destination); err == nil {
		return verifyFunctionMaterial(destination, files)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".material-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	for name, value := range files {
		f, err := os.OpenFile(filepath.Join(temporary, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(value)
		err = errors.Join(writeErr, f.Chown(65532, 65532), f.Sync(), f.Close())
		if err != nil {
			return err
		}
	}
	if err := os.Chown(temporary, 65532, 65532); err != nil {
		return err
	}
	if err := syncMaterialDirectory(temporary); err != nil {
		return err
	}
	// Never replace another process's immutable task material.
	if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return verifyFunctionMaterial(destination, files)
		}
		return err
	}
	return syncMaterialDirectory(parent)
}

func verifyFunctionMaterial(destination string, files map[string][]byte) error {
	info, err := os.Lstat(destination)
	if err != nil || !ownedFunctionMaterial(info, true) {
		return errors.New("function material path is not an owned private directory")
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := os.ReadDir(destination)
	if err != nil {
		return err
	}
	if len(entries) != len(files) {
		return errors.New("function material directory has unexpected entries")
	}
	for name, expected := range files {
		info, err := root.Lstat(name)
		if err != nil || !ownedFunctionMaterial(info, false) || info.Size() != int64(len(expected)) {
			return fmt.Errorf("unsafe existing function material %s", name)
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		actual, readErr := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
		err = errors.Join(readErr, f.Close())
		equal := bytes.Equal(actual, expected)
		clear(actual)
		if err != nil {
			return err
		}
		if !equal {
			return errors.New("function material changed for an existing task; replace the task")
		}
	}
	return nil
}

func ownedFunctionMaterial(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == 65532 && owner.Gid == 65532 && (directory && info.IsDir() || !directory && info.Mode().IsRegular())
}

func syncMaterialDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func (c *controller) verifyFunctionMount(ctx context.Context, ctr containerd.Container, expected []runtimespec.Mount) error {
	spec, err := ctr.Spec(ctx)
	if err != nil {
		return err
	}
	var actual []runtimespec.Mount
	for _, mount := range spec.Mounts {
		if mount.Destination == FunctionMaterialDirectory {
			actual = append(actual, mount)
		}
	}
	if len(actual) != len(expected) {
		return errors.New("container function material mount conflicts with task")
	}
	if len(actual) != 0 && (actual[0].Source != expected[0].Source || actual[0].Type != expected[0].Type || !slices.Equal(actual[0].Options, expected[0].Options)) {
		return errors.New("container function material mount conflicts with task")
	}
	return nil
}
