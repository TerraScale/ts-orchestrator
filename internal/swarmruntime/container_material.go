package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	containerd "github.com/containerd/containerd/v2/client"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
)

const ContainerMaterialDirectory = "/run/ts-orch/secrets"

var ErrContainerMaterialPending = errors.New("current signed container material is pending")

// ContainerTaskBinding contains lookup selectors, never authority or Vault refs.
type ContainerTaskBinding struct {
	TaskID, ServiceID, NodeID, InstanceID, Region, HostID, Fingerprint string
}

// ContainerMaterial comes from the current signed profile and recipient verifier.
// FileEnvironment maps exact signed *_FILE keys to their lowercase basenames.
// ExpiresAt bounds delivery admission; CredentialExpiresAt is actual secret expiry.
// Renewal replaces a task; files never change within the same task identity.
type ContainerMaterial struct {
	Binding             ContainerTaskBinding
	ExpiresAt           time.Time
	CredentialExpiresAt time.Time
	User                string
	Files               map[string][]byte
	FileEnvironment     map[string]string
}

// ContainerMaterialProvider verifies the current upstream task, signed intent,
// root-signed profile and fresh recipient grant independently. Empty files attest
// a verified no-secret profile; absent material never means an empty profile.
type ContainerMaterialProvider interface {
	CurrentContainerMaterial(context.Context, ContainerTaskBinding) (ContainerMaterial, error)
}

func (e *Executor) BindContainerMaterial(admitted Admission, provider ContainerMaterialProvider) error {
	if admitted.Role != "manager" && admitted.Role != "container" || admitted.InstanceID == "" || !intentName.MatchString(admitted.Region) || admitted.HostID == "" || provider == nil {
		return errors.New("container material requires a verified host and current signed profile verifier")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.containerMaterial != nil {
		return errors.New("container material authority is immutable")
	}
	e.containerIdentity = ContainerTaskBinding{InstanceID: admitted.InstanceID, Region: admitted.Region, HostID: admitted.HostID}
	e.containerMaterial = provider
	return nil
}

// TaskSecretDirectory holds each task's Vault secret files on tmpfs.
const TaskSecretDirectory = "/run/ts-orch/task-secrets"

// SecretResolver returns the current value of each of service's refs after
// checking that the service may read them. Errors name keys or secrets, never values.
type SecretResolver func(ctx context.Context, service string, refs map[string]vaultsecret.Ref) (map[string]string, error)

// BindVaultSecrets makes every task start read the secrets its service spec
// names, so a rotated secret reaches the next start. It replaces signed
// container material and is meant for the single host.
func (e *Executor) BindVaultSecrets(resolve SecretResolver) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if resolve == nil || e.containerMaterial != nil || e.vaultSecrets != nil {
		return errors.New("container material authority is immutable")
	}
	e.vaultSecrets = resolve
	return nil
}

func (c *controller) containerMaterialPath() string {
	if c.executor.vaultSecrets != nil {
		return filepath.Join(TaskSecretDirectory, c.id)
	}
	return filepath.Join(filepath.Dir(c.executor.logRoot), "container-material", c.id)
}

func (c *controller) containerMaterialMount(ctx context.Context) ([]runtimespec.Mount, []string, error) {
	e := c.executor
	if c.stateful != nil {
		return nil, nil, nil // The held stateful Source owns its exact process and material mounts.
	}
	if c.task.ServiceAnnotations.Labels[LabelRole] == "function-worker" {
		return nil, nil, nil // The dedicated function verifier owns this task's material.
	}
	if labels := c.task.ServiceAnnotations.Labels; e.containerMaterial == nil && labels[LabelSecrets] == "" && labels[LabelSecretRefs] == "" {
		// shortcut: no signed-material authority and no named secrets means nothing to deliver; drop once every host binds one.
		return nil, nil, nil
	}
	if e.vaultSecrets != nil {
		return c.vaultSecretMount(ctx)
	}
	if e.containerMaterial == nil || e.functionNodeID == "" || c.task.NodeID != e.functionNodeID {
		return nil, nil, ErrContainerMaterialPending
	}
	binding := e.containerIdentity
	binding.TaskID, binding.ServiceID, binding.NodeID, binding.Fingerprint = c.task.ID, c.task.ServiceID, e.functionNodeID, c.fingerprint
	material, err := e.containerMaterial.CurrentContainerMaterial(ctx, binding)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve current signed container material: %w", err)
	}
	if material.Binding != binding || !material.ExpiresAt.After(time.Now()) || material.User != c.spec.User {
		return nil, nil, fmt.Errorf("%w: material does not bind this current task, user and host", ErrContainerMaterialPending)
	}
	if !material.CredentialExpiresAt.IsZero() && (!material.CredentialExpiresAt.After(time.Now()) || len(material.Files) == 0) {
		return nil, nil, fmt.Errorf("%w: credential expiry is invalid", ErrContainerMaterialPending)
	}
	c.credentialExpiresAt = material.CredentialExpiresAt
	if len(material.Files) != len(material.FileEnvironment) || len(material.Files) > 64 {
		return nil, nil, errors.New("container material file mapping is incomplete")
	}
	var environment []string
	total := 0
	for key, name := range material.FileEnvironment {
		if !strings.HasSuffix(key, "_FILE") || len(key) <= len("_FILE") || len(key) > 128 || strings.IndexFunc(key, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
		}) >= 0 || key[0] < 'A' || key[0] > 'Z' || name != strings.ToLower(key) {
			return nil, nil, errors.New("container material requires exact signed file keys")
		}
		value := material.Files[name]
		if len(value) == 0 || len(value) > 64<<10 {
			return nil, nil, fmt.Errorf("invalid container material file %s", name)
		}
		total += len(value)
		path := ContainerMaterialDirectory + "/" + name
		for _, entry := range c.spec.Env {
			if entryKey, entryValue, _ := strings.Cut(entry, "="); entryKey == key && entryValue != path {
				return nil, nil, errors.New("task environment conflicts with signed secret file mapping")
			}
		}
		environment = append(environment, key+"="+path)
	}
	if total > 96<<10 {
		return nil, nil, errors.New("container material exceeds task bound")
	}
	if len(material.Files) == 0 {
		if _, err := os.Lstat(c.containerMaterialPath()); err == nil || !errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("existing container material conflicts with no-secret profile")
		}
		return nil, nil, nil
	}
	slices.Sort(environment)
	uid, gid, _ := strings.Cut(material.User, ":")
	u, _ := strconv.ParseUint(uid, 10, 32)
	g, _ := strconv.ParseUint(gid, 10, 32)
	if err := stageTaskMaterial(c.containerMaterialPath(), material.Files, uint32(u), uint32(g)); err != nil {
		return nil, nil, err
	}
	if !material.ExpiresAt.After(time.Now()) {
		return nil, nil, fmt.Errorf("%w: grant expired during preparation", ErrContainerMaterialPending)
	}
	return []runtimespec.Mount{{Destination: ContainerMaterialDirectory, Type: "bind", Source: c.containerMaterialPath(), Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}}}, environment, nil
}

func (c *controller) verifyContainerMaterial(ctx context.Context, ctr containerd.Container, mounts []runtimespec.Mount, environment []string) error {
	if c.stateful != nil {
		return nil // Its independently qualified full spec is verified by the stateful route.
	}
	if err := verifyTaskMaterialMount(ctx, ctr, ContainerMaterialDirectory, mounts); err != nil {
		return err
	}
	labels, err := ctr.Labels(ctx)
	if err != nil {
		return err
	}
	if labels[credentialExpiryLabel] != c.credentialExpiryLabel() {
		return errors.New("credential expiry changed for existing task; replace the task")
	}
	if len(environment) == 0 {
		return nil
	}
	spec, err := ctr.Spec(ctx)
	if err != nil {
		return err
	}
	if spec.Process == nil {
		return errors.New("container process is absent")
	}
	for _, expected := range environment {
		key, _, _ := strings.Cut(expected, "=")
		count := 0
		for _, actual := range spec.Process.Env {
			if actualKey, _, _ := strings.Cut(actual, "="); actualKey == key {
				if actual != expected {
					return errors.New("container environment conflicts with signed secret file mapping")
				}
				count++
			}
		}
		if count != 1 {
			return errors.New("container lacks exact signed secret file environment")
		}
	}
	return nil
}

// vaultSecretMount resolves exactly the spec's secret refs at this start. Each
// *_FILE key's value is a read-only file on tmpfs and the key is set to its
// in-container path; a plain key would put the value in the OCI spec env.
func (c *controller) vaultSecretMount(ctx context.Context) ([]runtimespec.Mount, []string, error) {
	labels := c.task.ServiceAnnotations.Labels
	if labels[LabelSecrets] == "" && labels[LabelSecretRefs] == "" {
		return nil, nil, nil
	}
	var refs map[string]vaultsecret.Ref
	if err := json.Unmarshal([]byte(labels[LabelSecretRefs]), &refs); err != nil ||
		!slices.Equal(slices.Sorted(maps.Keys(refs)), slices.Sorted(slices.Values(strings.Split(labels[LabelSecrets], ",")))) {
		return nil, nil, fmt.Errorf("service %s needs %s naming exactly its %s", labels[LabelServiceSpec], LabelSecretRefs, LabelSecrets)
	}
	for key := range refs {
		if !secretName.MatchString(key) || !vaultsecret.FileKey(key) {
			return nil, nil, fmt.Errorf("Vault secret key %q must match %s and end in _FILE", key, secretName)
		}
	}
	values, err := c.executor.vaultSecrets(ctx, labels[LabelServiceSpec], refs)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve Vault secrets: %w", err)
	}
	files, environment, err := secretFiles(refs, values)
	clear(values)
	if err != nil {
		return nil, nil, err
	}
	uid, gid, _ := strings.Cut(c.spec.User, ":")
	u, uErr := strconv.ParseUint(uid, 10, 32)
	g, gErr := strconv.ParseUint(gid, 10, 32)
	if uErr != nil || gErr != nil {
		return nil, nil, errors.New("Vault secrets need a numeric uid:gid container user")
	}
	if err := ownerOnlyDirectory(TaskSecretDirectory); err != nil {
		return nil, nil, err
	}
	if err := vaultsecret.RequireMemoryFilesystem(TaskSecretDirectory); err != nil {
		return nil, nil, err
	}
	if err := stageTaskMaterial(c.containerMaterialPath(), files, uint32(u), uint32(g)); err != nil {
		return nil, nil, err
	}
	return []runtimespec.Mount{{Destination: ContainerMaterialDirectory, Type: "bind", Source: c.containerMaterialPath(), Options: []string{"bind", "ro", "nosuid", "nodev", "noexec"}}}, environment, nil
}

// ownerOnlyDirectory creates directory if needed and re-asserts that it is a
// real directory owned by this process with mode 0700, whatever made it.
func ownerOnlyDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", directory)
	}
	return errors.Join(os.Chown(directory, os.Geteuid(), os.Getegid()), os.Chmod(directory, 0o700))
}

// secretFiles maps resolved *_FILE secrets to files (by lowercase key) and
// sorted env entries holding their paths; a key the resolver did not return
// fails the start.
func secretFiles(refs map[string]vaultsecret.Ref, values map[string]string) (map[string][]byte, []string, error) {
	files := map[string][]byte{}
	var environment []string
	for key := range refs {
		value, ok := values[key]
		if !ok || value == "" {
			return nil, nil, fmt.Errorf("Vault secret for %s is missing or empty", key)
		}
		if !vaultsecret.FileKey(key) {
			return nil, nil, fmt.Errorf("Vault secret %s must be a _FILE key", key)
		}
		name := strings.ToLower(key)
		files[name] = []byte(value)
		environment = append(environment, key+"="+ContainerMaterialDirectory+"/"+name)
	}
	slices.Sort(environment)
	return files, environment, nil
}
