package swarmruntime

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
)

func TestSecretFilesMapsFileKeysAndFailsOnMissing(t *testing.T) {
	refs := map[string]vaultsecret.Ref{"TERRABASE_MANAGEMENT_CREDENTIAL_FILE": {}}
	files, env, err := secretFiles(refs, map[string]string{"TERRABASE_MANAGEMENT_CREDENTIAL_FILE": "file"})
	if err != nil || string(files["terrabase_management_credential_file"]) != "file" || len(files) != 1 ||
		!slices.Equal(env, []string{"TERRABASE_MANAGEMENT_CREDENTIAL_FILE=" + ContainerMaterialDirectory + "/terrabase_management_credential_file"}) {
		t.Fatalf("files %d env %d: %v", len(files), len(env), err)
	}
	if _, _, err := secretFiles(refs, nil); err == nil || err.Error() != "Vault secret for TERRABASE_MANAGEMENT_CREDENTIAL_FILE is missing or empty" {
		t.Fatalf("missing secret error %v", err)
	}
	if _, _, err := secretFiles(map[string]vaultsecret.Ref{"PLAIN": {}}, map[string]string{"PLAIN": "x"}); err == nil {
		t.Fatal("plain env key accepted")
	}
}

// The executor resolves exactly terrascale.secret-refs and refuses keys that
// would reach the env or a path before it asks Vault.
func TestVaultSecretMountRequiresExactFileRefs(t *testing.T) {
	asked := false
	resolve := func(context.Context, string, map[string]vaultsecret.Ref) (map[string]string, error) {
		asked = true
		return nil, nil
	}
	ref := `{"vault":"ocid1.vault.oc1.sa-saopaulo-1.vault","name":"gru-1-ts-auth-master-key"}`
	for name, labels := range map[string]map[string]string{
		"no refs":      {LabelSecrets: "TS_AUTH_MASTER_KEY_FILE"},
		"keys differ":  {LabelSecrets: "TS_AUTH_MASTER_KEY_FILE", LabelSecretRefs: `{"OTHER_FILE":` + ref + `}`},
		"refs only":    {LabelSecretRefs: `{"TS_AUTH_MASTER_KEY_FILE":` + ref + `}`},
		"plain key":    {LabelSecrets: "TS_AUTH_MASTER_KEY", LabelSecretRefs: `{"TS_AUTH_MASTER_KEY":` + ref + `}`},
		"path key":     {LabelSecrets: "../X_FILE", LabelSecretRefs: `{"../X_FILE":` + ref + `}`},
		"invalid json": {LabelSecrets: "TS_AUTH_MASTER_KEY_FILE", LabelSecretRefs: `{`},
	} {
		labels[LabelServiceSpec] = "ts-auth"
		c := &controller{executor: &Executor{vaultSecrets: resolve}, task: &api.Task{ServiceAnnotations: api.Annotations{Labels: labels}}}
		if _, _, err := c.containerMaterialMount(t.Context()); err == nil || asked {
			t.Fatalf("%s: err=%v asked=%v", name, err, asked)
		}
	}
	var service string
	var got map[string]vaultsecret.Ref
	resolve = func(_ context.Context, s string, refs map[string]vaultsecret.Ref) (map[string]string, error) {
		service, got = s, refs
		return nil, os.ErrPermission
	}
	labels := map[string]string{LabelServiceSpec: "ts-auth", LabelSecrets: "TS_AUTH_MASTER_KEY_FILE", LabelSecretRefs: `{"TS_AUTH_MASTER_KEY_FILE":` + ref + `}`}
	c := &controller{executor: &Executor{vaultSecrets: resolve}, task: &api.Task{ServiceAnnotations: api.Annotations{Labels: labels}}}
	if _, _, err := c.containerMaterialMount(t.Context()); err == nil || service != "ts-auth" ||
		got["TS_AUTH_MASTER_KEY_FILE"] != (vaultsecret.Ref{Vault: "ocid1.vault.oc1.sa-saopaulo-1.vault", Name: "gru-1-ts-auth-master-key"}) || len(got) != 1 {
		t.Fatalf("resolved %s %v: %v", service, got, err)
	}
}

func TestOwnerOnlyDirectoryReassertsMode(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "task-secrets")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ownerOnlyDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v: %v", info.Mode(), err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if err := ownerOnlyDirectory(link); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlink accepted: %v", err)
	}
}
