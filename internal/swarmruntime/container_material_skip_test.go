package swarmruntime

import (
	"errors"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestContainerMaterialSkipsTaskWithoutSecrets(t *testing.T) {
	c := &controller{executor: &Executor{}, task: &api.Task{}}
	if mounts, env, err := c.containerMaterialMount(t.Context()); err != nil || mounts != nil || env != nil {
		t.Fatalf("task without secrets: mounts=%v env=%v err=%v", mounts, env, err)
	}
	c.task.ServiceAnnotations.Labels = map[string]string{LabelSecrets: "VAULT_CANARY_FILE"}
	if _, _, err := c.containerMaterialMount(t.Context()); !errors.Is(err, ErrContainerMaterialPending) {
		t.Fatalf("task with secrets and no authority: err=%v, want pending", err)
	}
}
