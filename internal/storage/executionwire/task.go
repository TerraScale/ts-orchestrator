package executionwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"github.com/moby/swarmkit/v2/api"
)

var ErrInvalid = errors.New("invalid runtime task identity")

// TaskSHA256 binds the assignment and complete spec, including both label sets.
func TaskSHA256(task *api.Task) (string, error) {
	if task == nil || task.ID == "" || task.ServiceID == "" || task.NodeID == "" {
		return "", ErrInvalid
	}
	data, err := json.Marshal(struct {
		ID, ServiceID, NodeID           string
		Spec                            api.TaskSpec
		Annotations, ServiceAnnotations api.Annotations
	}{task.ID, task.ServiceID, task.NodeID, task.Spec, task.Annotations, task.ServiceAnnotations}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
