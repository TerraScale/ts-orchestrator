package edge

import (
	"encoding/json/v2"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
)

const RequestProofKey = "TERRABASE_PEER_SECRET_FILE"

func RequestProofRef(services []*api.Service, last string) (string, error) {
	for _, svc := range services {
		labels := svc.Spec.Annotations.Labels
		if labels[swarmruntime.LabelServiceSpec] != "terrabase" {
			continue
		}
		var refs map[string]vaultsecret.Ref
		if json.Unmarshal([]byte(labels[swarmruntime.LabelSecretRefs]), &refs) != nil {
			return last, errors.New("invalid TerraBase secret references for request proof; the last good reference stays")
		}
		ref, ok := refs[RequestProofKey]
		if !ok {
			return "", nil
		}
		data, err := json.Marshal(ref)
		if err != nil {
			return last, err
		}
		return string(data), nil
	}
	return "", nil
}
