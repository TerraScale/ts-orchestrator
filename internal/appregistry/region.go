package appregistry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
)

var regional sync.Map

type Configuration struct {
	Namespace string
	Prefix    string
}

func ConfigurationFor(label string) (Configuration, error) {
	data, err := m1.Files.ReadFile("registry.json")
	if err != nil {
		return Configuration{}, err
	}
	var document map[string]struct {
		Namespace string
		Prefix    string `json:"repo_prefix"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return Configuration{}, err
	}
	environment := "prod"
	if label == fleet.Embedded().Staging.Label {
		environment = "stg"
	}
	item, ok := document[environment]
	if !ok || !repositoryPath.MatchString(item.Namespace+"/"+item.Prefix+"/app-canary") {
		return Configuration{}, errors.New("fleet OCIR namespace or repository prefix is unset or invalid")
	}
	return Configuration{Namespace: item.Namespace, Prefix: item.Prefix}, nil
}

func Regional(ctx context.Context, label string) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if value, ok := regional.Load(label); ok {
		return value.(*Client), nil
	}
	entry, ok := catalog.LookupName(label)
	if !ok {
		return nil, errors.New("app registry requires the host region")
	}
	configuration, err := ConfigurationFor(label)
	if err != nil {
		return nil, err
	}
	client := &Client{Host: entry.OCIRegion + ".ocir.io", Namespace: configuration.Namespace, Prefix: configuration.Prefix, Sign: func(request *http.Request) error {
		factory, err := ociclient.InstancePrincipalContext(request.Context(), entry.OCIRegion)
		if err != nil {
			return err
		}
		return common.DefaultRequestSigner(factory.Provider()).Sign(request)
	}}
	actual, _ := regional.LoadOrStore(label, client)
	return actual.(*Client), nil
}
