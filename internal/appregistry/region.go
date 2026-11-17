package appregistry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
)

var regional sync.Map

func Namespace() (string, error) {
	data, err := m1.Files.ReadFile("registry.json")
	if err != nil {
		return "", err
	}
	var document struct{ Namespace string }
	if err := json.Unmarshal(data, &document); err != nil {
		return "", err
	}
	if !repositoryPath.MatchString(document.Namespace + "/terrascale/app-canary") {
		return "", errors.New("fleet OCIR namespace is unset or invalid")
	}
	return document.Namespace, nil
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
	namespace, err := Namespace()
	if err != nil {
		return nil, err
	}
	client := &Client{Host: strings.ToLower(entry.OCIRegionKey) + ".ocir.io", Namespace: namespace, Sign: func(request *http.Request) error {
		factory, err := ociclient.InstancePrincipalContext(request.Context(), entry.OCIRegion)
		if err != nil {
			return err
		}
		return common.DefaultRequestSigner(factory.Provider()).Sign(request)
	}}
	actual, _ := regional.LoadOrStore(label, client)
	return actual.(*Client), nil
}
