package publicapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func natGatewayRequest(command sdkcli.Command) (core.CreateNatGatewayRequest, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name")
	if err != nil {
		return core.CreateNatGatewayRequest{}, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return core.CreateNatGatewayRequest{}, err
	}
	return core.CreateNatGatewayRequest{CreateNatGatewayDetails: core.CreateNatGatewayDetails{
		CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2], BlockTraffic: new(false), FreeformTags: tags}}, nil
}

func natGatewayIdentity(ctx context.Context, region string, command sdkcli.Command) (digest, token string, err error) {
	request, err := natGatewayRequest(command)
	if err != nil {
		return "", "", err
	}
	wire, err := request.HTTPRequest("POST", "/", nil, nil)
	if err != nil {
		return "", "", err
	}
	defer wire.Body.Close()
	body, err := io.ReadAll(wire.Body)
	if err != nil {
		return "", "", err
	}
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		return "", "", err
	}
	body, err = json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(body)
	digest = hex.EncodeToString(sum[:])
	return digest, ociresource.RetryToken(ctx, region+"/nat_gateway/"+digest), nil
}

func createNatGateway(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	request, err := natGatewayRequest(command)
	if err != nil {
		return nil, err
	}
	_, token, err := natGatewayIdentity(ctx, c.Region, command)
	if err != nil {
		return nil, err
	}
	request.OpcRetryToken = new(token)
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateNatGateway(ociclient.RequestContext(ctx), request)
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetNatGateway(ociclient.RequestContext(ctx), core.GetNatGatewayRequest{NatGatewayId: response.Id})
		return got.NatGateway, string(got.LifecycleState), err
	})
}
