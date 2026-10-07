package publicapi

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

// The writes of `ts-orch oci-region peer` (TS-668), and the two reads whose
// ETag guards a route table's or security list's full-list update.
func init() {
	for path, c := range map[string]struct {
		create creator
		flags  []string
	}{
		"network drg create":                           {createDRG, []string{"compartment-id", "display-name", "wait-for-state"}},
		"network remote-peering-connection create":     {createRPC, []string{"compartment-id", "drg-id", "display-name", "wait-for-state"}},
		"network remote-peering-connection connect":    {connectRPC, []string{"remote-peering-connection-id", "peer-id", "peer-region-name"}},
		"network drg-route-distribution create":        {createDRGDistribution, []string{"drg-id", "distribution-type", "display-name", "wait-for-state"}},
		"network drg-route-distribution-statement add": {addDRGStatements, []string{"route-distribution-id", "statements"}},
		"network drg-route-table create":               {createDRGRouteTable, []string{"drg-id", "display-name", "import-route-distribution-id", "is-ecmp-enabled", "wait-for-state"}},
		"network drg-attachment create":                {createDRGAttachment, []string{"drg-id", "display-name", "network-details", "drg-route-table-id", "wait-for-state"}},
		"network drg-attachment update":                {updateDRGAttachment, []string{"drg-attachment-id", "drg-route-table-id"}},
		"network route-table get":                      {getRouteTable, []string{"rt-id"}},
		"network route-table update":                   {updateRouteTable, []string{"rt-id", "route-rules", "if-match"}},
		"network security-list get":                    {getSecurityList, []string{"security-list-id"}},
		"network security-list update":                 {updateSecurityList, []string{"security-list-id", "egress-security-rules", "if-match"}},
	} {
		creators[path], createFlags[path] = c.create, c.flags
	}
}

// tagged is a response the oci CLI prints with its ETag beside the data.
type tagged struct {
	value any
	etag  *string
}

// drgNetwork is a DRG attachment's --network-details; only a VCN is attached.
type drgNetwork struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func createDRG(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "display-name")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateDrg(ctx, core.CreateDrgRequest{OpcRetryToken: retryToken(),
		CreateDrgDetails: core.CreateDrgDetails{CompartmentId: &values[0], DisplayName: &values[1]}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetDrg(ctx, core.GetDrgRequest{DrgId: response.Id})
		return got.Drg, string(got.LifecycleState), err
	})
}

func createRPC(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "drg-id", "display-name")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateRemotePeeringConnection(ctx, core.CreateRemotePeeringConnectionRequest{OpcRetryToken: retryToken(),
		CreateRemotePeeringConnectionDetails: core.CreateRemotePeeringConnectionDetails{CompartmentId: &values[0], DrgId: &values[1], DisplayName: &values[2]}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetRemotePeeringConnection(ctx, core.GetRemotePeeringConnectionRequest{RemotePeeringConnectionId: response.Id})
		return got.RemotePeeringConnection, string(got.LifecycleState), err
	})
}

func connectRPC(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "remote-peering-connection-id", "peer-id", "peer-region-name")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	_, err = client.ConnectRemotePeeringConnections(ctx, core.ConnectRemotePeeringConnectionsRequest{RemotePeeringConnectionId: &values[0],
		ConnectRemotePeeringConnectionsDetails: core.ConnectRemotePeeringConnectionsDetails{PeerId: &values[1], PeerRegionName: &values[2]}})
	return map[string]any{}, err
}

func createDRGDistribution(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "drg-id", "distribution-type", "display-name")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateDrgRouteDistribution(ctx, core.CreateDrgRouteDistributionRequest{OpcRetryToken: retryToken(),
		CreateDrgRouteDistributionDetails: core.CreateDrgRouteDistributionDetails{DrgId: &values[0],
			DistributionType: core.CreateDrgRouteDistributionDetailsDistributionTypeEnum(values[1]), DisplayName: &values[2]}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetDrgRouteDistribution(ctx, core.GetDrgRouteDistributionRequest{DrgRouteDistributionId: response.Id})
		return got.DrgRouteDistribution, string(got.LifecycleState), err
	})
}

func addDRGStatements(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "route-distribution-id")
	if err != nil {
		return nil, err
	}
	var statements []core.AddDrgRouteDistributionStatementDetails
	if err := jsonFlag(command, "statements", &statements); err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.AddDrgRouteDistributionStatements(ctx, core.AddDrgRouteDistributionStatementsRequest{DrgRouteDistributionId: &values[0],
		AddDrgRouteDistributionStatementsDetails: core.AddDrgRouteDistributionStatementsDetails{Statements: statements}})
	return response.Items, err
}

func createDRGRouteTable(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "drg-id", "display-name", "import-route-distribution-id")
	if err != nil {
		return nil, err
	}
	ecmp, err := boolFlag(command, "is-ecmp-enabled")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateDrgRouteTable(ctx, core.CreateDrgRouteTableRequest{OpcRetryToken: retryToken(),
		CreateDrgRouteTableDetails: core.CreateDrgRouteTableDetails{DrgId: &values[0], DisplayName: &values[1], ImportDrgRouteDistributionId: &values[2], IsEcmpEnabled: ecmp}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetDrgRouteTable(ctx, core.GetDrgRouteTableRequest{DrgRouteTableId: response.Id})
		return got.DrgRouteTable, string(got.LifecycleState), err
	})
}

func createDRGAttachment(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "drg-id", "display-name", "drg-route-table-id")
	if err != nil {
		return nil, err
	}
	var network drgNetwork
	if err := jsonFlag(command, "network-details", &network); err != nil {
		return nil, err
	}
	if network.Type != "VCN" || network.ID == "" {
		return nil, errors.New("--network-details must name a VCN")
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateDrgAttachment(ctx, core.CreateDrgAttachmentRequest{OpcRetryToken: retryToken(),
		CreateDrgAttachmentDetails: core.CreateDrgAttachmentDetails{DrgId: &values[0], DisplayName: &values[1], DrgRouteTableId: &values[2],
			NetworkDetails: core.VcnDrgAttachmentNetworkCreateDetails{Id: &network.ID}}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetDrgAttachment(ctx, core.GetDrgAttachmentRequest{DrgAttachmentId: response.Id})
		return got.DrgAttachment, string(got.LifecycleState), err
	})
}

// updateDRGAttachment only assigns the attachment's DRG route table.
func updateDRGAttachment(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "drg-attachment-id", "drg-route-table-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateDrgAttachment(ctx, core.UpdateDrgAttachmentRequest{DrgAttachmentId: &values[0],
		UpdateDrgAttachmentDetails: core.UpdateDrgAttachmentDetails{DrgRouteTableId: &values[1]}})
	return response.DrgAttachment, err
}

func getRouteTable(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "rt-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: &values[0]})
	return tagged{response.RouteTable, response.Etag}, err
}

func getSecurityList(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "security-list-id")
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: &values[0]})
	return tagged{response.SecurityList, response.Etag}, err
}

// updateRouteTable replaces the table's rules only if it is unchanged since
// the read that gave --if-match.
func updateRouteTable(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "rt-id", "if-match")
	if err != nil {
		return nil, err
	}
	var rules []core.RouteRule
	if err := jsonFlag(command, "route-rules", &rules); err != nil || len(rules) == 0 {
		return nil, errors.Join(err, errors.New("--route-rules must list the table's rules"))
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateRouteTable(ctx, core.UpdateRouteTableRequest{RtId: &values[0], IfMatch: &values[1],
		UpdateRouteTableDetails: core.UpdateRouteTableDetails{RouteRules: rules}})
	return response.RouteTable, err
}

// updateSecurityList replaces the list's egress rules, leaving its ingress
// rules, only if it is unchanged since the read that gave --if-match.
func updateSecurityList(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "security-list-id", "if-match")
	if err != nil {
		return nil, err
	}
	var egress []core.EgressSecurityRule
	if err := jsonFlag(command, "egress-security-rules", &egress); err != nil || len(egress) == 0 {
		return nil, errors.Join(err, errors.New("--egress-security-rules must list the list's egress rules"))
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	response, err := client.UpdateSecurityList(ctx, core.UpdateSecurityListRequest{SecurityListId: &values[0], IfMatch: &values[1],
		UpdateSecurityListDetails: core.UpdateSecurityListDetails{EgressSecurityRules: egress}})
	return response.SecurityList, err
}
