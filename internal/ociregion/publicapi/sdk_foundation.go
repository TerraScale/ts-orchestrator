package publicapi

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

// Retry identity binds the durable operation to the provider target and
// canonical mutation payload, including requests retried after process loss.
func retryToken(ctx context.Context, client *SDKClient, command sdkcli.Command) (*string, error) {
	flags := make(map[string]any, len(command.Flags))
	for key, value := range command.Flags {
		if key == "wait-for-state" {
			continue
		}
		flags[key] = value
		if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") {
			payload := jsontext.Value(value)
			if err := payload.Format(jsontext.ReorderRawObjects(true)); err != nil {
				return nil, fmt.Errorf("invalid OCI %s payload", key)
			}
			flags[key] = payload
		}
	}
	step, err := json.Marshal(map[string]any{"region": client.Region, "path": command.Path, "flags": flags}, json.Deterministic(true))
	if err != nil {
		return nil, errors.New("OCI retry identity is invalid")
	}
	return new(ociresource.RetryToken(ctx, string(step))), nil
}

func (c *SDKClient) identity() (identity.IdentityClient, error) {
	return c.reader.Factory().Identity()
}

func createCompartment(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "name", "description")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreateCompartment(ociclient.RequestContext(ctx), identity.CreateCompartmentRequest{OpcRetryToken: token,
		CreateCompartmentDetails: identity.CreateCompartmentDetails{FreeformTags: tags, CompartmentId: &values[0], Name: &values[1], Description: &values[2]}})
	return response.Compartment, err
}

func createDynamicGroup(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "name", "description", "matching-rule")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreateDynamicGroup(ociclient.RequestContext(ctx), identity.CreateDynamicGroupRequest{OpcRetryToken: token,
		CreateDynamicGroupDetails: identity.CreateDynamicGroupDetails{FreeformTags: tags, CompartmentId: &values[0], Name: &values[1], Description: &values[2], MatchingRule: &values[3]}})
	return response.DynamicGroup, err
}

func createPolicy(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "name", "description")
	if err != nil {
		return nil, err
	}
	var statements []string
	if err := jsonFlag(command, "statements", &statements); err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.identity()
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{OpcRetryToken: token,
		CreatePolicyDetails: identity.CreatePolicyDetails{FreeformTags: tags, CompartmentId: &values[0], Name: &values[1], Description: &values[2], Statements: statements}})
	return response.Policy, err
}

func createVCN(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "display-name", "cidr-block", "dns-label")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreateVcn(ociclient.RequestContext(ctx), core.CreateVcnRequest{OpcRetryToken: token, CreateVcnDetails: core.CreateVcnDetails{FreeformTags: tags,
		CompartmentId: &values[0], DisplayName: &values[1], CidrBlock: &values[2], DnsLabel: &values[3]}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: response.Id})
		return got.Vcn, string(got.LifecycleState), err
	})
}

func createServiceGateway(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "vcn-id", "display-name")
	if err != nil {
		return nil, err
	}
	var services []core.ServiceIdRequestDetails
	if err := jsonFlag(command, "services", &services); err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.network()
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreateServiceGateway(ociclient.RequestContext(ctx), core.CreateServiceGatewayRequest{OpcRetryToken: token,
		CreateServiceGatewayDetails: core.CreateServiceGatewayDetails{FreeformTags: tags, CompartmentId: &values[0], VcnId: &values[1], DisplayName: &values[2], Services: services}})
	if err != nil {
		return nil, err
	}
	return c.waitAvailable(ctx, command, func(ctx context.Context) (any, string, error) {
		got, err := client.GetServiceGateway(ociclient.RequestContext(ctx), core.GetServiceGatewayRequest{ServiceGatewayId: response.Id})
		return got.ServiceGateway, string(got.LifecycleState), err
	})
}

// createVault submits the vault; it is CREATING for minutes, so the caller
// waits for it to read back ACTIVE.
func createVault(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "display-name", "vault-type")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.reader.KMSVaults()
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreateVault(ociclient.RequestContext(ctx), keymanagement.CreateVaultRequest{OpcRetryToken: token, CreateVaultDetails: keymanagement.CreateVaultDetails{FreeformTags: tags,
		CompartmentId: &values[0], DisplayName: &values[1], VaultType: keymanagement.CreateVaultDetailsVaultTypeEnum(values[2])}})
	return response.Vault, err
}

func createKey(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "compartment-id", "display-name", "protection-mode", "endpoint")
	if err != nil {
		return nil, err
	}
	var shape keymanagement.KeyShape
	if err := jsonFlag(command, "key-shape", &shape); err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.reader.KMSManagement(values[3])
	if err != nil {
		return nil, err
	}
	token, err := retryToken(ctx, c, command)
	if err != nil {
		return nil, err
	}
	response, err := client.CreateKey(ociclient.RequestContext(ctx), keymanagement.CreateKeyRequest{OpcRetryToken: token, CreateKeyDetails: keymanagement.CreateKeyDetails{FreeformTags: tags,
		CompartmentId: &values[0], DisplayName: &values[1], KeyShape: &shape, ProtectionMode: keymanagement.CreateKeyDetailsProtectionModeEnum(values[2])}})
	return response.Key, err
}

func createBucket(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "namespace-name", "compartment-id", "name", "kms-key-id", "versioning", "public-access-type", "storage-tier")
	if err != nil {
		return nil, err
	}
	tags, err := optionalTags(command)
	if err != nil {
		return nil, err
	}
	client, err := c.reader.Factory().ObjectStorage()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateBucket(ociclient.RequestContext(ctx), objectstorage.CreateBucketRequest{NamespaceName: &values[0], CreateBucketDetails: objectstorage.CreateBucketDetails{FreeformTags: tags,
		CompartmentId: &values[1], Name: &values[2], KmsKeyId: &values[3], Versioning: objectstorage.CreateBucketDetailsVersioningEnum(values[4]),
		PublicAccessType: objectstorage.CreateBucketDetailsPublicAccessTypeEnum(values[5]), StorageTier: objectstorage.CreateBucketDetailsStorageTierEnum(values[6])}})
	return response.Bucket, err
}

func createRetentionRule(ctx context.Context, c *SDKClient, command sdkcli.Command) (any, error) {
	values, err := flags(command, "namespace-name", "bucket-name", "display-name", "time-amount", "time-unit")
	if err != nil {
		return nil, err
	}
	amount, err := strconv.ParseInt(values[3], 10, 64)
	if err != nil {
		return nil, err
	}
	client, err := c.reader.Factory().ObjectStorage()
	if err != nil {
		return nil, err
	}
	response, err := client.CreateRetentionRule(ociclient.RequestContext(ctx), objectstorage.CreateRetentionRuleRequest{NamespaceName: &values[0], BucketName: &values[1],
		CreateRetentionRuleDetails: objectstorage.CreateRetentionRuleDetails{DisplayName: &values[2],
			Duration: &objectstorage.Duration{TimeAmount: &amount, TimeUnit: objectstorage.DurationTimeUnitEnum(values[4])}}})
	return response.RetentionRule, err
}

// DecodeCreate checks a create command as its in-binary creator reads it,
// without calling OCI: the creator consumes every flag and each JSON flag
// decodes into its SDK type. The foundation's tests check its commands with
// it.
func DecodeCreate(args []string) error {
	command, err := sdkcli.Parse(args)
	if err != nil {
		return err
	}
	if _, ok := creators[command.Path]; !ok {
		return fmt.Errorf("%w: %s", sdkcli.ErrUnsupported, command.Path)
	}
	if extra := unacceptedCreateFlags(command); len(extra) > 0 {
		return fmt.Errorf("%s sends flags its creator does not consume: %v", command.Path, extra)
	}
	targets := map[string]any{}
	switch command.Path {
	case "iam policy create":
		targets["statements"] = &[]string{}
	case "network service-gateway create":
		targets["services"] = &[]core.ServiceIdRequestDetails{}
	case "kms management key create":
		targets["key-shape"] = &keymanagement.KeyShape{}
	case "network route-table create":
		targets["route-rules"] = &[]core.RouteRule{}
	case "network security-list create":
		targets["ingress-security-rules"], targets["egress-security-rules"] = &[]core.IngressSecurityRule{}, &[]core.EgressSecurityRule{}
	case "network subnet create":
		targets["security-list-ids"] = &[]string{}
	case "network nsg rules add":
		targets["security-rules"] = &[]core.AddSecurityRuleDetails{}
	case "network drg-route-distribution-statement add":
		targets["statements"] = &[]core.AddDrgRouteDistributionStatementDetails{}
	case "network drg-attachment create":
		targets["network-details"] = &drgNetwork{}
	case "network route-table update":
		targets["route-rules"] = &[]core.RouteRule{}
	case "network security-list update":
		targets["egress-security-rules"] = &[]core.EgressSecurityRule{}
	}
	for name, target := range targets {
		if err := jsonFlag(command, name, target); err != nil {
			return fmt.Errorf("%s: %w", command.Path, err)
		}
	}
	return nil
}
