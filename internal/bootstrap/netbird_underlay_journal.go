package bootstrap

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var netBirdUnderlaySteps = []string{"manager_gateway", "writer_gateway", "connect", "manager_route", "writer_route", "writer_security"}

// NetBirdUnderlayRecord is a single immutable original private network recipe.
// Possibly sent requests survive renewal, crashes and unrelated journal writes.
type NetBirdUnderlayRecord struct {
	PurposeSHA256 string                            `json:"purposeSha256"`
	GrantSHA256   string                            `json:"grantSha256"`
	Origin        NetBirdJournalOriginReference     `json:"origin"`
	OperationID   string                            `json:"operationId"`
	IntentDigest  string                            `json:"intentDigest"`
	Epoch         uint64                            `json:"epoch"`
	Recipe        NetBirdJournalUnderlayRecipe      `json:"recipe"`
	Manager       NetBirdUnderlayEndpoint           `json:"manager"`
	Writer        NetBirdUnderlayEndpoint           `json:"writer"`
	StartedAt     time.Time                         `json:"startedAt"`
	ExpiresAt     time.Time                         `json:"expiresAt"`
	Requests      map[string]NetBirdUnderlayRequest `json:"requests"`
}

type NetBirdUnderlayEndpoint struct {
	InstanceID           string `json:"instanceId"`
	VNICID               string `json:"vnicId"`
	CompartmentID        string `json:"compartmentId"`
	NetworkCompartmentID string `json:"networkCompartmentId"`
	NetworkID            string `json:"networkId"`
	SubnetID             string `json:"subnetId"`
	RouteTableID         string `json:"routeTableId"`
	SecurityID           string `json:"securityId"`
	NSGID                string `json:"nsgId"`
}

// Exactly one typed OCI body is allowed per fixed step. Response identity is
// retained before readiness readback; its absence never permits redispatch.
type NetBirdUnderlayRequest struct {
	Create         *core.CreateLocalPeeringGatewayDetails   `json:"create,omitempty"`
	Connect        *core.ConnectLocalPeeringGatewaysDetails `json:"connect,omitempty"`
	Route          *core.UpdateRouteTableDetails            `json:"route,omitempty"`
	Security       *core.UpdateSecurityListDetails          `json:"security,omitempty"`
	ResourceID     string                                   `json:"resourceId"`
	IfMatch        string                                   `json:"ifMatch"`
	RequestDigest  string                                   `json:"requestDigest"`
	RetryToken     string                                   `json:"retryToken"`
	FirstAttemptAt time.Time                                `json:"firstAttemptAt"`
	ResponseID     string                                   `json:"responseId,omitempty"`
	RespondedAt    time.Time                                `json:"respondedAt,omitzero"`
	VerifiedAt     time.Time                                `json:"verifiedAt,omitzero"`
}

func (r NetBirdUnderlayRecord) Validate() error {
	if err := r.Origin.Validate(); err != nil {
		return err
	}
	if r.Origin.GrantSHA256 != r.GrantSHA256 {
		return errors.New("NetBird underlay archive differs from its original signed grant")
	}
	if !validDigest(r.PurposeSHA256) || !validDigest(r.GrantSHA256) || !validDigest(r.IntentDigest) || !entityid.Valid(r.OperationID) || r.Epoch == 0 ||
		r.StartedAt.IsZero() || !r.StartedAt.Before(r.ExpiresAt) || len(r.Requests) > len(netBirdUnderlaySteps) || r.Manager.validate() != nil || r.Writer.validate() != nil ||
		r.Manager.InstanceID == r.Writer.InstanceID || r.Manager.VNICID == r.Writer.VNICID || r.Manager.NetworkID == r.Writer.NetworkID || r.Manager.SubnetID == r.Writer.SubnetID ||
		r.Manager.RouteTableID == r.Writer.RouteTableID || r.Manager.SecurityID == r.Writer.SecurityID || r.Manager.NSGID == r.Writer.NSGID {
		return errors.New("NetBird underlay has invalid original purpose, native endpoints or finite cap")
	}
	if err := r.Recipe.Validate(); err != nil {
		return err
	}
	for key := range r.Requests {
		if !slices.Contains(netBirdUnderlaySteps, key) {
			return errors.New("NetBird underlay contains an unknown network operation")
		}
	}
	for index, key := range netBirdUnderlaySteps {
		request, ok := r.Requests[key]
		if !ok {
			continue
		}
		if index > 0 && r.Requests[netBirdUnderlaySteps[index-1]].VerifiedAt.IsZero() {
			return errors.New("NetBird underlay operation lacks its verified predecessor")
		}
		if err := r.validateRequest(key, request); err != nil {
			return err
		}
	}
	return nil
}

func (e NetBirdUnderlayEndpoint) validate() error {
	for kind, id := range map[string]string{"instance": e.InstanceID, "vnic": e.VNICID, "vcn": e.NetworkID, "subnet": e.SubnetID, "routetable": e.RouteTableID, "securitylist": e.SecurityID, "networksecuritygroup": e.NSGID} {
		if !netBirdUnderlayNativeID(kind, id) {
			return errors.New("NetBird underlay endpoint has an invalid native GRU identity")
		}
	}
	if !strings.HasPrefix(e.CompartmentID, "ocid1.compartment.") || len(e.CompartmentID) > 512 || !strings.HasPrefix(e.NetworkCompartmentID, "ocid1.compartment.") || len(e.NetworkCompartmentID) > 512 {
		return errors.New("NetBird underlay endpoint has no native compartment")
	}
	return nil
}

func netBirdUnderlayNativeID(kind, id string) bool {
	return len(id) <= 512 && strings.HasPrefix(id, "ocid1."+kind+".oc1.sa-saopaulo-1.") && len(strings.TrimPrefix(id, "ocid1."+kind+".oc1.sa-saopaulo-1.")) > 0
}

func (r NetBirdUnderlayRecord) validateRequest(key string, request NetBirdUnderlayRequest) error {
	if request.FirstAttemptAt.Before(r.StartedAt) || !request.FirstAttemptAt.Before(r.ExpiresAt) ||
		!request.RespondedAt.IsZero() && (request.RespondedAt.Before(request.FirstAttemptAt) || !request.RespondedAt.Before(r.ExpiresAt)) ||
		!request.VerifiedAt.IsZero() && (request.RespondedAt.IsZero() || request.VerifiedAt.Before(request.RespondedAt) || !request.VerifiedAt.Before(r.ExpiresAt)) ||
		request.RespondedAt.IsZero() && request.ResponseID != "" {
		return errors.New("NetBird underlay dispatch changed its original finite interval or outcome")
	}
	if err := r.validateRequestBody(key, request); err != nil {
		return err
	}
	wire, err := NetBirdUnderlayRequestWire(request)
	if err != nil || !validDigest(request.RequestDigest) || request.RequestDigest != digestBytes(wire) ||
		request.RetryToken != digestBytes([]byte(r.PurposeSHA256+"\x00"+key+"\x00"+request.RequestDigest)) {
		return errors.New("NetBird underlay dispatch changed its exact SDK request or original token")
	}
	return nil
}

func (r NetBirdUnderlayRecord) validateRequestBody(key string, q NetBirdUnderlayRequest) error {
	count := 0
	for _, present := range []bool{q.Create != nil, q.Connect != nil, q.Route != nil, q.Security != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return errors.New("NetBird underlay dispatch must retain exactly one typed SDK body")
	}
	switch key {
	case "manager_gateway", "writer_gateway":
		endpoint := r.Manager
		if key == "writer_gateway" {
			endpoint = r.Writer
		}
		expected := core.CreateLocalPeeringGatewayDetails{CompartmentId: new(endpoint.NetworkCompartmentID), VcnId: new(endpoint.NetworkID), DisplayName: new("gru-1-netbird-journal")}
		if q.Create == nil || !netBirdUnderlayEqual(q.Create, &expected) || q.ResourceID != "" || q.IfMatch != "" || q.ResponseID != "" && !netBirdUnderlayNativeID("localpeeringgateway", q.ResponseID) || !q.RespondedAt.IsZero() && q.ResponseID == "" {
			return errors.New("NetBird underlay gateway create exceeds its exact VCN and compartment")
		}
	case "connect":
		if q.Connect == nil || underlayValue(q.Connect.PeerId) != r.Requests["writer_gateway"].ResponseID || q.ResourceID != r.Requests["manager_gateway"].ResponseID || q.IfMatch != "" || q.ResponseID != "" {
			return errors.New("NetBird underlay connect differs from the two positive original gateway IDs")
		}
	case "manager_route", "writer_route":
		endpoint, destination, gateway := r.Manager, r.Recipe.WriterPrivateIP+"/32", r.Requests["manager_gateway"].ResponseID
		if key == "writer_route" {
			endpoint, destination, gateway = r.Writer, r.Recipe.ManagerPrivateIP+"/32", r.Requests["writer_gateway"].ResponseID
		}
		if q.Route == nil || q.ResourceID != endpoint.RouteTableID || q.IfMatch == "" || len(q.IfMatch) > 512 || q.ResponseID != "" || q.Route.DisplayName != nil || len(q.Route.DefinedTags) != 0 || len(q.Route.FreeformTags) != 0 ||
			!netBirdUnderlayHasRoute(q.Route.RouteRules, destination, gateway) {
			return errors.New("NetBird underlay route dispatch lacks its exact conditional /32 peer route")
		}
	case "writer_security":
		if q.Security == nil || q.ResourceID != r.Writer.SecurityID || q.IfMatch == "" || len(q.IfMatch) > 512 || q.ResponseID != "" || q.Security.DisplayName != nil || len(q.Security.DefinedTags) != 0 || len(q.Security.FreeformTags) != 0 ||
			!slices.ContainsFunc(q.Security.IngressSecurityRules, func(rule core.IngressSecurityRule) bool {
				return netBirdUnderlayEqual(rule, NetBirdUnderlayIngress(r.Recipe.ManagerPrivateIP))
			}) {
			return errors.New("NetBird underlay security dispatch lacks its exact conditional manager /32 TCP443 rule")
		}
	default:
		return errors.New("NetBird underlay dispatch has an unknown operation")
	}
	return nil
}

func netBirdUnderlayEqual(first, second any) bool {
	a, err := json.Marshal(first, json.Deterministic(true))
	if err != nil {
		return false
	}
	b, err := json.Marshal(second, json.Deterministic(true))
	return err == nil && bytes.Equal(a, b)
}

func NetBirdUnderlayRequestWire(q NetBirdUnderlayRequest) ([]byte, error) {
	var request common.OCIRequest
	switch {
	case q.Create != nil:
		request = core.CreateLocalPeeringGatewayRequest{CreateLocalPeeringGatewayDetails: *q.Create}
	case q.Connect != nil:
		request = core.ConnectLocalPeeringGatewaysRequest{LocalPeeringGatewayId: new(q.ResourceID), ConnectLocalPeeringGatewaysDetails: *q.Connect}
	case q.Route != nil:
		request = core.UpdateRouteTableRequest{RtId: new(q.ResourceID), UpdateRouteTableDetails: *q.Route}
	case q.Security != nil:
		request = core.UpdateSecurityListRequest{SecurityListId: new(q.ResourceID), UpdateSecurityListDetails: *q.Security}
	default:
		return nil, errors.New("NetBird underlay has no typed SDK request")
	}
	r, err := request.HTTPRequest(http.MethodPost, "/", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, errors.New("NetBird underlay SDK request has no body")
	}
	defer r.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(wire) > 64<<10 {
		return nil, errors.Join(errors.New("NetBird underlay SDK request exceeds its fixed body bound"), err)
	}
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		return nil, err
	}
	return json.Marshal(body, json.Deterministic(true))
}

func NetBirdUnderlayIngress(managerIP string) core.IngressSecurityRule {
	return core.IngressSecurityRule{Protocol: new("6"), Source: new(managerIP + "/32"), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, IsStateless: new(false),
		TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(443), Max: new(443)}}}
}

func netBirdUnderlayHasRoute(rules []core.RouteRule, destination, gateway string) bool {
	expected := core.RouteRule{Destination: new(destination), DestinationType: core.RouteRuleDestinationTypeCidrBlock, NetworkEntityId: new(gateway)}
	count := 0
	peer := netip.MustParsePrefix(destination).Addr()
	for _, rule := range rules {
		if underlayValue(rule.NetworkEntityId) == gateway || underlayValue(rule.Destination) == destination {
			if !(underlayValue(rule.Destination) == underlayValue(expected.Destination) && rule.DestinationType == expected.DestinationType && underlayValue(rule.NetworkEntityId) == underlayValue(expected.NetworkEntityId) && (underlayValue(rule.CidrBlock) == "" || underlayValue(rule.CidrBlock) == underlayValue(expected.Destination)) && (rule.RouteType == "" || rule.RouteType == core.RouteRuleRouteTypeStatic)) {
				return false
			}
			count++
		} else if prefix, err := netip.ParsePrefix(underlayValue(rule.Destination)); err == nil && prefix.Contains(peer) && prefix.Bits() != 0 {
			// The pre-existing Internet default remains; a competing private path does not.
			return false
		}
	}
	return count == 1
}

func underlayValue[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return v
}
