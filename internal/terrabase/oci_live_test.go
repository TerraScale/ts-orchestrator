package terrabase

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/limits"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// a1Shape is the ARM64 shape TerraBase hosts run on.
const a1Shape = "VM.Standard.A1.Flex"

// TestLiveOCITerraBaseHostsReadOnly checks, against the real OCI API, what a
// C# TerraBase release needs from a cell: the region offers the ARM64 A1
// shape with A1 cores left for another member, an Ubuntu ARM64 base image
// fits that shape, and the cell's running TerraBase hosts are A1 instances on
// distinct fault domains whose network security groups let every member
// reach the others' peer port. It logs the TERRABASE_PEERS value those hosts
// give. Every call is a list or get through the shared OCI client factory
// with the operator's ~/.oci/config DEFAULT profile; nothing is created,
// changed or deleted.
//
// Opt in with TS_OCI_LIVE_COMPARTMENT_ID, the cell's compartment. Optional:
// TS_OCI_LIVE_REGION (default: the profile's region), TS_OCI_LIVE_HOST_PREFIX
// (default gru-1-db-) and TS_OCI_LIVE_PEER_PORT (default 9443). A cell with
// no running host of that prefix yet passes the regional checks and skips
// the host checks.
func TestLiveOCITerraBaseHostsReadOnly(t *testing.T) {
	compartment := tier.Qualification(t, "TS_OCI_LIVE_COMPARTMENT_ID")[0]
	prefix := liveEnv("TS_OCI_LIVE_HOST_PREFIX", "gru-1-db-")
	peerPort, err := parsePort(liveEnv("TS_OCI_LIVE_PEER_PORT", "9443"))
	if err != nil {
		t.Fatalf("TS_OCI_LIVE_PEER_PORT: %v", err)
	}
	region := os.Getenv("TS_OCI_LIVE_REGION")
	if region == "" {
		if region, err = common.DefaultConfigProvider().Region(); err != nil {
			t.Fatal(err)
		}
	}
	factory, err := ociclient.OperatorConfig(region)
	if err != nil {
		t.Fatal(err)
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	network, err := factory.Network()
	if err != nil {
		t.Fatal(err)
	}
	identities, err := factory.Identity()
	if err != nil {
		t.Fatal(err)
	}
	quotas, err := limits.NewLimitsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	quotas.SetRegion(region)
	factory.Configure(&quotas.BaseClient, ociclient.ServiceIdentity)
	ctx := t.Context()

	// The region offers A1 with one OCPU and 6 GB per OCPU, the host profile.
	shapes, err := compute.ListShapes(ctx, core.ListShapesRequest{CompartmentId: &compartment, Limit: common.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(shapes.Items, func(shape core.Shape) bool { return shape.Shape != nil && *shape.Shape == a1Shape })
	if index < 0 {
		t.Fatalf("%s is not offered in %s", a1Shape, region)
	}
	shape := shapes.Items[index]
	if shape.ProcessorDescription == nil || !strings.Contains(*shape.ProcessorDescription, "Ampere") ||
		shape.OcpuOptions == nil || *shape.OcpuOptions.Min > 1 ||
		shape.MemoryOptions == nil || *shape.MemoryOptions.MaxPerOcpuInGBs < 6 {
		t.Fatalf("%s does not fit the TerraBase host profile: %+v", a1Shape, shape)
	}

	// A1 cores are left for at least one more member.
	domains, err := identities.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: &tenancy})
	if err != nil {
		t.Fatal(err)
	}
	available := int64(0)
	for _, domain := range domains.Items {
		availability, err := quotas.GetResourceAvailability(ctx, limits.GetResourceAvailabilityRequest{ServiceName: common.String("compute"),
			LimitName: common.String("standard-a1-core-count"), CompartmentId: &tenancy, AvailabilityDomain: domain.Name})
		if err != nil {
			t.Fatal(err)
		}
		if availability.Available != nil {
			available += *availability.Available
		}
	}
	if available < 1 {
		t.Fatalf("no %s cores are available in %s", a1Shape, region)
	}

	// The region publishes an Ubuntu ARM64 base image for A1.
	images, err := compute.ListImages(ctx, core.ListImagesRequest{CompartmentId: &compartment,
		OperatingSystem: common.String("Canonical Ubuntu"), Shape: common.String(a1Shape), Limit: common.Int(20)})
	if err != nil {
		t.Fatal(err)
	}
	if len(images.Items) == 0 {
		t.Fatalf("no Canonical Ubuntu image fits %s in %s", a1Shape, region)
	}
	t.Logf("%s: %s offered (%s), %d A1 cores available, %d Ubuntu A1 images", region, a1Shape,
		*shape.ProcessorDescription, available, len(images.Items))

	observation, err := observePeerIngress(ctx, compute, network, compartment, prefix, peerPort)
	for _, instance := range observation.instances {
		if instance.Shape == nil || *instance.Shape != a1Shape {
			t.Errorf("host %s runs %v, not %s", *instance.DisplayName, instance.Shape, a1Shape)
		}
	}
	domainsUsed := map[string]bool{}
	for _, member := range observation.members {
		if domainsUsed[member.faultDomain] && len(observation.members) <= 3 {
			t.Errorf("hosts share fault domain %s", member.faultDomain)
		}
		domainsUsed[member.faultDomain] = true
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.members) == 0 {
		t.Logf("no running hosts named %s* in the compartment yet; TerraBase host checks skipped", prefix)
		return
	}
	t.Logf("%s=%s", EnvPeers, observation.peers)
	for _, pair := range observation.pairs {
		if !pair.allowed {
			t.Errorf("%s cannot reach %s on TCP %d: no ingress rule on %s's groups allows it", pair.sender, pair.receiver, peerPort, pair.receiver)
		}
	}
}

type peerIngressMember struct {
	name, faultDomain string
	address           netip.Addr
	groups            []string
	instanceID        *string
	attachment        core.VnicAttachment
	vnic              core.Vnic
}

type peerIngressAssessment struct {
	sender, receiver string
	allowed          bool
}

type peerIngressObservation struct {
	instances []core.Instance
	members   []peerIngressMember
	peers     string
	parsed    []Peer
	rules     map[string][]core.SecurityRule
	pairs     []peerIngressAssessment
}

// shortcut: retain one-page/static-ingress limits until separately scoped pagination/policy work.
// Direction relies on the request filter; source ports, IsValid and IsStateless are not policy inputs.
func observePeerIngress(ctx context.Context, compute core.ComputeClient, network core.VirtualNetworkClient,
	compartment, prefix string, port int,
) (peerIngressObservation, error) {
	var observation peerIngressObservation
	instances, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &compartment,
		LifecycleState: core.InstanceLifecycleStateRunning, Limit: new(100)})
	if err != nil {
		return observation, fmt.Errorf("list peer instances: %w", err)
	}
	for _, instance := range instances.Items {
		if instance.DisplayName == nil || !strings.HasPrefix(*instance.DisplayName, prefix) {
			continue
		}
		// Keep matching instances even when no primary VNIC becomes a peer.
		observation.instances = append(observation.instances, instance)
		attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: &compartment, InstanceId: instance.Id})
		if err != nil {
			return observation, fmt.Errorf("list peer %s VNIC attachments: %w", *instance.DisplayName, err)
		}
		for _, attachment := range attachments.Items {
			if attachment.VnicId == nil || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
				continue
			}
			vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
			if err != nil {
				return observation, fmt.Errorf("get peer VNIC %s: %w", *attachment.VnicId, err)
			}
			if vnic.IsPrimary == nil || !*vnic.IsPrimary || vnic.PrivateIp == nil {
				continue
			}
			address, err := netip.ParseAddr(*vnic.PrivateIp)
			if err != nil {
				return observation, fmt.Errorf("parse peer %s private IP: %w", *instance.DisplayName, err)
			}
			observation.members = append(observation.members, peerIngressMember{
				name: *instance.DisplayName, faultDomain: *instance.FaultDomain, address: address, groups: vnic.NsgIds,
				instanceID: instance.Id, attachment: attachment, vnic: vnic.Vnic,
			})
		}
	}
	if len(observation.members) == 0 {
		return observation, nil
	}
	entries := make([]string, len(observation.members))
	for i, member := range observation.members {
		entries[i] = member.name + "=" + netip.AddrPortFrom(member.address, uint16(port)).String()
	}
	observation.peers = strings.Join(entries, ",")
	observation.parsed, err = ParsePeers(observation.peers)
	if err != nil {
		return observation, fmt.Errorf("the hosts give an invalid peer list: %w", err)
	}
	observation.rules = map[string][]core.SecurityRule{}
	for _, member := range observation.members {
		for _, group := range member.groups {
			if _, read := observation.rules[group]; read {
				continue
			}
			response, err := network.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
				NetworkSecurityGroupId: &group, Direction: core.ListNetworkSecurityGroupSecurityRulesDirectionIngress, Limit: new(100)})
			if err != nil {
				return observation, fmt.Errorf("list peer NSG %s ingress: %w", group, err)
			}
			observation.rules[group] = response.Items
		}
	}
	for _, receiver := range observation.members {
		for _, sender := range observation.members {
			if sender.name != receiver.name {
				observation.pairs = append(observation.pairs, peerIngressAssessment{
					sender: sender.name, receiver: receiver.name,
					allowed: peerPortOpen(receiver.groups, observation.rules, sender.address, sender.groups, port),
				})
			}
		}
	}
	return observation, nil
}

// peerPortOpen reports whether an ingress rule of the receiver's groups lets
// TCP from the sender's address or groups reach port.
func peerPortOpen(receiver []string, rules map[string][]core.SecurityRule, sender netip.Addr, senderGroups []string, port int) bool {
	for _, group := range receiver {
		for _, rule := range rules[group] {
			if rule.Protocol == nil || (*rule.Protocol != "6" && *rule.Protocol != "all") || rule.Source == nil {
				continue
			}
			if *rule.Protocol == "6" && rule.TcpOptions != nil && rule.TcpOptions.DestinationPortRange != nil {
				ports := rule.TcpOptions.DestinationPortRange
				if ports.Min == nil || ports.Max == nil || *ports.Min > port || *ports.Max < port {
					continue
				}
			}
			switch rule.SourceType {
			case core.SecurityRuleSourceTypeNetworkSecurityGroup:
				if slices.Contains(senderGroups, *rule.Source) {
					return true
				}
			default:
				if prefix, err := netip.ParsePrefix(*rule.Source); err == nil && prefix.Contains(sender) {
					return true
				}
			}
		}
	}
	return false
}

func TestPeerPortOpen(t *testing.T) {
	tcp := func(source string, kind core.SecurityRuleSourceTypeEnum, low, high int) core.SecurityRule {
		return core.SecurityRule{Protocol: common.String("6"), Source: &source, SourceType: kind,
			TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: &low, Max: &high}}}
	}
	rules := map[string][]core.SecurityRule{
		"cidr": {tcp("10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9443, 9443)},
		"nsg":  {tcp("members", core.SecurityRuleSourceTypeNetworkSecurityGroup, 9000, 9500)},
		"miss": {tcp("10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9465, 9465)},
	}
	sender := netip.MustParseAddr("10.251.0.22")
	for name, want := range map[string]bool{"cidr": true, "nsg": true, "miss": false} {
		if got := peerPortOpen([]string{name}, rules, sender, []string{"members"}, 9443); got != want {
			t.Errorf("%s: open %v, want %v", name, got, want)
		}
	}
	if peerPortOpen([]string{"nsg"}, rules, sender, []string{"0000000000V4MRM46HP1SNGDYW"}, 9443) {
		t.Error("a rule for another group opened the port")
	}
	if peerPortOpen([]string{"cidr"}, rules, netip.MustParseAddr("10.9.0.1"), nil, 9443) {
		t.Error("a rule for another network opened the port")
	}
}

func liveEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// This checks static ingress observations, not peer TCP, egress, routing or replication.
func TestPeerPortOpenThroughSDKObservedHosts(t *testing.T) {
	const (
		compartment = "ocid1.compartment.oc1..offline"
		instanceA   = "ocid1.instance.oc1.sa-saopaulo-1..offlinea"
		instanceB   = "ocid1.instance.oc1.sa-saopaulo-1..offlineb"
		vnicA       = "ocid1.vnic.oc1.sa-saopaulo-1..offlinea"
		vnicB       = "ocid1.vnic.oc1.sa-saopaulo-1..offlineb"
		groupA      = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1..receiver"
		groupB      = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1..members"
		foreign     = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1..foreign"
		nameA       = "offline-db-a"
		nameB       = "offline-db-b"
		addressA    = "10.251.0.11"
	)
	for _, tc := range []struct {
		name, source               string
		kind                       core.SecurityRuleSourceTypeEnum
		low, high                  int
		senderAddress, senderGroup string
		allowed                    bool
	}{
		{"cidr", "10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9443, 9443, "10.251.0.22", groupB, true},
		{"nsg", groupB, core.SecurityRuleSourceTypeNetworkSecurityGroup, 9000, 9500, "10.251.0.22", groupB, true},
		{"destination_miss", "10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9465, 9465, "10.251.0.22", groupB, false},
		{"sender_nsg_miss", groupB, core.SecurityRuleSourceTypeNetworkSecurityGroup, 9000, 9500, "10.251.0.22", foreign, false},
		{"sender_cidr_miss", "10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9443, 9443, "10.9.0.1", groupB, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instanceJSON := func(id, name, domain string) string {
				return fmt.Sprintf(`{"id":%q,"compartmentId":%q,"displayName":%q,"faultDomain":%q,"shape":"VM.Standard.A1.Flex","lifecycleState":"RUNNING"}`,
					id, compartment, name, domain)
			}
			attachmentJSON := func(id, instance, vnic string) string {
				return fmt.Sprintf(`[{"id":%q,"compartmentId":%q,"instanceId":%q,"vnicId":%q,"lifecycleState":"ATTACHED"}]`,
					id, compartment, instance, vnic)
			}
			vnicJSON := func(id, address, group string) string {
				return fmt.Sprintf(`{"id":%q,"compartmentId":%q,"isPrimary":true,"privateIp":%q,"nsgIds":[%q]}`,
					id, compartment, address, group)
			}
			ruleJSON := func(id, source string, kind core.SecurityRuleSourceTypeEnum, low, high int) string {
				return fmt.Sprintf(`[{"id":%q,"direction":"INGRESS","protocol":"6","source":%q,"sourceType":%q,"isValid":true,"isStateless":false,"tcpOptions":{"destinationPortRange":{"min":%d,"max":%d}}}]`,
					id, source, kind, low, high)
			}
			type reply struct {
				path  string
				query url.Values
				body  string
			}
			replies := []reply{
				{"/20160918/instances", url.Values{"compartmentId": {compartment}, "lifecycleState": {"RUNNING"}, "limit": {"100"}},
					"[" + instanceJSON(instanceA, nameA, "FAULT-DOMAIN-1") + "," + instanceJSON(instanceB, nameB, "FAULT-DOMAIN-2") + "]"},
				{"/20160918/vnicAttachments", url.Values{"compartmentId": {compartment}, "instanceId": {instanceA}}, attachmentJSON("attachment-a", instanceA, vnicA)},
				{"/20160918/vnics/" + vnicA, url.Values{}, vnicJSON(vnicA, addressA, groupA)},
				{"/20160918/vnicAttachments", url.Values{"compartmentId": {compartment}, "instanceId": {instanceB}}, attachmentJSON("attachment-b", instanceB, vnicB)},
				{"/20160918/vnics/" + vnicB, url.Values{}, vnicJSON(vnicB, tc.senderAddress, tc.senderGroup)},
				{"/20160918/networkSecurityGroups/" + groupA + "/securityRules", url.Values{"direction": {"INGRESS"}, "limit": {"100"}},
					ruleJSON("rule-to-a", tc.source, tc.kind, tc.low, tc.high)},
				{"/20160918/networkSecurityGroups/" + tc.senderGroup + "/securityRules", url.Values{"direction": {"INGRESS"}, "limit": {"100"}},
					ruleJSON("rule-to-b", addressA+"/32", core.SecurityRuleSourceTypeCidrBlock, 9443, 9443)},
			}
			type requestRecord struct {
				method, host, uri                       string
				contentType, nextPage                   string
				requestHash, responseHash               [sha256.Size]byte
				requestBytes, responseBytes, statusCode int
				complete                                bool
			}
			var mu sync.Mutex
			var records []requestRecord
			var overflow int
			var failures []string
			var host string
			factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if len(records) > len(replies) {
					overflow++
					http.Error(w, "fixture audit overflow", http.StatusBadRequest)
					return
				}
				record := requestRecord{method: r.Method, host: r.Host, uri: r.RequestURI}
				defer func() { records = append(records, record) }()
				reject := func(message string) {
					failures = append(failures, message)
					record.statusCode = http.StatusBadRequest
					http.Error(w, "unexpected fixture request", http.StatusBadRequest)
				}
				if len(records) >= len(replies) {
					reject("extra SDK request")
					return
				}
				want := replies[len(records)]
				query, queryErr := url.ParseQuery(r.URL.RawQuery)
				if r.Method != http.MethodGet || r.Host != host || r.URL.EscapedPath() != want.path || queryErr != nil || !reflect.DeepEqual(query, want.query) {
					reject(fmt.Sprintf("request %d: got %s %s %s, want GET %s %s query=%v", len(records)+1, r.Method, r.Host, r.RequestURI, host, want.path, want.query))
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 1))
				record.requestBytes, record.requestHash = len(body), sha256.Sum256(body)
				if err != nil || len(body) != 0 || r.ContentLength != 0 {
					reject("GET request body was not empty")
					return
				}
				// Server checks presence; this checks structure, not signature validity.
				signature, prefixOK := strings.CutPrefix(r.Header.Get("Authorization"), `Signature version="1",headers="date (request-target) host",keyId="ocid1.tenancy.oc1..t/ocid1.user.oc1..u/fp",algorithm="rsa-sha256",signature="`)
				signature, suffixOK := strings.CutSuffix(signature, `"`)
				decoded, decodeErr := base64.StdEncoding.DecodeString(signature)
				_, dateErr := http.ParseTime(r.Header.Get("Date"))
				if !prefixOK || !suffixOK || decodeErr != nil || len(decoded) != 256 || dateErr != nil {
					reject("missing or malformed SDK signing headers")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				n, writeErr := io.WriteString(w, want.body)
				record.statusCode, record.responseBytes = http.StatusOK, n
				record.contentType, record.nextPage = w.Header().Get("Content-Type"), w.Header().Get("opc-next-page")
				record.responseHash = sha256.Sum256([]byte(want.body[:n]))
				record.complete = writeErr == nil && n == len(want.body)
				if !record.complete {
					failures = append(failures, fmt.Sprintf("response %d incomplete: wrote %d/%d: %v", len(records)+1, n, len(want.body), writeErr))
				}
			})
			endpointURL, err := url.Parse(endpoint)
			if err != nil || endpointURL.Scheme != "http" || !net.ParseIP(endpointURL.Hostname()).IsLoopback() {
				t.Fatalf("fixture endpoint is not local HTTP: %s (%v)", endpoint, err)
			}
			mu.Lock()
			host = endpointURL.Host
			mu.Unlock()
			t.Cleanup(func() {
				mu.Lock()
				defer mu.Unlock()
				if overflow != 0 {
					t.Errorf("SDK audit overflow: %d calls beyond the bounded records", overflow)
				}
				for _, failure := range failures {
					t.Error(failure)
				}
				if len(records) != len(replies) {
					t.Errorf("SDK attempts: got %d, want exactly %d; no extra calls or retries", len(records), len(replies))
				}
				for i, record := range records {
					t.Logf("SDK request %d: %s host=%s uri=%s uri_sha256=%x request_bytes=%d request_sha256=%x status=%d response_bytes=%d response_sha256=%x content_type=%s next_page=%q complete=%v",
						i+1, record.method, record.host, record.uri, sha256.Sum256([]byte(record.uri)), record.requestBytes, record.requestHash,
						record.statusCode, record.responseBytes, record.responseHash, record.contentType, record.nextPage, record.complete)
					if i >= len(replies) {
						continue
					}
					want := replies[i]
					if !record.complete || record.statusCode != http.StatusOK || record.contentType != "application/json" || record.nextPage != "" || record.requestBytes != 0 || record.requestHash != sha256.Sum256(nil) ||
						record.responseBytes != len(want.body) || record.responseHash != sha256.Sum256([]byte(want.body)) {
						t.Errorf("SDK request %d did not complete the exact fixture exchange", i+1)
					}
				}
			})
			transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != host {
					return nil, fmt.Errorf("unexpected fixture dial %s %s", network, address)
				}
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
			}}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("unexpected fixture redirect") }}
			compute, err := factory.Compute()
			if err != nil {
				t.Fatal(err)
			}
			network, err := factory.Network()
			if err != nil {
				t.Fatal(err)
			}
			for _, sdk := range []*common.BaseClient{&compute.BaseClient, &network.BaseClient} {
				ociclient.PinHost(sdk, endpoint)
				sdk.HTTPClient = client
				ociclient.ConfigureReadCancellation(sdk)
				if sdk.Host != endpoint {
					t.Fatalf("SDK host: got %s, want %s", sdk.Host, endpoint)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			got, err := observePeerIngress(ctx, compute, network, compartment, "offline-db-", 9443)
			if err != nil {
				t.Fatalf("SDK observation failed, not an ingress denial: %v", err)
			}
			// The SDK normalizes omitted licensingConfigs to a nonnil empty slice.
			wantInstance := func(id, name, domain string) core.Instance {
				return core.Instance{Id: new(id), CompartmentId: new(compartment), DisplayName: new(name), FaultDomain: new(domain),
					Shape: new(a1Shape), LifecycleState: core.InstanceLifecycleStateRunning, LicensingConfigs: []core.LicensingConfig{}}
			}
			wantMember := func(instance, attachment, vnic, name, domain, address, group string) peerIngressMember {
				return peerIngressMember{name: name, faultDomain: domain, address: netip.MustParseAddr(address), groups: []string{group}, instanceID: new(instance),
					attachment: core.VnicAttachment{Id: new(attachment), CompartmentId: new(compartment), InstanceId: new(instance), VnicId: new(vnic), LifecycleState: core.VnicAttachmentLifecycleStateAttached},
					vnic:       core.Vnic{Id: new(vnic), CompartmentId: new(compartment), IsPrimary: new(true), PrivateIp: new(address), NsgIds: []string{group}}}
			}
			wantRule := func(id, source string, kind core.SecurityRuleSourceTypeEnum, low, high int) core.SecurityRule {
				return core.SecurityRule{Id: new(id), Direction: core.SecurityRuleDirectionIngress, Protocol: new("6"), Source: new(source), SourceType: kind,
					IsValid: new(true), IsStateless: new(false), TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(low), Max: new(high)}}}
			}
			want := peerIngressObservation{
				instances: []core.Instance{wantInstance(instanceA, nameA, "FAULT-DOMAIN-1"), wantInstance(instanceB, nameB, "FAULT-DOMAIN-2")},
				members: []peerIngressMember{
					wantMember(instanceA, "attachment-a", vnicA, nameA, "FAULT-DOMAIN-1", addressA, groupA),
					wantMember(instanceB, "attachment-b", vnicB, nameB, "FAULT-DOMAIN-2", tc.senderAddress, tc.senderGroup),
				},
				peers: nameA + "=" + addressA + ":9443," + nameB + "=" + tc.senderAddress + ":9443",
				parsed: []Peer{{Name: nameA, Address: netip.MustParseAddrPort(addressA + ":9443")},
					{Name: nameB, Address: netip.MustParseAddrPort(tc.senderAddress + ":9443")}},
				rules: map[string][]core.SecurityRule{
					groupA:         {wantRule("rule-to-a", tc.source, tc.kind, tc.low, tc.high)},
					tc.senderGroup: {wantRule("rule-to-b", addressA+"/32", core.SecurityRuleSourceTypeCidrBlock, 9443, 9443)},
				},
				pairs: []peerIngressAssessment{{sender: nameB, receiver: nameA, allowed: tc.allowed}, {sender: nameA, receiver: nameB, allowed: true}},
			}
			for _, field := range []struct {
				name      string
				got, want any
			}{
				{"matching instances", got.instances, want.instances},
				{"observed members", got.members, want.members},
				{"peer serialization", got.peers, want.peers},
				{"parsed peers", got.parsed, want.parsed},
				{"decoded ingress rules", got.rules, want.rules},
				{"ordered pair assessments", got.pairs, want.pairs},
			} {
				if !reflect.DeepEqual(field.got, field.want) {
					t.Errorf("%s: got %+v, want %+v", field.name, field.got, field.want)
				}
			}
			t.Logf("%s=%s; members=%d ordered_pairs=%+v", EnvPeers, got.peers, len(got.members), got.pairs)
		})
	}
}
