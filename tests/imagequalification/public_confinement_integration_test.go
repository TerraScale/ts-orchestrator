package imagequalification

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

// Local SDK fixtures have no reason to contact an ambient proxy.
func TestMain(m *testing.M) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if err := os.Unsetenv(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

var sdkAuthorizationField = regexp.MustCompile(`([a-zA-Z]+)="([^"]*)"`)

func authenticatedFixtureRequest(r *http.Request, key *rsa.PublicKey, tenancy string) bool {
	fields := map[string]string{}
	for _, match := range sdkAuthorizationField.FindAllStringSubmatch(r.Header.Get("Authorization"), -1) {
		fields[match[1]] = match[2]
	}
	if !strings.HasPrefix(fields["keyId"], tenancy+"/") || fields["algorithm"] != "rsa-sha256" {
		return false
	}
	var lines []string
	for header := range strings.FieldsSeq(fields["headers"]) {
		value := r.Header.Get(header)
		if header == "host" {
			value = r.Host
		}
		if header == "(request-target)" {
			value = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
		}
		lines = append(lines, header+": "+value)
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
}

func TestPublicConfinementSealsActualSDKAndRejectsResourceDrift(t *testing.T) {
	f := fixture(t)
	a := f.prepared.Approval()
	path := filepath.Join(t.TempDir(), "resources.json")
	initial, err := f.prepared.ConfinementScope(path)
	if err != nil {
		t.Fatal(err)
	}
	a.PolicyStatements = confinement.RequiredStatements(initial)
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, ApprovalScope(a.RunID, a.Candidate), f.now.Add(-1), f.prepared.expires, f.private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(wire, nil, f.roots, a.Candidate, a.RunID, f.disk, f.qualification, f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := prepared.ConfinementScope(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	factory := func(user, fp string) *ociclient.Factory {
		provider := common.NewRawConfigurationProvider(a.Tenancy, user, a.OCIRegion, fp, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
		result, err := ociclient.New(provider, ociclient.Options{Region: a.OCIRegion, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 1000}, ociclient.ServiceCompute: {PerSecond: 10000, Burst: 1000}, ociclient.ServiceNetwork: {PerSecond: 10000, Burst: 1000}, ociclient.ServiceObjectStorage: {PerSecond: 10000, Burst: 1000}}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	observer, candidate := factory("ocid1.user.oc1..observer", "observer-fingerprint"), factory(a.Principal, "candidate-fingerprint")
	remote := &cloudFixture{hosts: map[string]map[string]any{}, tokens: map[string]string{}}
	var fixtureMu sync.Mutex
	drift := false
	bootSize := int64(50)
	index := func(id string) string { return strings.TrimPrefix(id, "ocid1.instance.oc1..") }
	attachments := func(instanceID string) []core.VnicAttachment {
		var list []core.VnicAttachment
		for id, h := range remote.hosts {
			if instanceID != "" && instanceID != id || h["lifecycleState"] == "TERMINATED" {
				continue
			}
			list = append(list, core.VnicAttachment{Id: new("ocid1.vnicattachment.oc1.." + index(id)), InstanceId: new(id), CompartmentId: new(a.Compartment), SubnetId: new(a.Subnet), VnicId: new("ocid1.vnic.oc1.." + index(id)), AvailabilityDomain: new("fixture-ad"), LifecycleState: core.VnicAttachmentLifecycleStateAttached})
		}
		return list
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixtureMu.Lock()
		defer fixtureMu.Unlock()
		if !authenticatedFixtureRequest(r, &key.PublicKey, a.Tenancy) {
			http.Error(w, "invalid actual SDK signature", 401)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !strings.Contains(r.Header.Get("Authorization"), `keyId="`+a.Tenancy+"/"+a.Principal+`/candidate-fingerprint"`) {
			http.Error(w, "observer must not write", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("opc-request-id", "public-confinement-fixture")
		write := func(value any) {
			if err := json.MarshalWrite(w, value); err != nil {
				t.Error(err)
			}
		}
		p := strings.TrimPrefix(r.URL.Path, "/20160918")
		switch {
		case p == "/tenancies/"+a.Tenancy:
			write(identity.Tenancy{Id: new(a.Tenancy), HomeRegionKey: new("GRU")})
		case p == "/n" || p == "/n/":
			write(a.Namespace)
		case p == "/users/"+a.Principal:
			write(identity.User{Id: new(a.Principal), CompartmentId: new(a.Tenancy), Name: new("qualification"), LifecycleState: identity.UserLifecycleStateActive})
		case p == "/users/"+a.Principal+"/apiKeys":
			write([]identity.ApiKey{{UserId: new(a.Principal), Fingerprint: new("candidate-fingerprint"), LifecycleState: identity.ApiKeyLifecycleStateActive}})
		case p == "/groups/"+a.Group:
			write(identity.Group{Id: new(a.Group), CompartmentId: new(a.Tenancy), Name: new("qualification"), LifecycleState: identity.GroupLifecycleStateActive})
		case p == "/groups":
			write([]identity.Group{{Id: new(a.Group), CompartmentId: new(a.Tenancy), Name: new("qualification"), LifecycleState: identity.GroupLifecycleStateActive}})
		case p == "/userGroupMemberships":
			write([]identity.UserGroupMembership{{UserId: new(a.Principal), GroupId: new(a.Group), LifecycleState: identity.UserGroupMembershipLifecycleStateActive}})
		case p == "/dynamicGroups":
			write([]identity.DynamicGroup{})
		case p == "/compartments":
			write([]identity.Compartment{{Id: new(a.Compartment), CompartmentId: new(a.Tenancy), LifecycleState: identity.CompartmentLifecycleStateActive}})
		case p == "/policies":
			if r.URL.Query().Get("compartmentId") == a.Tenancy {
				statements := a.PolicyStatements
				if drift {
					statements = append(append([]string{}, statements...), "Allow group id "+a.Group+" to manage all-resources in tenancy")
				}
				write([]identity.Policy{{Id: new(a.PolicyID), CompartmentId: new(a.Tenancy), LifecycleState: identity.PolicyLifecycleStateActive, Statements: statements}})
			} else {
				write([]identity.Policy{})
			}
		case p == "/subnets":
			write([]core.Subnet{{Id: new(a.Subnet), CompartmentId: new(a.Compartment)}})
		case p == "/subnets/"+a.Subnet:
			write(core.Subnet{Id: new(a.Subnet), CompartmentId: new(a.Compartment), VcnId: new("ocid1.vcn.oc1..fixture"), RouteTableId: new("ocid1.routetable.oc1..fixture"), CidrBlock: new(a.PeerCIDR), ProhibitPublicIpOnVnic: new(true), SecurityListIds: []string{"ocid1.securitylist.oc1..fixture"}, LifecycleState: core.SubnetLifecycleStateAvailable})
		case p == "/vcns/ocid1.vcn.oc1..fixture":
			write(core.Vcn{Id: new("ocid1.vcn.oc1..fixture"), CompartmentId: new(a.Compartment), CidrBlock: new(a.VCNCIDR), LifecycleState: core.VcnLifecycleStateAvailable})
		case p == "/routeTables/ocid1.routetable.oc1..fixture":
			write(core.RouteTable{Id: new("ocid1.routetable.oc1..fixture"), CompartmentId: new(a.Compartment), VcnId: new("ocid1.vcn.oc1..fixture"), LifecycleState: core.RouteTableLifecycleStateAvailable})
		case p == "/securityLists/ocid1.securitylist.oc1..fixture":
			write(core.SecurityList{Id: new("ocid1.securitylist.oc1..fixture"), CompartmentId: new(a.Compartment), VcnId: new("ocid1.vcn.oc1..fixture"), LifecycleState: core.SecurityListLifecycleStateAvailable, IngressSecurityRules: []core.IngressSecurityRule{{Source: new(a.PeerCIDR), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, Protocol: new("all")}, {Source: new(a.RunnerCIDR), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, Protocol: new("6"), TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(22), Max: new(22)}}}}, EgressSecurityRules: []core.EgressSecurityRule{{Destination: new(a.PeerCIDR), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock, Protocol: new("all")}}})
		case p == "/privateIps":
			var ips []core.PrivateIp
			for _, v := range attachments("") {
				ips = append(ips, core.PrivateIp{Id: new("ocid1.privateip.oc1.." + index(*v.InstanceId)), VnicId: v.VnicId, SubnetId: new(a.Subnet), CompartmentId: new(a.Compartment), IsPrimary: new(true)})
			}
			if ips == nil {
				ips = []core.PrivateIp{}
			}
			write(ips)
		case p == "/vnicAttachments":
			list := attachments(r.URL.Query().Get("instanceId"))
			if list == nil {
				list = []core.VnicAttachment{}
			}
			write(list)
		case strings.HasPrefix(p, "/vnics/"):
			id := strings.TrimPrefix(p, "/vnics/")
			write(core.Vnic{Id: new(id), CompartmentId: new(a.Compartment), SubnetId: new(a.Subnet), PrivateIp: new("10.8.0.2"), IsPrimary: new(true), LifecycleState: core.VnicLifecycleStateAvailable})
		case p == "/bootVolumeAttachments":
			id := r.URL.Query().Get("instanceId")
			write([]core.BootVolumeAttachment{{Id: new("ocid1.bootvolumeattachment.oc1.." + index(id)), InstanceId: new(id), BootVolumeId: new("ocid1.bootvolume.oc1.." + index(id)), CompartmentId: new(a.Compartment), AvailabilityDomain: new("fixture-ad"), LifecycleState: core.BootVolumeAttachmentLifecycleStateAttached}})
		case strings.HasPrefix(p, "/bootVolumes/"):
			write(core.BootVolume{Id: new(strings.TrimPrefix(p, "/bootVolumes/")), CompartmentId: new(a.Compartment), AvailabilityDomain: new("fixture-ad"), SizeInGBs: new(bootSize), LifecycleState: core.BootVolumeLifecycleStateAvailable})
		default:
			remote.serve(w, r)
		}
	}))
	defer server.Close()
	fixtureURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "identity.sa-saopaulo-1.oci.oraclecloud.com:443" && address != "iaas.sa-saopaulo-1.oraclecloud.com:443" && address != "objectstorage.sa-saopaulo-1.oraclecloud.com:443" {
			return nil, fmt.Errorf("unapproved fixture OCI origin %s", address)
		}
		return (&tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: fixtureURL.Hostname(), MinVersion: tls.VersionTLS13}}).DialContext(ctx, network, fixtureURL.Host)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	verified, err := confinement.Observe(t.Context(), observer, candidate, scope)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newConfinedCloud(t.Context(), prepared, verified, path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := client.prepareResources(t.Context(), path, publicSSHKey(t))
	if err != nil {
		t.Fatal(err)
	}
	fixtureMu.Lock()
	launches := remote.launches
	fixtureMu.Unlock()
	if len(j.Hosts) != 4 || launches != 4 {
		t.Fatal("sealed positive consumer did not launch the exact finite hosts")
	}
	first := j.Hosts[a.Hosts[0].Name]
	fixtureMu.Lock()
	remote.hosts[first]["shape"] = "VM.Standard.E4.Flex"
	fixtureMu.Unlock()
	if _, err := client.compute.GetInstance(ociclient.RequestContext(t.Context()), core.GetInstanceRequest{InstanceId: new(first)}); err == nil {
		t.Fatal("actual shape drift crossed guarded SDK dispatch")
	}
	fixtureMu.Lock()
	remote.hosts[first]["shape"] = a.Hosts[0].Shape
	bootSize = 51
	fixtureMu.Unlock()
	if _, err := client.compute.GetInstance(ociclient.RequestContext(t.Context()), core.GetInstanceRequest{InstanceId: new(first)}); err == nil {
		t.Fatal("actual boot size drift crossed guarded SDK dispatch")
	}
	fixtureMu.Lock()
	bootSize = 50
	drift = true
	fixtureMu.Unlock()
	if err := client.cleanup(t.Context(), path); err == nil {
		t.Fatal("inherited privilege drift crossed cleanup guard")
	}
	fixtureMu.Lock()
	deletes := remote.deletes
	fixtureMu.Unlock()
	if deletes != 0 {
		t.Fatal("drift dispatched a destructive SDK call")
	}
	fixtureMu.Lock()
	drift = false
	fixtureMu.Unlock()
	if err := client.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	cleaned, err := client.load(path)
	if err != nil {
		t.Fatal(err)
	}
	fixtureMu.Lock()
	deletes = remote.deletes
	fixtureMu.Unlock()
	if !cleaned.ImageDeleted || !cleaned.ObjectDeleted || len(cleaned.Terminated) != 4 || deletes != 6 {
		t.Fatalf("sealed consumer cleanup incomplete: %+v deletes=%d", cleaned, deletes)
	}
}
