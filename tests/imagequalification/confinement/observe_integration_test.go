package confinement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// This scenario traverses the actual OCI clients, HTTP signing and paginated
// protocol. The local endpoint is a provider simulator, never live acceptance.
func TestSDKConfinementInventoryAndPreEffectRevalidation(t *testing.T) {
	for _, mode := range []string{"valid", "late-policy", "late-membership", "late-dynamic-group", "dynamic-rule-overlap", "dynamic-rule-compound", "dynamic-profile-missing", "ambiguous-group", "domain-subject", "policy-extra", "public-route", "external-egress", "foreign-host", "foreign-subnet", "descendant-compartment", "key-mismatch", "pagination-loop"} {
		t.Run(mode, func(t *testing.T) {
			s := Scope{ApprovalSHA256: strings.Repeat("a", 64), RunID: "exact-run", Tenancy: "ocid1.tenancy.oc1..test", Principal: "ocid1.user.oc1..candidate", Group: "ocid1.group.oc1..candidate", PolicyID: "ocid1.policy.oc1..candidate", Compartment: "ocid1.compartment.oc1..disposable", Subnet: "ocid1.subnet.oc1..disposable", Namespace: "qualification", Bucket: "disposable", Object: "qualification/exact-run/image.qcow2", RunnerCIDR: "10.72.0.1/32", PeerCIDR: "10.72.1.0/24", VCNCIDR: "10.72.0.0/16", HostNames: []string{"ts-qualification-exact-run-host"}, ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second), CleanupUntil: time.Now().Add(2 * time.Hour).Truncate(time.Second)}
			s.PolicyStatements = RequiredStatements(s)
			s.ProductionDynamicGroups = []ProductionDynamicGroup{{ID: "ocid1.dynamicgroup.oc1..production", Name: "gru-1-controllers", InstanceCompartment: "ocid1.compartment.oc1..production"}}
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			factory := func(user, fingerprint string) *ociclient.Factory {
				provider := common.NewRawConfigurationProvider(s.Tenancy, user, "sa-saopaulo-1", fingerprint, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
				f, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 1000}, ociclient.ServiceNetwork: {PerSecond: 10000, Burst: 1000}, ociclient.ServiceCompute: {PerSecond: 10000, Burst: 1000}}})
				if err != nil {
					t.Fatal(err)
				}
				return f
			}
			observer := factory("ocid1.user.oc1..reader", "reader-fingerprint")
			candidate := factory(s.Principal, "candidate-fingerprint")
			var requests, writes atomic.Int32
			var drift atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet {
					writes.Add(1)
					http.Error(w, "read-only observer", http.StatusForbidden)
					return
				}
				if !validSignature(r, &key.PublicKey, s.Tenancy+"/") {
					http.Error(w, "invalid SDK signature", http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				path := strings.TrimPrefix(r.URL.Path, "/20160918")
				write := func(value any) {
					wire, err := json.Marshal(value)
					if err != nil {
						t.Error(err)
						return
					}
					_, _ = w.Write(wire)
				}
				page := r.URL.Query().Get("page")
				switch {
				case path == "/n/" || path == "/n":
					write(s.Namespace)
				case path == "/users/"+s.Principal:
					write(identity.User{Id: new(s.Principal), CompartmentId: new(s.Tenancy), Name: new("qualification"), LifecycleState: identity.UserLifecycleStateActive})
				case path == "/users/"+s.Principal+"/apiKeys":
					fp := "candidate-fingerprint"
					if mode == "key-mismatch" {
						fp = "different"
					}
					write([]identity.ApiKey{{UserId: new(s.Principal), Fingerprint: new(fp), LifecycleState: identity.ApiKeyLifecycleStateActive}})
				case path == "/groups/"+s.Group:
					write(identity.Group{Id: new(s.Group), CompartmentId: new(s.Tenancy), Name: new("qualification"), LifecycleState: identity.GroupLifecycleStateActive})
				case path == "/groups":
					if page == "" {
						w.Header().Set("opc-next-page", "groups-2")
						write([]identity.Group{{Id: new(s.Group), Name: new("qualification"), CompartmentId: new(s.Tenancy), LifecycleState: identity.GroupLifecycleStateActive}})
					} else {
						name := "Administrators"
						if mode == "ambiguous-group" {
							name = "qualification"
						}
						write([]identity.Group{{Id: new("ocid1.group.oc1..admin"), Name: new(name), CompartmentId: new(s.Tenancy), LifecycleState: identity.GroupLifecycleStateActive}})
					}
				case path == "/userGroupMemberships":
					if page == "" {
						w.Header().Set("opc-next-page", "membership-2")
						write([]identity.UserGroupMembership{{UserId: new(s.Principal), GroupId: new(s.Group), LifecycleState: identity.UserGroupMembershipLifecycleStateActive}})
					} else if mode == "late-membership" {
						write([]identity.UserGroupMembership{{UserId: new(s.Principal), GroupId: new("ocid1.group.oc1..production"), LifecycleState: identity.UserGroupMembershipLifecycleStateActive}})
					} else {
						write([]identity.UserGroupMembership{})
					}
				case path == "/dynamicGroups":
					if page == "" {
						w.Header().Set("opc-next-page", "dynamic-2")
						profile := s.ProductionDynamicGroups[0]
						rule := "ALL {instance.compartment.id = '" + profile.InstanceCompartment + "'}"
						if mode == "dynamic-rule-overlap" {
							rule = "ALL {instance.compartment.id = '" + s.Compartment + "'}"
						}
						if mode == "dynamic-rule-compound" {
							rule = "ANY {instance.compartment.id = '" + profile.InstanceCompartment + "', instance.compartment.id = '" + s.Compartment + "'}"
						}
						if mode == "dynamic-profile-missing" {
							write([]identity.DynamicGroup{})
						} else {
							write([]identity.DynamicGroup{{Id: new(profile.ID), Name: new(profile.Name), CompartmentId: new(s.Tenancy), LifecycleState: identity.DynamicGroupLifecycleStateActive, MatchingRule: new(rule)}})
						}
					} else if mode == "late-dynamic-group" {
						write([]identity.DynamicGroup{{Id: new("ocid1.dynamicgroup.oc1..production"), MatchingRule: new("ALL {instance.compartment.id = '" + s.Compartment + "'}")}})
					} else {
						write([]identity.DynamicGroup{})
					}
				case path == "/compartments":
					if r.URL.Query().Get("accessLevel") != "ANY" || r.URL.Query().Get("compartmentIdInSubtree") != "true" {
						t.Error("compartment inventory was permission-filtered")
					}
					if mode == "pagination-loop" {
						w.Header().Set("opc-next-page", "repeat")
					}
					if mode == "descendant-compartment" && page == "" {
						w.Header().Set("opc-next-page", "compartment-2")
					}
					if mode == "descendant-compartment" && page != "" {
						write([]identity.Compartment{{Id: new("ocid1.compartment.oc1..production-child"), CompartmentId: new(s.Compartment), LifecycleState: identity.CompartmentLifecycleStateActive}})
					} else {
						write([]identity.Compartment{{Id: new(s.Compartment), CompartmentId: new(s.Tenancy), LifecycleState: identity.CompartmentLifecycleStateActive}})
					}
				case path == "/policies":
					if r.URL.Query().Get("compartmentId") == s.Tenancy {
						if page == "" {
							w.Header().Set("opc-next-page", "policy-2")
							subject := "Administrators"
							if mode == "domain-subject" {
								subject = "Default/Administrators"
							}
							write([]identity.Policy{{Id: new("ocid1.policy.oc1..admin"), CompartmentId: new(s.Tenancy), LifecycleState: identity.PolicyLifecycleStateActive, Statements: []string{"Allow group " + subject + " to manage all-resources in tenancy", "Allow dynamic-group gru-1-controllers to read secret-bundles in compartment id ocid1.compartment.oc1..production"}}})
						} else if mode == "late-policy" || drift.Load() {
							write([]identity.Policy{{Id: new("ocid1.policy.oc1..unknown"), CompartmentId: new(s.Tenancy), LifecycleState: identity.PolicyLifecycleStateActive, Statements: []string{"Allow any-user to manage all-resources in tenancy"}}})
						} else {
							write([]identity.Policy{})
						}
					} else {
						statements := s.PolicyStatements
						if mode == "policy-extra" {
							statements = append(append([]string{}, statements...), "Allow group id "+s.Group+" to manage all-resources in tenancy")
						}
						write([]identity.Policy{{Id: new(s.PolicyID), CompartmentId: new(s.Compartment), LifecycleState: identity.PolicyLifecycleStateActive, Statements: statements}})
					}
				case path == "/subnets/"+s.Subnet:
					write(core.Subnet{Id: new(s.Subnet), CompartmentId: new(s.Compartment), VcnId: new("ocid1.vcn.oc1..disposable"), RouteTableId: new("ocid1.routetable.oc1..disposable"), CidrBlock: new(s.PeerCIDR), ProhibitPublicIpOnVnic: new(true), SecurityListIds: []string{"ocid1.securitylist.oc1..disposable"}, LifecycleState: core.SubnetLifecycleStateAvailable})
				case path == "/subnets":
					if r.URL.Query().Get("compartmentId") != s.Compartment {
						t.Error("subnet inventory is not complete compartment scope")
					}
					if page == "" {
						w.Header().Set("opc-next-page", "subnet-2")
						write([]core.Subnet{{Id: new(s.Subnet), CompartmentId: new(s.Compartment)}})
					} else if mode == "foreign-subnet" {
						write([]core.Subnet{{Id: new("ocid1.subnet.oc1..production"), CompartmentId: new(s.Compartment)}})
					} else {
						write([]core.Subnet{})
					}
				case path == "/vcns/ocid1.vcn.oc1..disposable":
					write(core.Vcn{Id: new("ocid1.vcn.oc1..disposable"), CompartmentId: new(s.Compartment), CidrBlock: new(s.VCNCIDR), LifecycleState: core.VcnLifecycleStateAvailable})
				case path == "/routeTables/ocid1.routetable.oc1..disposable":
					var rules []core.RouteRule
					if mode == "public-route" {
						rules = []core.RouteRule{{Destination: new("0.0.0.0/0"), NetworkEntityId: new("ocid1.internetgateway.oc1..prod")}}
					}
					write(core.RouteTable{Id: new("ocid1.routetable.oc1..disposable"), CompartmentId: new(s.Compartment), VcnId: new("ocid1.vcn.oc1..disposable"), LifecycleState: core.RouteTableLifecycleStateAvailable, RouteRules: rules})
				case path == "/securityLists/ocid1.securitylist.oc1..disposable":
					destination := s.PeerCIDR
					if mode == "external-egress" {
						destination = "0.0.0.0/0"
					}
					write(core.SecurityList{Id: new("ocid1.securitylist.oc1..disposable"), CompartmentId: new(s.Compartment), VcnId: new("ocid1.vcn.oc1..disposable"), LifecycleState: core.SecurityListLifecycleStateAvailable, IngressSecurityRules: []core.IngressSecurityRule{{Source: new(s.PeerCIDR), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, Protocol: new("all")}, {Source: new(s.RunnerCIDR), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, Protocol: new("6"), TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(22), Max: new(22)}}}}, EgressSecurityRules: []core.EgressSecurityRule{{Destination: new(destination), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock, Protocol: new("all")}}})
				case path == "/privateIps":
					if mode == "foreign-host" {
						write([]core.PrivateIp{{Id: new("ocid1.privateip.oc1..foreign"), VnicId: new("ocid1.vnic.oc1..foreign"), SubnetId: new(s.Subnet), CompartmentId: new(s.Compartment), IsPrimary: new(true)}})
					} else {
						write([]core.PrivateIp{})
					}
				case path == "/vnicAttachments":
					write([]core.VnicAttachment{})
				default:
					t.Errorf("unexpected OCI boundary %s", r.URL.Path)
					http.Error(w, "unexpected", http.StatusNotFound)
				}
			}))
			defer server.Close()
			verified, err := observe(t.Context(), observer, candidate, s, server.URL, time.Now())
			if mode != "valid" {
				if err == nil || verified.Factory() != nil {
					t.Fatal("unsafe OCI state produced verified authority")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if verified.EvidenceSHA256() == "" || verified.Factory() == candidate {
					t.Fatal("missing observations or mutable original provider retained")
				}
				evidence := verified.Evidence()
				digest := sha256.Sum256(evidence)
				if len(evidence) == 0 || fmt.Sprintf("%x", digest) != verified.EvidenceSHA256() {
					t.Fatal("retained observation facts differ from evidence digest")
				}
				if err := verified.Revalidate(t.Context(), s); err != nil {
					t.Fatal(err)
				}
				drift.Store(true)
				if err := verified.Revalidate(t.Context(), s); err == nil {
					t.Fatal("new inherited privilege passed pre-effect revalidation")
				}
			}
			if requests.Load() == 0 || writes.Load() != 0 {
				t.Fatal("observer did not cross read-only authenticated HTTP boundary")
			}
		})
	}
}

var authorizationField = regexp.MustCompile(`([a-zA-Z]+)="([^"]*)"`)

func validSignature(r *http.Request, key *rsa.PublicKey, tenancyPrefix string) bool {
	fields := map[string]string{}
	for _, match := range authorizationField.FindAllStringSubmatch(r.Header.Get("Authorization"), -1) {
		fields[match[1]] = match[2]
	}
	if !strings.HasPrefix(fields["keyId"], tenancyPrefix) || fields["algorithm"] != "rsa-sha256" {
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
