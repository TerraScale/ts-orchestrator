package publicapi

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

// TestSDKDecodesEveryCommandTheProvisionerSends runs cert, apply and an
// origin-range refresh against the fake and decodes each served command's
// JSON flags into the SDK request types, so the in-binary path accepts
// exactly what the provisioner emits.
func TestSDKDecodesEveryCommandTheProvisionerSends(t *testing.T) {
	d := testDesired(t, ownedPlan)
	f := newFakeOCI(t)
	fc, cloudflare := newFakeCloudflare(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	members := testCA(t)
	if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err != nil {
		t.Fatal(err)
	}
	// A controller dropped out of the ts-auth set and the bandwidth grew.
	auth := field(f.balancer, "backend-sets", "ts-auth").(map[string]any)
	auth["backends"] = auth["backends"].([]any)[:1]
	grown := testDesired(t, strings.NewReplacer(`"max_mbps":100`, `"max_mbps":200`).Replace(ownedPlan))
	if _, err := p.Provision(t.Context(), grown, cloudflare, members, ""); err != nil {
		t.Fatal(err)
	}
	delete(f.balancer["certificates"].(map[string]any), originCertificate)
	fc.ranges = []string{"104.16.0.0/13"}
	for _, plan := range []func() ([]step, error){
		func() ([]step, error) { return p.certSteps(t.Context(), d, cloudflare) },
		func() ([]step, error) { return p.originSteps(t.Context(), d, cloudflare) },
	} {
		steps, err := plan()
		if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
			t.Fatal(err)
		}
	}
	// A renamed auth host rotates the origin certificate and the hostname.
	renamed := grown
	renamed.AuthHost = "gru.login.terrascale.tech"
	if steps, err := p.certSteps(t.Context(), renamed, cloudflare); err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision(t.Context(), renamed, cloudflare, members, ""); err != nil {
		t.Fatal(err)
	}
	decoded := map[string]bool{}
	for _, args := range f.calls {
		command, err := sdkcli.Parse(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if _, ok := creators[command.Path]; !ok {
			continue
		}
		if extra := unacceptedCreateFlags(command); len(extra) > 0 {
			t.Fatalf("%s sends flags its creator does not consume: %v", command.Path, extra)
		}
		var err2 error
		switch command.Path {
		case "network route-table create":
			var rules []core.RouteRule
			err2 = jsonFlag(command, "route-rules", &rules)
		case "network security-list create":
			var ingress []core.IngressSecurityRule
			var egress []core.EgressSecurityRule
			err2 = errors.Join(jsonFlag(command, "ingress-security-rules", &ingress), jsonFlag(command, "egress-security-rules", &egress))
			if len(ingress) != 0 || len(egress) != 2 || *egress[1].TcpOptions.DestinationPortRange.Min != AuthPort {
				t.Fatalf("ingress=%+v egress=%+v", ingress, egress)
			}
		case "network subnet create":
			var lists []string
			err2 = jsonFlag(command, "security-list-ids", &lists)
		case "network nsg rules add":
			var rules []core.AddSecurityRuleDetails
			err2 = jsonFlag(command, "security-rules", &rules)
			if err2 == nil && (len(rules) != 1 || rules[0].Direction != core.AddSecurityRuleDetailsDirectionIngress || rules[0].SourceType != core.AddSecurityRuleDetailsSourceTypeCidrBlock) {
				t.Fatalf("nsg rules %+v", rules)
			}
		case "lb certificate create":
			var details loadbalancer.CreateCertificateDetails
			err2 = jsonFlag(command, "certificate", &details)
			if err2 == nil && (!strings.HasPrefix(*details.CertificateName, originCertificate) || *details.CaCertificate != d.OriginPull.CACertificate) {
				t.Fatalf("certificate %v", *details.CertificateName)
			}
		case "lb load-balancer update-shape":
			var shape loadbalancer.ShapeDetails
			err2 = jsonFlag(command, "shape-details", &shape)
		case "lb backend-set update":
			var details loadbalancer.UpdateBackendSetDetails
			err2 = jsonFlag(command, "details", &details)
			if err2 == nil && (command.Flags["backend-set-name"] != "ts-auth" || len(details.Backends) != len(d.Auth) ||
				details.SslConfiguration != nil || *details.HealthChecker.UrlPath != HealthPath) {
				t.Fatalf("backend set %+v", details)
			}
		case "lb listener update":
			var details loadbalancer.UpdateListenerDetails
			err2 = jsonFlag(command, "details", &details)
			if err2 == nil && (*details.Port != 443 || !strings.HasPrefix(*details.SslConfiguration.CertificateName, originCertificate+"-") ||
				*details.SslConfiguration.VerifyPeerCertificate != true) {
				t.Fatalf("listener %+v", details)
			}
		case "lb load-balancer update":
			var tags map[string]string
			err2 = jsonFlag(command, "freeform-tags", &tags)
			if err2 == nil && tags["terrascale-resource-key"] != d.Owned.String() {
				t.Fatalf("tags %v", tags)
			}
		case "lb hostname update":
			if command.Flags["name"] != "ts-auth" || command.Flags["hostname"] != renamed.AuthHost {
				t.Fatalf("hostname %v", command.Flags)
			}
		case "vault secret update-base64":
			if _, err2 = base64.StdEncoding.DecodeString(command.Flags["secret-content-content"]); err2 == nil && command.Flags["secret-id"] == "" {
				t.Fatal("secret update without an ID")
			}
		case "network nsg rules remove":
			var ids []string
			err2 = jsonFlag(command, "security-rule-ids", &ids)
		case "lb load-balancer create":
			var details loadbalancer.CreateLoadBalancerDetails
			for name, target := range map[string]any{"subnet-ids": &details.SubnetIds, "network-security-group-ids": &details.NetworkSecurityGroupIds,
				"shape-details": &details.ShapeDetails, "certificates": &details.Certificates, "hostnames": &details.Hostnames,
				"backend-sets": &details.BackendSets, "listeners": &details.Listeners, "rule-sets": &details.RuleSets} {
				err2 = errors.Join(err2, jsonFlag(command, name, target))
			}
			redirect, ok := details.RuleSets["https-redirect"].Items[0].(loadbalancer.RedirectRule)
			if err2 == nil && (!ok || *redirect.RedirectUri.Protocol != "HTTPS" || *details.Listeners["ts-auth"].SslConfiguration.VerifyPeerCertificate != true ||
				*details.BackendSets["terrabase"].SslConfiguration.CertificateName != memberCA || *details.ShapeDetails.MaximumBandwidthInMbps != 100) {
				t.Fatalf("load balancer %+v", details)
			}
		}
		if err2 != nil {
			t.Fatalf("%s: %v", command.Path, err2)
		}
		decoded[command.Path] = true
	}
	for path := range creators {
		if !decoded[path] {
			t.Errorf("provisioner never exercised %s", path)
		}
	}
}

func TestSDKNeverHandsSecretsToTheCLI(t *testing.T) {
	called := false
	client := &SDKClient{Region: "sa-saopaulo-1", Backend: sdkcli.BackendAuto, creators: map[string]creator{
		"lb certificate create": func(context.Context, *SDKClient, sdkcli.Command) (any, error) {
			called = true
			return nil, nil
		},
	}}
	_, err := client.Call(t.Context(), "lb", "certificate", "create", "--load-balancer-id", "lb",
		"--certificate", "{}", "--passphrase", "p")
	if !errors.Is(err, sdkcli.ErrUnsupported) || called {
		t.Fatalf("secret-bearing create with an unconsumed flag = %v (called %v)", err, called)
	}
}
