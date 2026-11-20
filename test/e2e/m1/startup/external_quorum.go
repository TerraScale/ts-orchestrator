package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func externalIdentityJourney(ctx context.Context) error {
	region, err := fleet.Embedded().Region("gru")
	if err != nil {
		return err
	}
	mode := "missing"
	requested := map[string]bool{}
	ownership := ociresource.Ownership{Owner: fleet.Owner}
	tags := func(kind, name string) map[string]string {
		return ownership.Stamp(region.Key(kind, name), 1, "journey").Freeform
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requested[r.URL.Path] = true
		if r.Method != http.MethodGet {
			http.Error(w, "compute must refuse before an OCI mutation", http.StatusBadRequest)
			return
		}
		instance := map[string]any{"id": "instance-0", "displayName": "ts-gru-1", "compartmentId": region.CompartmentID, "lifecycleState": "RUNNING"}
		if mode == "stopped" {
			instance["lifecycleState"] = "STOPPED"
		}
		if mode == "compartment" {
			instance["compartmentId"] = "other-compartment"
		}
		if mode == "owned" {
			instance["freeformTags"] = tags("instance", "node")
		}
		vcn := "regional-vcn"
		if mode == "vcn" || mode == "copied-subnet" {
			vcn = "other-vcn"
		}
		var body any
		switch r.URL.Path {
		case "/20160918/vcns":
			body = []any{map[string]any{"id": "regional-vcn", "compartmentId": region.CompartmentID, "lifecycleState": "AVAILABLE", "cidrBlocks": []string{region.VCNCIDR}, "freeformTags": tags("vcn", "vcn")}}
			if mode == "no-external" {
				body = append(body.([]any), map[string]any{"id": "rebuilt-vcn", "compartmentId": region.CompartmentID, "lifecycleState": "AVAILABLE", "cidrBlocks": []string{region.VCNCIDR}, "freeformTags": tags("vcn", "vcn")})
			}
		case "/20160918/subnets":
			body = []any{map[string]any{"id": "private-subnet", "vcnId": "regional-vcn", "cidrBlock": region.PrivateSubnetCIDR, "prohibitPublicIpOnVnic": true, "lifecycleState": "AVAILABLE", "freeformTags": tags("subnet", "private-subnet")}}
			if mode == "copied-subnet" {
				body = append([]any{map[string]any{"id": "copied-private-subnet", "vcnId": "other-vcn", "cidrBlock": region.PrivateSubnetCIDR, "prohibitPublicIpOnVnic": true, "lifecycleState": "AVAILABLE", "freeformTags": tags("subnet", "private-subnet")}}, body.([]any)...)
			}
		case "/20160918/networkSecurityGroups":
			body = []any{map[string]any{"id": "node-nsg", "vcnId": "regional-vcn", "lifecycleState": "AVAILABLE", "freeformTags": tags("nsg", "node-nsg")}}
		case "/20160918/instances":
			body = []any{instance}
			if mode == "missing" {
				body = []any{}
			}
			if mode == "ambiguous" {
				body = []any{instance, instance}
			}
		case "/20160918/instances/instance-0":
			body = instance
		case "/20160918/vnicAttachments":
			body = []any{map[string]any{"instanceId": "instance-0", "vnicId": "primary", "lifecycleState": "ATTACHED"}}
			if mode == "detached" {
				body = []any{}
			}
		case "/20160918/vnics/primary":
			body = map[string]any{"id": "primary", "subnetId": "host-subnet", "isPrimary": true}
		case "/20160918/subnets/host-subnet":
			body = map[string]any{"id": "host-subnet", "vcnId": vcn, "compartmentId": region.CompartmentID}
		case "/20160918/instancePools":
			body = []any{map[string]any{"id": "pool", "lifecycleState": "RUNNING"}}
			if mode == "terminating-pool" {
				body = []any{map[string]any{"id": "pool", "lifecycleState": "TERMINATING"}}
			}
		case "/20160918/instancePools/pool/instances":
			body = []any{}
			if mode == "pooled" || mode == "terminating-pool" {
				body = []any{map[string]any{"id": "instance-0"}}
			}
		default:
			http.Error(w, "unexpected OCI request: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			panic(err)
		}
	}))
	defer endpoint.Close()
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.Listener.Addr().String())
	}}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = original
		transport.CloseIdleConnections()
	}()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	provider := common.NewRawConfigurationProvider("tenancy", "user", region.OCIRegion, "00:11", private, nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: region.OCIRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		return err
	}
	for _, refusal := range []struct{ mode, reason string }{
		{"missing", "expected one live OCI instance"}, {"ambiguous", "expected one live OCI instance"},
		{"stopped", "must be RUNNING"}, {"compartment", "must be RUNNING"},
		{"owned", "pool instance ownership"}, {"detached", "no attached primary VNIC"},
		{"vcn", "outside region VCN"}, {"copied-subnet", "outside region VCN"}, {"pooled", "belongs to instance pool"}, {"terminating-pool", "belongs to instance pool"},
	} {
		mode = refusal.mode
		err := fleet.ApplyCompute(ctx, fleet.Embedded(), region, factory, nil, ociresource.Out{Apply: true, Same: io.Discard, Changed: io.Discard})
		if err == nil || !strings.Contains(err.Error(), "refusing compute minimum 2") || !strings.Contains(err.Error(), refusal.reason) {
			return fmt.Errorf("external %s did not refuse compute: %v", mode, err)
		}
	}
	mode, requested = "no-external", map[string]bool{}
	bare := region
	bare.Nodes.External = nil
	err = fleet.ApplyCompute(ctx, fleet.Embedded(), bare, factory, nil, ociresource.Out{Apply: true, Same: io.Discard, Changed: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "list availability domains") ||
		requested["/20160918/vcns"] || requested["/20160918/instances"] || requested["/20160918/instancePools"] || !requested["/20160918/subnets"] || !requested["/20160918/networkSecurityGroups"] {
		return fmt.Errorf("compute without external hosts left the plain path: requests %v: %v", requested, err)
	}
	fmt.Println("ok external identity: a region without external hosts selects its subnet and NSG with a second owned VCN present and reads no VCN or external host")
	mode = "running"
	compute, err := factory.Compute()
	if err != nil {
		return err
	}
	management, err := factory.ComputeManagement()
	if err != nil {
		return err
	}
	network, err := factory.Network()
	if err != nil {
		return err
	}
	verified, err := fleet.VerifyExternal(ctx, region, compute, management, network, "regional-vcn")
	if err != nil || verified["instance-0"] != "ts-gru-1" {
		return fmt.Errorf("running external identity was not verified: %v %v", verified, err)
	}
	if err := computeMutationJourney(ctx, region, factory); err != nil {
		return err
	}
	fmt.Println("ok external identity: compute refuses missing, ambiguous, stopped, wrong-compartment, owned, detached, wrong-VCN and pooled hosts; running non-pool host verified")
	return nil
}

func regionalQuorumJourney(ctx context.Context, state string, ready bool, inventory func(context.Context) error) error {
	region := fleet.Region{Label: "gru", OCIRegion: "sa-saopaulo-1", Nodes: fleet.Nodes{Min: 2, Max: 2, External: []string{"worker-0"}}}
	eligible := map[string]string{"manager": "manager", "instance-0": "worker-0", "instance-1": "worker-1"}
	before := fleet.QuorumCheck(region, regionhealth.ReadQuorum(ctx, state), eligible)
	if before.State != fleet.Ok {
		return fmt.Errorf("regional quorum must start at three votes: %+v", before)
	}
	checks := fleet.QuorumChecks(ctx, region, func(ctx context.Context) (map[string]string, error) {
		return eligible, inventory(ctx)
	}, func(ctx context.Context) fleet.QuorumObservation { return regionhealth.ReadQuorum(ctx, state) })
	check := checks[len(checks)-1]
	gate := fleet.RequireQuorum([]fleet.Report{{Name: "gru", Checks: checks}})
	if len(checks) != 1 || (check.State == fleet.Ok) != ready || (gate == nil) != ready {
		return fmt.Errorf("regional quorum ready=%t: %+v; %v", ready, checks, gate)
	}
	if !ready && (len(check.Details) == 0 || !strings.Contains(check.Details[0], "2/3")) {
		return fmt.Errorf("external host demoted during the OCI inventory should leave exactly two votes: %+v", check)
	}
	fmt.Printf("ok regional quorum: started %s, decided ready=%t on %s\n", before.Details[0], ready, check.Details[0])
	return nil
}
