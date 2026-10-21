package fixturegen

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/tests/firecracker/production"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const fixtureTenancyOCID = "ocid1.tenancy.oc1..restartfixture"

type packetSimulatorDispatcher struct {
	t       *testing.T
	server  *httptest.Server
	client  *http.Client
	allowed map[string][]byte
}

func newPacketSimulatorDispatcher(t *testing.T, config production.Config) (*production.Simulator, packetSimulatorDispatcher) {
	t.Helper()
	simulator, err := production.NewSimulator(config)
	if err != nil {
		t.Fatalf("simulator rejected packet routes: %v", err)
	}
	server := httptest.NewServer(simulator)
	t.Cleanup(server.Close)
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	allowed := map[string][]byte{"POST\nauth.sa-saopaulo-1.oraclecloud.com\n/v1/x509": nil}
	for _, path := range []string{"/opc/v2/instance/id", "/opc/v2/instance/metadata/terrascale-bootstrap",
		"/opc/v2/instance/region", "/opc/v2/identity/cert.pem", "/opc/v2/identity/key.pem",
		"/opc/v2/identity/intermediate.pem", "/opc/v2/vnics/"} {
		allowed["GET\n169.254.169.254\n"+path] = nil
	}
	for _, read := range config.Reads {
		allowed["GET\n"+read.Host+"\n"+read.RequestURI] = bytes.Clone(read.Body)
	}
	return simulator, packetSimulatorDispatcher{t: t, server: server, client: client, allowed: allowed}
}

func (dispatcher packetSimulatorDispatcher) Do(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	if request.Host == "" {
		request.Host = request.URL.Host
	}
	key := request.Method + "\n" + request.Host + "\n" + request.URL.RequestURI()
	expected, allowed := dispatcher.allowed[key]
	if !allowed || request.Host != request.URL.Host {
		return nil, fmt.Errorf("SDK request is outside exact packet routes")
	}
	request.URL.Scheme = "http"
	request.URL.Host = strings.TrimPrefix(dispatcher.server.URL, "http://")
	request.RequestURI = ""
	response, err := dispatcher.client.Do(request)
	if err != nil || expected == nil {
		return response, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(expected))+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) {
		return nil, fmt.Errorf("SDK socket response differs from packet provider bytes: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	dispatcher.t.Logf("SDK socket response route_sha256=%x body_sha256=%x", sha256.Sum256([]byte(key)), sha256.Sum256(body))
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

// assertPacketComputeSDK exercises the signed packet's exact routes through
// the real instance-principal SDK. The fixturetest build also repeats these
// reads through the production instance observer.
func assertPacketComputeSDK(t *testing.T, packet VerifiedPacket, slot string,
	observed ObservedController, vnic GuestObservation,
) {
	t.Helper()
	config, err := packet.SimulatorConfig(slot)
	if err != nil {
		t.Fatal(err)
	}
	if config.PrimaryPrivateIP != vnic.PrimaryPrivateIP {
		t.Fatalf("%s simulator VNIC address = %q, want %q", slot, config.PrimaryPrivateIP, vnic.PrimaryPrivateIP)
	}
	simulator, dispatcher := newPacketSimulatorDispatcher(t, config)
	defer dispatcher.server.Close()
	provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(
		common.Region("sa-saopaulo-1"),
		func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) { return dispatcher, nil })
	if err != nil {
		t.Fatalf("%s instance principal configuration: %v", slot, err)
	}
	if _, err := provider.KeyID(); err != nil {
		t.Fatalf("%s instance principal federation: %v; requests=%#v", slot, err, simulator.Requests())
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	compute.HTTPClient = dispatcher
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	network.HTTPClient = dispatcher
	instance, err := compute.GetInstance(t.Context(), core.GetInstanceRequest{InstanceId: new(observed.InstanceOCID)})
	if err != nil || instance.Id == nil || *instance.Id != observed.InstanceOCID ||
		instance.Etag == nil || *instance.Etag != observed.ETag ||
		instance.CompartmentId == nil || instance.ImageId == nil ||
		instance.AvailabilityDomain == nil || instance.FaultDomain == nil || instance.Shape == nil ||
		instance.LifecycleState != core.InstanceLifecycleStateRunning {
		t.Fatalf("%s SDK GetInstance decoded unexpected response: %+v, %v", slot, instance, err)
	}
	attachments, err := compute.ListVnicAttachments(t.Context(), core.ListVnicAttachmentsRequest{
		CompartmentId: instance.CompartmentId, InstanceId: new(observed.InstanceOCID), Limit: new(50),
	})
	if err != nil || len(attachments.Items) != 1 ||
		attachments.Items[0].VnicId == nil || *attachments.Items[0].VnicId != vnic.PrimaryVNICOCID ||
		attachments.Items[0].LifecycleState != core.VnicAttachmentLifecycleStateAttached {
		t.Fatalf("%s SDK ListVnicAttachments decoded unexpected response: %+v, %v", slot, attachments, err)
	}
	primary, err := network.GetVnic(t.Context(), core.GetVnicRequest{VnicId: new(vnic.PrimaryVNICOCID)})
	if err != nil || primary.Id == nil || *primary.Id != vnic.PrimaryVNICOCID ||
		primary.PrivateIp == nil || *primary.PrivateIp != vnic.PrimaryPrivateIP ||
		primary.SubnetId == nil || primary.CompartmentId == nil || primary.AvailabilityDomain == nil ||
		*primary.CompartmentId != vnic.NetworkCompartmentOCID ||
		primary.IsPrimary == nil || !*primary.IsPrimary ||
		primary.LifecycleState != core.VnicLifecycleStateAvailable {
		t.Fatalf("%s SDK GetVnic decoded unexpected response: %+v, %v", slot, primary, err)
	}
	subnet, err := network.GetSubnet(t.Context(), core.GetSubnetRequest{SubnetId: primary.SubnetId})
	if err != nil || subnet.Id == nil || *subnet.Id != *primary.SubnetId ||
		subnet.CompartmentId == nil || *subnet.CompartmentId != vnic.NetworkCompartmentOCID ||
		*subnet.CompartmentId == *instance.CompartmentId ||
		subnet.VcnId == nil || *subnet.VcnId != vnic.VCNOCID ||
		subnet.AvailabilityDomain == nil || *subnet.AvailabilityDomain != *primary.AvailabilityDomain ||
		subnet.LifecycleState != core.SubnetLifecycleStateAvailable {
		t.Fatalf("%s SDK GetSubnet decoded unexpected network identity: %+v, %v", slot, subnet, err)
	}
	additionalComputeReads := assertPacketComputeObserver(t, provider, &compute, &network,
		observed, vnic, instance, primary, config)
	computeReads := 0
	for _, request := range simulator.Requests() {
		if !request.Listed || request.Status != http.StatusOK {
			t.Fatalf("%s SDK used an unlisted or failed route: %+v", slot, request)
		}
		if request.Host == "iaas.sa-saopaulo-1.oraclecloud.com" {
			computeReads++
		}
	}
	if computeReads != 4+additionalComputeReads || simulator.OverflowCount() != 0 {
		t.Fatalf("%s SDK Compute request count = %d, audit overflow = %d", slot,
			computeReads, simulator.OverflowCount())
	}
}

func fixtureInstanceCertificate(t *testing.T) (certificate, key, intermediate []byte) {
	t.Helper()
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline fixture intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate,
		&issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{
			CommonName: "offline fixture instance",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 13},
				Value: "opc-tenant:" + fixtureTenancyOCID}},
		},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer,
		&leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
}
