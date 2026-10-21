package rootcapacity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func capacityProtocolUserNamespace(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false}
	output, err := child.CombinedOutput()
	t.Logf("user namespace SDK regression:\n%s", output)
	if err != nil {
		t.Fatalf("root read fixture requires an unprivileged user namespace: %v", err)
	}
	return true
}

func capacityProtocolProvider(t *testing.T) common.ConfigurationProvider {
	t.Helper()
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return common.NewRawConfigurationProvider("ocid1.tenancy.oc1..fixture", "ocid1.user.oc1..fixture", "sa-saopaulo-1", "fixture",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
}

func capacityProtocolTransport(t *testing.T, handler http.Handler) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	address, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() || address.Port == 0 {
		t.Fatal("SDK fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fixture refuses plaintext dialing")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errors.New("fixture refuses non-TCP dialing")
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, address.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
}

func capacityProtocolObservation(t *testing.T, ctx context.Context, provider common.ConfigurationProvider) (*attempt, core.ComputeManagementClient) {
	t.Helper()
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := capacitySafetyAttempt()
	a.call, a.deadline, a.observation = call, call.Deadline(), &rootoci.PoolChildObservation{}
	a.factory, err = ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		t.Fatal(err)
	}
	return &a, management
}

// This authenticates SDK reads, never controller writes or admitted child birth.
func TestRootCapacityConfigurationReadbackOCIProtocol(t *testing.T) {
	if capacityProtocolUserNamespace(t) {
		return
	}
	provider := capacityProtocolProvider(t)
	for _, change := range []string{"unchanged", "image", "network", "subnet", "public IP", "metadata", "shape", "OCPUs", "memory", "legacy IMDS", "missing IMDS", "id", "compartment"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			a := capacitySafetyAttempt()
			details := a.configurationRequest().CreateInstanceConfiguration.(core.CreateInstanceConfigurationDetails)
			expectedSHA, err := oci.PoolConfigurationSHA256(details.InstanceDetails)
			if err != nil {
				t.Fatal(err)
			}
			configurationID := "ocid1.instanceconfiguration.oc1..fixture"
			configuration := core.InstanceConfiguration{Id: new(configurationID), CompartmentId: details.CompartmentId,
				DisplayName: details.DisplayName, FreeformTags: details.FreeformTags, InstanceDetails: details.InstanceDetails}
			launch := configuration.InstanceDetails.(core.ComputeInstanceDetails).LaunchDetails
			switch change {
			case "image":
				source := launch.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails)
				source.ImageId = new("ocid1.image.oc1..foreign")
				launch.SourceDetails = source
			case "network":
				launch.CreateVnicDetails.NsgIds = []string{"ocid1.networksecuritygroup.oc1..foreign"}
			case "subnet":
				launch.CreateVnicDetails.SubnetId = new("ocid1.subnet.oc1..foreign")
			case "public IP":
				launch.CreateVnicDetails.AssignPublicIp = new(true)
			case "metadata":
				launch.Metadata["unapproved"] = "bootstrap"
			case "shape":
				launch.Shape = new("VM.Standard.E4.Flex")
			case "OCPUs":
				launch.ShapeConfig.Ocpus = new(float32(4))
			case "memory":
				launch.ShapeConfig.MemoryInGBs = new(float32(24))
			case "legacy IMDS":
				launch.InstanceOptions.AreLegacyImdsEndpointsDisabled = new(false)
			case "missing IMDS":
				launch.InstanceOptions = nil
			case "id":
				configuration.Id = new("ocid1.instanceconfiguration.oc1..foreign")
			case "compartment":
				configuration.CompartmentId = new("ocid1.compartment.oc1..foreign")
			}
			var gets, writes atomic.Int32
			capacityProtocolTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				gets.Add(1)
				if r.URL.Path != "/20160918/instanceConfigurations/"+configurationID || r.URL.RawQuery != "" ||
					r.TLS == nil || !strings.Contains(r.Header.Get("Authorization"), `signature="`) {
					t.Errorf("unexpected configuration SDK read: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.MarshalWrite(w, configuration); err != nil {
					t.Error(err)
				}
			}))
			observed, management := capacityProtocolObservation(t, ctx, provider)
			err = observed.verifyConfiguration(ctx, management, configurationID, expectedSHA)
			if change == "unchanged" && err != nil {
				t.Fatal("exact actual configuration was rejected", err)
			}
			if change != "unchanged" && err == nil {
				t.Fatal("same configuration tags admitted a changed actual launch body or identity")
			}
			if gets.Load() != 1 || writes.Load() != 0 {
				t.Fatalf("readback dispatched gets=%d writes=%d; want one GET only", gets.Load(), writes.Load())
			}
		})
	}
}
