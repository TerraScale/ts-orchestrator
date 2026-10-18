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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// These read-only SDK listings do not establish launch or admission authority.
func TestRootCapacityListingPaginationOCIProtocol(t *testing.T) {
	if os.Geteuid() != 0 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootCapacityListingPaginationOCIProtocol$", "-test.v")
		child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			GidMappingsEnableSetgroups: false}
		output, err := child.CombinedOutput()
		t.Logf("user namespace SDK regression:\n%s", output)
		if err != nil {
			t.Fatalf("root read fixture requires an unprivileged user namespace: %v", err)
		}
		return
	}
	// OCI vendor switch preserves the pinned loopback transport instead of installing ambient proxies.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..fixture", "ocid1.user.oc1..fixture", "sa-saopaulo-1", "fixture",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	for _, listing := range []string{"shapes", "pools", "members"} {
		for _, scenario := range []struct {
			name       string
			next       []string
			cycle      bool
			emptyFinal bool
		}{
			{name: "self cycle", next: []string{"A", "A"}, cycle: true},
			{name: "two token cycle", next: []string{"A", "B", "A"}, cycle: true},
			{name: "finite absent final token", next: []string{"A", "B", ""}},
			{name: "finite empty final token", next: []string{"A", "B", ""}, emptyFinal: true},
		} {
			t.Run(listing+"/"+scenario.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				call, err := rootoci.RootCall(ctx)
				if err != nil {
					t.Fatal(err)
				}
				pages := make(chan string, 129)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					index := len(pages)
					if index >= len(scenario.next) {
						t.Error("listing requested another page after termination or repeated token")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					pages <- r.URL.Query().Get("page")
					path := "/20160918/" + map[string]string{"shapes": "shapes", "pools": "instancePools", "members": "instancePools/ocid1.instancepool.oc1..fixture/instances"}[listing]
					query := r.URL.Query()
					if r.Method != http.MethodGet || r.URL.Path != path || query.Get("compartmentId") != "ocid1.compartment.oc1..fixture" ||
						r.TLS == nil || !strings.Contains(r.Header.Get("Authorization"), `signature="`) {
						t.Errorf("unexpected signed listing request: %s %s", r.Method, r.URL)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if listing == "shapes" && (query.Get("availabilityDomain") != "AD-1" || query.Get("imageId") != "ocid1.image.oc1..fixture") ||
						listing == "pools" && query.Get("displayName") != "original-pool" {
						t.Error("listing changed its original image, AD or pool name scope")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if next := scenario.next[index]; next != "" || scenario.emptyFinal {
						w.Header().Set("opc-next-page", next)
					}
					var items any
					switch listing {
					case "shapes":
						shapes := []core.Shape{}
						if !scenario.cycle && index == len(scenario.next)-1 {
							shapes = append(shapes, core.Shape{Shape: new(nodescale.PreferredShape), ProcessorDescription: new("Ampere"), IsFlexible: new(true),
								OcpuOptions:   &core.ShapeOcpuOptions{Min: new(float32(1)), Max: new(float32(4))},
								MemoryOptions: &core.ShapeMemoryOptions{MinInGBs: new(float32(1)), MaxInGBs: new(float32(24)), MinPerOcpuInGBs: new(float32(1)), MaxPerOcpuInGBs: new(float32(12))}})
						}
						items = shapes
					case "pools":
						items = []core.InstancePoolSummary{{Id: new(fmt.Sprintf("ocid1.instancepool.oc1..%d", index)), DisplayName: new("original-pool"),
							CompartmentId: new("ocid1.compartment.oc1..fixture"), LifecycleState: core.InstancePoolSummaryLifecycleStateTerminated}}
					case "members":
						items = []core.InstanceSummary{{Id: new(fmt.Sprintf("ocid1.instance.oc1..%d", index)), State: new("RUNNING")}}
					}
					if err := json.MarshalWrite(w, items); err != nil {
						t.Error(err)
					}
				}))
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
				t.Cleanup(func() {
					http.DefaultTransport = previous
					transport.CloseIdleConnections()
				})
				factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1"})
				if err != nil {
					t.Fatal(err)
				}
				a := &attempt{call: call, deadline: call.Deadline(), factory: factory, observation: &rootoci.PoolChildObservation{},
					receipt: budget.Reservation{CompartmentID: "ocid1.compartment.oc1..fixture"},
					record:  region.FoundationRecord{CapacityPools: map[string]region.PoolResourceRecord{"ocid1.instancepool.oc1..fixture": {CompartmentID: "ocid1.compartment.oc1..fixture"}}},
					recipe:  nodescale.Recipe{ImageID: "ocid1.image.oc1..fixture", Capacity: nodescale.Capacity{Shape: nodescale.PreferredShape, Architecture: "arm64"}, OCPUs: 2, MemoryGB: 12}}
				var members []core.InstanceSummary
				if listing == "shapes" {
					err = a.validateShapeResources(ctx, "AD-1")
				} else {
					management, clientErr := factory.ComputeManagement()
					if clientErr != nil {
						t.Fatal(clientErr)
					}
					if listing == "pools" {
						err = a.rejectPoolCollision(ctx, management, "original-pool")
					} else {
						members, err = a.members(ctx, management, "ocid1.instancepool.oc1..fixture")
					}
				}
				if scenario.cycle {
					if err == nil || !strings.Contains(err.Error(), "repeated") || members != nil {
						t.Fatalf("cycle returned err=%v, members=%v; want token refusal without partial members", err, members)
					}
				} else if err != nil || listing == "members" && len(members) != len(scenario.next) {
					t.Fatalf("finite listing returned err=%v, members=%v", err, members)
				}
				close(pages)
				var got []string
				for page := range pages {
					got = append(got, page)
				}
				want := append([]string{""}, scenario.next[:len(scenario.next)-1]...)
				if !slices.Equal(got, want) {
					t.Fatalf("page requests=%q, want %q", got, want)
				}
			})
		}
	}
}
