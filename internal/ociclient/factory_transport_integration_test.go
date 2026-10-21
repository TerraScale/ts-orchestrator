package ociclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestFactorySDKTransportReuseThroughVerifiedTLSHTTP(t *testing.T) {
	type observation struct {
		server         int
		remote, host   string
		otherPrincipal bool
	}
	observed := make(chan observation, 16)
	var calls atomic.Int32
	var connections [2]atomic.Int32
	var servers [2]*httptest.Server
	for index := range servers {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			authorization := r.Header.Get("Authorization")
			if r.TLS == nil || !strings.Contains(authorization, `signature="`) || !strings.Contains(authorization, `keyId="ocid1.tenancy.oc1..t/`) {
				t.Error("expected verified TLS and a signed SDK request")
			}
			observed <- observation{server: index, remote: r.RemoteAddr, host: r.Host,
				otherPrincipal: strings.Contains(authorization, "/ocid1.user.oc1..other/")}
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodHead {
				_, _ = io.WriteString(w, `{"id":"ocid1.instance.oc1..a","lifecycleState":"RUNNING"}`)
			}
		}))
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections[index].Add(1)
			}
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		servers[index] = server
	}
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	install := func(server *httptest.Server) {
		t.Helper()
		listener, ok := server.Listener.Addr().(*net.TCPAddr)
		if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
			t.Fatal("SDK transport fixture requires literal loopback TLS")
		}
		transport := previous.(*http.Transport).Clone()
		transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("fixture refuses plaintext dialing")
		}
		transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errors.New("fixture refuses non-TCP network")
			}
			return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
		}
		http.DefaultTransport = transport
		t.Cleanup(transport.CloseIdleConnections)
	}
	install(servers[0])
	provider := testProvider(t)
	newFactory := func(provider common.ConfigurationProvider) *Factory {
		t.Helper()
		factory, err := New(provider, Options{Region: "sa-saopaulo-1", Retry: RetryOptions{MaxAttempts: 1}})
		if err != nil {
			t.Fatal(err)
		}
		return factory
	}
	cleanupTransport := func(factory *Factory) {
		transport := factory.transport
		t.Cleanup(func() {
			if transport != nil {
				if delegate, ok := transport.Delegate().(*http.Transport); ok {
					delegate.CloseIdleConnections()
				}
			}
		})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	read := func(factory *Factory, ctx context.Context, host string) observation {
		t.Helper()
		client, err := factory.Compute()
		if err != nil {
			t.Fatal(err)
		}
		cleanupTransport(factory)
		PinHost(&client.BaseClient, host)
		response, err := client.GetInstance(RequestContext(ctx), core.GetInstanceRequest{InstanceId: new("ocid1.instance.oc1..a")})
		if err != nil || response.Id == nil || *response.Id != "ocid1.instance.oc1..a" {
			t.Fatalf("signed SDK read failed: %v", err)
		}
		select {
		case result := <-observed:
			return result
		case <-ctx.Done():
			t.Fatal(ctx.Err())
			return observation{}
		}
	}
	factory := newFactory(provider)
	var revoked atomic.Bool
	denied := errors.New("fixture authority revoked")
	guarded := WithRequestGuard(ctx, func(context.Context) error {
		if revoked.Load() {
			return denied
		}
		return nil
	})
	first := read(factory, guarded, servers[0].URL)
	second := read(factory, guarded, servers[0].URL)
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	cleanupTransport(factory)
	PinHost(&objects.BaseClient, "https://"+first.host)
	_, err = objects.HeadObject(RequestContext(guarded), objectstorage.HeadObjectRequest{NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("object")})
	if err != nil {
		t.Fatal(err)
	}
	third := <-observed
	if first.remote != second.remote || first.remote != third.remote || connections[0].Load() != 1 {
		t.Fatalf("new Compute/ObjectStorage clients opened %d TLS connections, want one", connections[0].Load())
	}
	revoked.Store(true)
	client, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	PinHost(&client.BaseClient, servers[0].URL)
	_, err = client.GetInstance(RequestContext(guarded), core.GetInstanceRequest{InstanceId: new("ocid1.instance.oc1..a")})
	if !errors.Is(err, denied) || calls.Load() != 3 {
		t.Fatalf("revoked authority reached shared transport: calls=%d err=%v", calls.Load(), err)
	}
	fresh := read(factory, ctx, servers[0].URL)
	if fresh.remote != first.remote {
		t.Fatal("request authority was retained by the shared transport")
	}
	key, err := provider.PrivateRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	otherProvider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..other", "sa-saopaulo-1", "fp", string(pemKey(key)), nil)
	other := read(newFactory(otherProvider), ctx, servers[0].URL)
	if other.remote == first.remote || !other.otherPrincipal || first.otherPrincipal {
		t.Fatal("distinct factories shared a connection or signing principal")
	}
	regional, err := factory.ForRegion("us-ashburn-1")
	if err != nil {
		t.Fatal(err)
	}
	region := read(regional, ctx, "https://"+first.host)
	if region.remote == first.remote {
		t.Fatal("regional factories shared a connection")
	}
	endpoint := read(factory, ctx, servers[1].URL)
	if endpoint.remote == first.remote || endpoint.host != strings.TrimPrefix(servers[1].URL, "https://") {
		t.Fatal("distinct endpoint reused a different host's connection")
	}
	install(servers[1])
	changed := read(factory, ctx, servers[0].URL)
	if changed.server != 1 || connections[1].Load() != 1 {
		t.Fatal("new SDK client retained the previous default transport template")
	}
	custom, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	custom.HTTPClient = servers[0].Client()
	t.Cleanup(servers[0].Client().CloseIdleConnections)
	PinHost(&custom.BaseClient, servers[0].URL)
	factory.Configure(&custom.BaseClient, ServiceCompute)
	_, err = custom.GetInstance(RequestContext(ctx), core.GetInstanceRequest{InstanceId: new("ocid1.instance.oc1..a")})
	if err != nil {
		t.Fatal(err)
	}
	if result := <-observed; result.server != 0 {
		t.Fatal("public Configure replaced the caller's custom dispatcher")
	}
}
