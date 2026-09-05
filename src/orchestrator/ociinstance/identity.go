// Package ociinstance obtains OCI instance-principal session credentials through
// the official SDK. Private keys and federation tokens remain in host memory.
package ociinstance

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"terrascale.tech/orchestrator/src/orchestrator/internal/ociworker"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

var ErrIdentity = errors.New("ociinstance: instance identity unavailable")
var ErrRequest = errors.New("ociinstance: request denied or unavailable")

const operationTimeout = 30 * time.Second

type silentLogger struct{}

func (silentLogger) LogLevel() int                         { return 0 }
func (silentLogger) Log(int, string, ...interface{}) error { return nil }
func init()                                                { common.SetSDKLogger(silentLogger{}) }

type Options struct {
	// Transport is an explicit qualification seam. Nil selects the restricted
	// production HTTP transport; SDK environment endpoint overrides are denied.
	Transport http.RoundTripper
}

type Identity struct {
	lifetime  context.Context
	cancel    context.CancelFunc
	region    string
	transport http.RoundTripper
	// configuration and active are accessed only while holding ociworker.Gate.
	configuration common.ConfigurationProvider
	active        context.Context
}

func New(ctx context.Context, region string, options Options) (*Identity, error) {
	if ctx == nil || ctx.Err() != nil || !validHomeRegion(region) {
		return nil, ErrIdentity
	}
	lifetime, cancel := context.WithCancel(ctx)
	rt := options.Transport
	if rt == nil {
		rt = productionTransport()
	}
	identity := &Identity{lifetime: lifetime, cancel: cancel, region: region, transport: rt}
	err := identity.run(ctx, func() error {
		modifier := func(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
			client, ok := dispatcher.(*http.Client)
			if !ok {
				return nil, ErrIdentity
			}
			copy := *client
			copy.Transport = rt
			copy.Timeout = 20 * time.Second
			copy.CheckRedirect = noRedirect
			return credentialDispatcher{identity: identity, client: &copy}, nil
		}
		cfg, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(common.Region(region), modifier)
		if err != nil {
			return ErrIdentity
		}
		if _, err = cfg.KeyID(); err != nil {
			return ErrIdentity
		}
		identity.configuration = cfg
		return nil
	})
	if err != nil {
		identity.Close()
		return nil, ErrIdentity
	}
	return identity, nil
}

// run bounds caller latency while retaining the shared SDK worker until a
// context-insensitive SDK retry sleep exits. Every later network call uses the
// canceled active context, so abandoning a wait never creates more authority.
func (i *Identity) run(ctx context.Context, fn func() error) error {
	if i == nil || ctx == nil || ctx.Err() != nil || i.lifetime.Err() != nil {
		return ErrRequest
	}
	bounded, cancel := context.WithTimeout(ctx, operationTimeout)
	stop := context.AfterFunc(i.lifetime, cancel)
	defer func() { stop(); cancel() }()
	select {
	case ociworker.Gate <- struct{}{}:
	case <-bounded.Done():
		return ErrRequest
	}
	done := make(chan error, 1)
	go func() {
		defer func() { <-ociworker.Gate }()
		i.active = bounded
		if bounded.Err() != nil {
			done <- ErrRequest
			return
		}
		done <- fn()
	}()
	select {
	case err := <-done:
		if bounded.Err() != nil {
			return ErrRequest
		}
		return err
	case <-bounded.Done():
		return ErrRequest
	}
}

func (i *Identity) Sign(request *http.Request) error {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Fragment != "" || request.Host != request.URL.Host || !allowedObjectHost(request.URL.Host) {
		return ErrRequest
	}
	copy := request.Clone(request.Context())
	err := i.run(request.Context(), func() error {
		if i.configuration == nil {
			return ErrIdentity
		}
		// OCI's SDK documents a refresh race between KeyID and PrivateRSAKey.
		// Read the token again after the key; retry once if refresh changed it.
		for n := 0; n < 2; n++ {
			id, err := i.configuration.KeyID()
			if err != nil {
				return ErrIdentity
			}
			key, err := i.configuration.PrivateRSAKey()
			if err != nil {
				return ErrIdentity
			}
			again, err := i.configuration.KeyID()
			if err != nil {
				return ErrIdentity
			}
			if id != again {
				continue
			}
			signer, err := provider.NewInstancePrincipalSigner(id, key)
			if err != nil {
				return ErrIdentity
			}
			if i.active.Err() != nil {
				return ErrRequest
			}
			if err = signer.Sign(copy); err != nil {
				return ErrRequest
			}
			return nil
		}
		return ErrIdentity
	})
	if err != nil {
		return ErrRequest
	}
	request.Header = copy.Header
	return nil
}

// NewTransport creates an Object Storage client for this instance's region.
func (i *Identity) NewTransport(service provider.OCIService, maxObjectBytes int64) (*provider.OCIHTTPTransport, error) {
	if i == nil {
		return nil, ErrIdentity
	}
	return i.NewTransportForRegion(service, i.region, maxObjectBytes)
}

// NewTransportForRegion permits signed cross-region object publication without
// obtaining or copying any owner's API signing key.
func (i *Identity) NewTransportForRegion(service provider.OCIService, region string, maxObjectBytes int64) (*provider.OCIHTTPTransport, error) {
	if i == nil || i.lifetime.Err() != nil || service != provider.OCIServiceObjectStorage {
		return nil, ErrRequest
	}
	host, ok := provider.OCIServiceHost(service, region)
	if !ok || !validHomeRegion(region) {
		return nil, ErrRequest
	}
	cfg, err := provider.NewOCIServiceTransportConfig(service, region, "https://"+host)
	if err != nil {
		return nil, ErrRequest
	}
	cfg.MaxObjectBytes = maxObjectBytes
	client := &http.Client{Transport: lifetimeTransport{identity: i, host: host}, Timeout: 30 * time.Second, CheckRedirect: noRedirect}
	return provider.NewOCIHTTPTransport(cfg, client, i)
}

func (i *Identity) Close() error {
	if i == nil {
		return nil
	}
	i.cancel()
	if c, ok := i.transport.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
	return nil
}
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
func productionTransport() *http.Transport {
	return &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}
func allowedObjectHost(host string) bool {
	const prefix = "objectstorage."
	const suffix = ".oraclecloud.com"
	return strings.HasPrefix(host, prefix) && strings.HasSuffix(host, suffix) && validHomeRegion(strings.TrimSuffix(strings.TrimPrefix(host, prefix), suffix))
}

type lifetimeTransport struct {
	identity *Identity
	host     string
}

func (t lifetimeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil || request.URL.Host != t.host || request.Host != t.host || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Fragment != "" || t.identity.lifetime.Err() != nil {
		return nil, ErrRequest
	}
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(t.identity.lifetime, cancel)
	response, err := t.identity.transport.RoundTrip(request.Clone(ctx))
	if err != nil {
		stop()
		cancel()
		return nil, ErrRequest
	}
	if response == nil || response.Body == nil {
		stop()
		cancel()
		return nil, ErrRequest
	}
	response.Body = &cancelBody{ReadCloser: response.Body, finish: func() { stop(); cancel() }}
	return response, nil
}

type cancelBody struct {
	io.ReadCloser
	finish func()
}

func (b *cancelBody) Close() error { defer b.finish(); return b.ReadCloser.Close() }

type credentialDispatcher struct {
	identity *Identity
	client   *http.Client
}

func (d credentialDispatcher) Do(request *http.Request) (*http.Response, error) {
	i := d.identity
	if i.active == nil || i.active.Err() != nil || i.lifetime.Err() != nil || request == nil || request.URL == nil || request.URL.User != nil || request.URL.Fragment != "" || request.URL.RawQuery != "" || request.URL.RawPath != "" || request.URL.Opaque != "" {
		return nil, ErrIdentity
	}
	metadata := request.URL.Scheme == "http" && request.URL.Host == "169.254.169.254" && request.Method == http.MethodGet && (request.URL.Path == "/opc/v2/instance/region" || request.URL.Path == "/opc/v2/identity/cert.pem" || request.URL.Path == "/opc/v2/identity/key.pem" || request.URL.Path == "/opc/v2/identity/intermediate.pem")
	federation := request.URL.Scheme == "https" && request.URL.Host == "auth."+i.region+".oraclecloud.com" && request.Method == http.MethodPost && request.URL.Path == "/v1/x509"
	if !metadata && !federation {
		return nil, ErrIdentity
	}
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(i.active, cancel)
	lifeStop := context.AfterFunc(i.lifetime, cancel)
	defer func() { stop(); lifeStop(); cancel() }()
	response, err := d.client.Do(request.Clone(ctx))
	if err != nil {
		return nil, ErrIdentity
	}
	if response == nil || response.Body == nil {
		return nil, ErrIdentity
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	closed := response.Body.Close()
	if err != nil || closed != nil || len(body) > 256<<10 {
		clear(body)
		return nil, ErrIdentity
	}
	// The region response must match the explicitly configured home region.
	if metadata && request.URL.Path == "/opc/v2/instance/region" && !matchesMetadataRegion(string(body), i.region) {
		clear(body)
		return nil, ErrIdentity
	}
	response.Body = &erasingBody{Reader: bytes.NewReader(body), body: body}
	return response, nil
}

type erasingBody struct {
	*bytes.Reader
	body []byte
}

func (b *erasingBody) Close() error { clear(b.body); return nil }
