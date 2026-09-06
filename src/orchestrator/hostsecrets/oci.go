package hostsecrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"terrascale.tech/orchestrator/src/orchestrator/internal/ociworker"
)

// SDK debug logging can include Vault response bodies and federation material.
// Disable that process-wide SDK sink at package initialization, before requests.
type silentSDKLogger struct{}

func (silentSDKLogger) LogLevel() int                         { return 0 }
func (silentSDKLogger) Log(int, string, ...interface{}) error { return nil }
func init()                                                   { common.SetSDKLogger(silentSDKLogger{}) }

type secretFetcher struct{ client secrets.SecretsClient }

var identityWorker = ociworker.Gate

// The official SDK metadata retry loop sleeps without accepting a context.
// Bound caller latency and serialize that SDK path (which also updates SDK
// metadata globals). Cancellation prevents all subsequent dispatcher calls.
func newInstanceFetcher(ctx context.Context, region string) (*secretFetcher, error) {
	return instanceFetcherWithTransport(ctx, region, credentialTransport())
}
func instanceFetcherWithTransport(ctx context.Context, region string, transport http.RoundTripper) (*secretFetcher, error) {
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrIdentity
	}
	type result struct {
		fetcher *secretFetcher
		err     error
	}
	finished := make(chan result, 1)
	go func() {
		defer func() { <-identityWorker }()
		f, e := constructInstanceFetcher(ctx, region, transport)
		finished <- result{f, e}
	}()
	select {
	case outcome := <-finished:
		return outcome.fetcher, outcome.err
	case <-ctx.Done():
		return nil, ErrIdentity
	}
}
func instanceConfiguration(ctx context.Context, region string, transport http.RoundTripper) (common.ConfigurationProvider, error) {
	modifier := func(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
		client, ok := dispatcher.(*http.Client)
		if !ok {
			return nil, ErrIdentity
		}
		copy := *client
		copy.Transport = transport
		copy.Timeout = 20 * time.Second
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return boundedDispatcher{client: &copy, ctx: ctx, region: region}, nil
	}
	configuration, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(common.Region(region), modifier)
	if err != nil {
		return nil, ErrIdentity
	}
	// Force initial federation inside the bounded identity worker as well.
	if _, err := configuration.KeyID(); err != nil {
		return nil, ErrIdentity
	}
	return configuration, nil
}

func constructInstanceFetcher(ctx context.Context, region string, transport http.RoundTripper) (*secretFetcher, error) {
	configuration, err := instanceConfiguration(ctx, region, transport)
	if err != nil {
		return nil, err
	}
	client, err := secrets.NewSecretsClientWithConfigurationProvider(configuration)
	if err != nil {
		return nil, ErrIdentity
	}
	client.SetRegion(region)
	client.HTTPClient = boundedDispatcher{client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: ctx, region: region}
	return &secretFetcher{client: client}, nil
}

// boundedDispatcher bounds SDK decoding, including error and federation bodies.
// It deliberately returns fixed labels instead of raw transport errors.
func credentialTransport() *http.Transport {
	return &http.Transport{
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

type boundedDispatcher struct {
	client *http.Client
	ctx    context.Context
	region string
}

func (d boundedDispatcher) Do(request *http.Request) (*http.Response, error) {
	if err := d.ctx.Err(); err != nil {
		return nil, ErrFetch
	}
	if request.URL == nil || request.URL.User != nil || request.URL.Fragment != "" {
		return nil, ErrFetch
	}
	host := request.URL.Host
	metadata := request.URL.Scheme == "http" && host == "169.254.169.254" && request.Method == http.MethodGet
	cloud := request.URL.Scheme == "https" && (host == "auth."+d.region+".oraclecloud.com" || host == "secrets.vaults."+d.region+".oci.oraclecloud.com")
	if !metadata && !cloud {
		return nil, ErrFetch
	}
	requestCtx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	request = request.Clone(requestCtx)
	response, err := d.client.Do(request)
	if err != nil {
		return nil, ErrFetch
	}
	if response.Body == nil {
		return nil, ErrFetch
	}
	const maximum = 256 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(body) > maximum {
		erase(body)
		return nil, ErrFetch
	}
	response.Body = &erasingReader{Reader: bytes.NewReader(body), body: body}
	return response, nil
}

type erasingReader struct {
	*bytes.Reader
	body []byte
}

func (r *erasingReader) Close() error { erase(r.body); return nil }

func (f *secretFetcher) fetch(ctx context.Context, entry Entry) ([]byte, error) {
	// Signing can refresh federation tokens using SDK-internal sleeps too.
	// Share the single SDK worker limit with initial identity construction.
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrFetch
	}
	type result struct {
		body []byte
		err  error
	}
	completed := make(chan result)
	go func() {
		defer func() { <-identityWorker }()
		body, err := f.fetchBundle(ctx, entry)
		select {
		case completed <- result{body, err}:
		case <-ctx.Done():
			erase(body)
		}
	}()
	select {
	case outcome := <-completed:
		return outcome.body, outcome.err
	case <-ctx.Done():
		return nil, ErrFetch
	}
}
func (f *secretFetcher) fetchBundle(ctx context.Context, entry Entry) ([]byte, error) {
	noRetry := common.NoRetryPolicy()
	response, err := f.client.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{SecretId: common.String(entry.SecretID), VersionNumber: common.Int64(entry.VersionNumber), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return nil, ErrFetch
	}
	if response.SecretId == nil || *response.SecretId != entry.SecretID || response.VersionNumber == nil || *response.VersionNumber != entry.VersionNumber {
		return nil, ErrDigest
	}
	now := time.Now()
	if (response.TimeOfExpiry != nil && !response.TimeOfExpiry.Time.After(now)) || (response.TimeOfDeletion != nil && !response.TimeOfDeletion.Time.After(now)) {
		return nil, ErrFetch
	}
	content, ok := response.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(MaxSecretBytes) {
		return nil, ErrFetch
	}
	body, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || len(body) == 0 || len(body) > MaxSecretBytes {
		erase(body)
		return nil, ErrFetch
	}
	if digest(body) != entry.SHA256 {
		erase(body)
		return nil, ErrDigest
	}
	return body, nil
}
