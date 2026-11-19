package appregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var repositoryPath = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}/terrascale/[a-z0-9][a-z0-9._-]{0,127}$`)
var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var pinnedPath = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}@sha256:[0-9a-f]{64}$`)

var ErrOutsideRegionalOCIR = errors.New("request outside regional OCIR")

type credential struct {
	token   string
	expires time.Time
}

type Client struct {
	Host      string
	Namespace string
	Prefix    string
	Sign      func(*http.Request) error
	Transport http.RoundTripper
	mu        sync.Mutex
	tokens    map[string]credential
}

func (c *Client) BoundTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = c.Transport
	}
	if base == nil {
		base = remote.DefaultTransport
	}
	return regionalTransport{host: c.Host, base: base}
}

type regionalTransport struct {
	host string
	base http.RoundTripper
}

func (t regionalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !t.allows(request.URL) {
		return nil, ErrOutsideRegionalOCIR
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if location := response.Header.Get("Location"); response.StatusCode >= 300 && response.StatusCode < 400 && location != "" {
		destination, err := request.URL.Parse(location)
		if err != nil || !t.allows(destination) {
			return nil, errors.Join(ErrOutsideRegionalOCIR, response.Body.Close())
		}
	}
	return response, nil
}

func (t regionalTransport) allows(target *url.URL) bool {
	return target.Scheme == "https" && target.Host == t.host && target.User == nil
}

func IsImage(image string) bool { return pinnedPath.MatchString(image) }

func Package(image string) string {
	repository, _, _ := strings.Cut(image, "@")
	if strings.HasPrefix(repository, "ghcr.io/terrascale/") {
		return strings.TrimPrefix(repository, "ghcr.io/terrascale/")
	}
	if !IsImage(image) {
		return ""
	}
	return repository
}

func (c *Client) Image(image string) (string, error) {
	if !IsImage(image) {
		return "", errors.New("app image requires a package and manifest digest")
	}
	pkg, digest, _ := strings.Cut(image, "@")
	repository, err := c.Repository(pkg)
	if err != nil {
		return "", err
	}
	return repository + "@" + digest, nil
}

func (c *Client) path(pkg string) (string, error) {
	path := c.Namespace + "/" + c.Prefix + "/" + pkg
	if !packageName.MatchString(pkg) || !repositoryPath.MatchString(path) {
		return "", errors.New("invalid app repository")
	}
	return path, nil
}

func (c *Client) Repository(pkg string) (string, error) {
	path, err := c.path(pkg)
	if err != nil {
		return "", err
	}
	return c.Host + "/" + path, nil
}

func (c *Client) Keychain(ctx context.Context, pkg string) (authn.Keychain, error) {
	repository, err := c.path(pkg)
	if err != nil {
		return nil, err
	}
	token, err := c.token(ctx, repository)
	if err != nil {
		return nil, err
	}
	return keychain{host: c.Host, auth: authn.FromConfig(authn.AuthConfig{RegistryToken: token})}, nil
}

func (c *Client) Token(ctx context.Context, image string) (string, error) {
	if !IsImage(image) {
		return "", errors.New("app token requires a package and manifest digest")
	}
	repository, err := c.path(Package(image))
	if err != nil {
		return "", err
	}
	return c.token(ctx, repository)
}

func (c *Client) token(ctx context.Context, repository string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if cached := c.tokens[repository]; time.Until(cached.expires) > time.Minute {
		return cached.token, nil
	}
	endpoint := url.URL{Scheme: "https", Host: c.Host, Path: "/20180419/docker/token"}
	endpoint.RawQuery = url.Values{"service": {c.Host}, "scope": {"repository:" + repository + ":pull"}}.Encode()
	issued := time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if c.Sign == nil {
		return "", errors.New("OCIR requires instance-principal request signing")
	}
	if err := c.Sign(request); err != nil {
		return "", err
	}
	client := &http.Client{Transport: c.BoundTransport(nil), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("OCIR token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OCIR token request: HTTP %d", response.StatusCode)
	}
	var result struct {
		Token     string `json:"token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return "", errors.New("invalid OCIR token response")
	}

	if result.Token == "" || result.ExpiresIn <= 60 || result.ExpiresIn > 86400 {
		return "", errors.New("OCIR returned an empty or invalid token lifetime")
	}
	value := credential{result.Token, issued.Add(time.Duration(result.ExpiresIn) * time.Second)}
	if time.Until(value.expires) <= time.Minute {
		return "", errors.New("OCIR returned an expired token")
	}
	if c.tokens == nil {
		c.tokens = map[string]credential{}
	}
	c.tokens[repository] = value
	return value.token, nil
}

type keychain struct {
	host string
	auth authn.Authenticator
}

func (k keychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if resource.RegistryStr() != k.host {
		return nil, errors.New("OCIR credentials requested for another registry")
	}
	return k.auth, nil
}
