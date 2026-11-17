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
)

var repositoryPath = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}/terrascale/[a-z0-9][a-z0-9._-]{0,127}$`)
var pinnedPath = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}/terrascale/[a-z0-9][a-z0-9._-]{0,127}@sha256:[0-9a-f]{64}$`)

type credential struct {
	token   string
	expires time.Time
}

type Client struct {
	Host      string
	Namespace string
	Sign      func(*http.Request) error
	Transport http.RoundTripper
	mu        sync.Mutex
	tokens    map[string]credential
}

func IsImage(image string) bool { return pinnedPath.MatchString(image) }

func Package(image string) string {
	repository, _, _ := strings.Cut(image, "@")
	if strings.HasPrefix(repository, "ghcr.io/terrascale/") {
		return strings.TrimPrefix(repository, "ghcr.io/terrascale/")
	}
	if !repositoryPath.MatchString(repository) {
		return ""
	}
	_, repository, _ = strings.Cut(repository, "/terrascale/")
	return repository
}

func (c *Client) Image(image string) (string, error) {
	if !IsImage(image) || !strings.HasPrefix(image, c.Namespace+"/terrascale/") {
		return "", errors.New("app image is outside the tenancy repository or lacks a manifest digest")
	}
	return c.Host + "/" + image, nil
}

func (c *Client) Repository(pkg string) (string, error) {
	path := c.Namespace + "/terrascale/" + pkg
	if !repositoryPath.MatchString(path) {
		return "", errors.New("invalid app repository")
	}
	return c.Host + "/" + path, nil
}

func (c *Client) Keychain(ctx context.Context, repository string) (authn.Keychain, error) {
	if !repositoryPath.MatchString(repository) || !strings.HasPrefix(repository, c.Namespace+"/terrascale/") {
		return nil, errors.New("OCIR token scope differs from the app repository")
	}
	token, err := c.token(ctx, repository)
	if err != nil {
		return nil, err
	}
	return keychain{host: c.Host, auth: authn.FromConfig(authn.AuthConfig{RegistryToken: token})}, nil
}

func (c *Client) Token(ctx context.Context, image string) (string, error) {
	if _, err := c.Image(image); err != nil {
		return "", err
	}
	repository, _, _ := strings.Cut(image, "@")
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
	client := &http.Client{Transport: c.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("OCIR token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OCIR token request: HTTP %d", response.StatusCode)
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresIn int64     `json:"expires_in"`
		IssuedAt  time.Time `json:"issued_at"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return "", errors.New("invalid OCIR token response")
	}
	if result.IssuedAt.IsZero() {
		result.IssuedAt = time.Now()
	}
	if result.Token == "" || result.ExpiresIn <= 60 || result.ExpiresIn > 86400 {
		return "", errors.New("OCIR returned an empty or invalid token lifetime")
	}
	value := credential{result.Token, result.IssuedAt.Add(time.Duration(result.ExpiresIn) * time.Second)}
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
