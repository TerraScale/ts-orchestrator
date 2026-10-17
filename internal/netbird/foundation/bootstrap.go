// Package foundation owns the dedicated GRU NetBird service before overlay admission.
package foundation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/net/html"
	"golang.org/x/sys/unix"
)

const (
	ManagementSecretName = "gru-1-netbird-admin-pat"
	ownerSecretName      = "gru-1-netbird-owner-password"
	identitySecretName   = "gru-1-netbird-owner-identity"
	ownerEmail           = "netbird-owner@terrascale.tech"
	serviceName          = "ts-orchestrator"
	publicOrigin         = "https://netbird.terrascale.tech"
)

// BootstrapVault uses the existing instance-principal OCI clients. Values never leave this boundary.
type BootstrapVault struct {
	// StoreGeneration comes from the authenticated foundation record, never peer metadata.
	StoreGeneration string
	Check           func() error
	Target          vaultsecret.Target
	Management      interface {
		vaultsecret.VaultClient
		vaultsecret.VersionClient
	}
	Bundles vaultsecret.BundleClient
}

func (v BootstrapVault) validate() error {
	if v.Management == nil || v.Bundles == nil || v.Target.VaultID == "" || v.Check == nil {
		return errors.New("NetBird bootstrap requires its scoped foundation Vault")
	}
	if v.StoreGeneration == "" || len(v.StoreGeneration) > 256 || strings.TrimSpace(v.StoreGeneration) != v.StoreGeneration || strings.ContainsFunc(v.StoreGeneration, unicode.IsControl) {
		return errors.New("NetBird bootstrap requires its authenticated store generation")
	}
	return v.Check()
}

// BootstrapResult contains references only, suitable for retained operation evidence.
type BootstrapResult struct {
	ManagementPAT vaultsecret.Ref
	SecretID      string
}

type bootstrapClient struct {
	beforeWrite func() error
	base        string
	http        *http.Client
}

func newBootstrapClient(base string) (*bootstrapClient, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("NetBird bootstrap requires a literal loopback HTTP origin")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() {
		return nil, errors.New("NetBird bootstrap requires a literal loopback HTTP origin")
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 10 * time.Second}
	return &bootstrapClient{base: base, http: &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Bootstrap creates an owner through loopback only, then publishes an admin service PAT to Vault.
// The password is committed first, so losing any later response is recoverable through embedded Dex.
func Bootstrap(ctx context.Context, origin, identityDirectory string, vault BootstrapVault) (BootstrapResult, error) {
	var result BootstrapResult
	if err := vault.validate(); err != nil {
		return result, err
	}
	vault.Management = fencedBootstrapVault{vault.Management, vault.Check}
	client, err := newBootstrapClient(origin)
	if err != nil {
		return result, err
	}
	defer client.http.CloseIdleConnections()
	client.beforeWrite = vault.Check
	var instance struct {
		SetupRequired *bool `json:"setup_required"`
	}
	if err = client.api(ctx, "GET", "/instance", "", nil, &instance); err != nil {
		return result, err
	}
	if instance.SetupRequired == nil {
		return result, errors.New("NetBird instance omitted setup status")
	}
	escrow, err := loadOwnerEscrow(identityDirectory)
	if err != nil {
		return result, err
	}
	if escrow.Password != "" && (escrow.Target != vault.Target || escrow.StoreGeneration != vault.StoreGeneration) {
		return result, errors.New("NetBird owner escrow requires authenticated recovery before changing its foundation Vault or store generation")
	}
	escrow.Target = vault.Target
	escrow.StoreGeneration = vault.StoreGeneration
	if *instance.SetupRequired && escrow.SetupAttempt != "" {
		return result, errors.New("NetBird retained setup attempt requires original store restoration or authenticated recovery before bootstrap")
	}
	identity, identityErr := vaultsecret.Read(ctx, vault.Bundles, vault.Target.VaultID, identitySecretName)
	if identityErr != nil && !vaultsecret.Absent(identityErr) {
		return result, errors.New("NetBird retained owner identity unavailable")
	}
	if identityErr != nil {
		identity = escrow.OwnerID
	}
	if *instance.SetupRequired && identity != "" {
		return result, errors.New("NetBird existing identity requires store restoration before bootstrap")
	}
	if identity != "" && escrow.OwnerID != "" && identity != escrow.OwnerID {
		return result, errors.New("NetBird escrow identity differs from Vault")
	}
	password, err := vaultsecret.Read(ctx, vault.Bundles, vault.Target.VaultID, ownerSecretName)
	if err != nil {
		if !vaultsecret.Absent(err) || !*instance.SetupRequired && escrow.Password == "" {
			return result, errors.New("NetBird owner credential unavailable; restore its existing identity and Vault material")
		}
		stored, ensureErr := vaultsecret.Ensure(ctx, vault.Management, vault.Target, ownerSecretName, "NetBird foundation owner recovery credential", func(context.Context) (string, error) {
			if escrow.Password != "" {
				return escrow.Password, nil
			}
			return randomCredential(), nil
		})
		if ensureErr != nil {
			return result, errors.New("NetBird owner credential publication failed")
		}
		password, err = vaultsecret.ReadBack(ctx, vault.Bundles, vault.Target.VaultID, ownerSecretName, stored.Created || stored.Provisioning)
		if err != nil {
			return result, errors.New("NetBird owner credential verification failed")
		}
	}
	if escrow.Password != "" && escrow.Password != password {
		return result, errors.New("NetBird owner escrow differs from Vault")
	}
	escrow.Password = password
	if err = saveOwnerEscrow(identityDirectory, escrow); err != nil {
		return result, err
	}
	if len(password) < 32 || len(password) > 256 {
		return result, errors.New("NetBird owner credential is invalid")
	}
	if *instance.SetupRequired {
		escrow.SetupAttempt = randomCredential()
		if err = saveOwnerEscrow(identityDirectory, escrow); err != nil {
			return result, err
		}
		if err = client.api(ctx, "POST", "/setup", "", map[string]any{"email": ownerEmail, "password": password, "name": "TerraScale foundation owner"}, nil); err != nil {
			return result, err
		}
	}
	if err = client.api(ctx, "GET", "/instance", "", nil, &instance); err != nil {
		return result, err
	}
	if instance.SetupRequired == nil || *instance.SetupRequired {
		return result, errors.New("NetBird initial setup has not closed")
	}
	ref := vaultsecret.Ref{Vault: vault.Target.VaultID, Name: ManagementSecretName}
	current, readErr := vaultsecret.ReadVersioned(ctx, vault.Bundles, ref.Vault, ref.Name)
	if readErr == nil {
		if !netbird.ValidAdminPAT([]byte(current.Value)) {
			return result, errors.New("NetBird Vault service credential is invalid")
		}
		var users []apiUser
		err = client.api(ctx, "GET", "/users", "Token "+current.Value, nil, &users)
		if err == nil {
			if err = client.verifyIdentity(ctx, vault, users, identity, identityDirectory, escrow); err != nil {
				return result, err
			}
			subject, err := serviceSubject(users, "")
			if err != nil {
				return result, err
			}
			for _, user := range users {
				if user.Name == serviceName && user.ID != subject.ID {
					return result, errors.New("NetBird service identity is ambiguous")
				}
			}
			for _, user := range users {
				if user.ID == subject.ID {
					var tokens []apiToken
					if err = client.api(ctx, "GET", "/users/"+user.ID+"/tokens", "Token "+current.Value, nil, &tokens); err != nil {
						return result, err
					}
					count := 0
					fresh := false
					for _, token := range tokens {
						if token.Name == serviceName {
							count++
							fresh = token.Expires.After(time.Now().Add(14 * 24 * time.Hour))
						}
					}
					if count == 1 && fresh {
						return BootstrapResult{ManagementPAT: ref, SecretID: current.SecretID}, nil
					}
				}
			}
		} else {
			status, ok := errors.AsType[*bootstrapStatus](err)
			if !ok || status.code != 401 {
				return result, err
			}
		}

	} else if !vaultsecret.Absent(readErr) {
		return result, errors.New("NetBird Vault service credential read failed")
	}
	jwt, err := client.login(ctx, password)
	if err != nil {
		return result, err
	}
	password = ""
	var users []apiUser
	if err = client.api(ctx, "GET", "/users", "Bearer "+jwt, nil, &users); err != nil {
		return result, err
	}
	if err = client.verifyIdentity(ctx, vault, users, identity, identityDirectory, escrow); err != nil {
		return result, err
	}
	var userID string
	for _, user := range users {
		if user.Name == serviceName {
			if !user.Service || user.Role != "admin" || userID != "" {
				return result, errors.New("NetBird service identity is ambiguous or has the wrong role")
			}
			userID = user.ID
		}
	}
	if userID == "" {
		var user apiUser
		if err = client.api(ctx, "POST", "/users", "Bearer "+jwt, map[string]any{"name": serviceName, "role": "admin", "is_service_user": true, "auto_groups": []string{}}, &user); err != nil {
			return result, err
		}
		userID = user.ID
	}
	if userID == "" || strings.ContainsAny(userID, "/?#%") {
		return result, errors.New("NetBird service identity returned an invalid ID")
	}
	path := "/users/" + userID + "/tokens"
	var tokens []apiToken
	if err = client.api(ctx, "GET", path, "Bearer "+jwt, nil, &tokens); err != nil {
		return result, err
	}
	var token struct {
		Plain    string   `json:"plain_token"`
		Metadata apiToken `json:"personal_access_token"`
	}
	if err = client.api(ctx, "POST", path, "Bearer "+jwt, map[string]any{"name": serviceName, "expires_in": 365}, &token); err != nil {
		return result, err
	}
	if !netbird.ValidAdminPAT([]byte(token.Plain)) || token.Metadata.ID == "" {
		return result, errors.New("NetBird minted an invalid service token")
	}
	var stored vaultsecret.Stored
	if readErr == nil {
		stored, err = vaultsecret.PublishVersion(ctx, vault.Management, ref, current.SecretID, current.Number, []byte(token.Plain))
	} else {
		stored, err = vaultsecret.Ensure(ctx, vault.Management, vault.Target, ref.Name, "NetBird account administration service credential", func(context.Context) (string, error) { return token.Plain, nil })
	}
	if err != nil {
		return result, errors.New("NetBird service credential publication failed")
	}
	saved, err := vaultsecret.ReadBack(ctx, vault.Bundles, ref.Vault, ref.Name, stored.Created || stored.Provisioning)
	if err != nil || saved != token.Plain {
		return result, errors.New("NetBird service credential publication is not verified")
	}
	var publishedUsers []apiUser
	if err = client.api(ctx, "GET", "/users", "Token "+saved, nil, &publishedUsers); err != nil {
		return result, err
	}
	if _, err = serviceSubject(publishedUsers, userID); err != nil {
		return result, err
	}
	// Keep the old CURRENT usable until its replacement is stored and authenticated.
	for _, old := range tokens {
		if old.Name == serviceName && old.ID != token.Metadata.ID {
			if old.ID == "" || strings.ContainsAny(old.ID, "/?#%") {
				return result, errors.New("NetBird token returned an invalid ID")
			}
			if err = client.api(ctx, "DELETE", path+"/"+old.ID, "Bearer "+jwt, nil, nil); err != nil {
				return result, err
			}
		}
	}
	return BootstrapResult{ManagementPAT: ref, SecretID: stored.ID}, nil
}

type apiToken struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expiration_date"`
}

type apiUser struct {
	Current *bool  `json:"is_current"`
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Service bool   `json:"is_service_user"`
}

// NetBird's /users/current rejects service users; /users marks the authenticated subject.
func serviceSubject(users []apiUser, expected string) (apiUser, error) {
	var subject apiUser
	count := 0
	for _, user := range users {
		if user.Current != nil && *user.Current {
			count++
			if count > 1 {
				return apiUser{}, errors.New("NetBird authenticated credential subject is ambiguous")
			}
			subject = user
		}
	}
	if subject.Name != serviceName || !subject.Service || subject.Role != "admin" || subject.ID == "" || strings.ContainsAny(subject.ID, "/?#%") || expected != "" && subject.ID != expected {
		return apiUser{}, errors.New("NetBird Vault credential does not belong to its admin service user")
	}
	return subject, nil
}

func (c *bootstrapClient) verifyIdentity(ctx context.Context, vault BootstrapVault, users []apiUser, expected, identityDirectory string, escrow ownerEscrow) error {
	var owner string
	for _, user := range users {
		if user.Email == ownerEmail && user.Role == "owner" && !user.Service {
			if owner != "" {
				return errors.New("NetBird foundation owner is ambiguous")
			}
			owner = user.ID
		}
	}
	if owner == "" || expected != "" && owner != expected {
		return errors.New("NetBird account differs from its retained owner identity")
	}
	stored, err := vaultsecret.Ensure(ctx, vault.Management, vault.Target, identitySecretName, "NetBird retained owner identity; restore instead of resetting", func(context.Context) (string, error) { return owner, nil })
	if err != nil {
		return errors.New("NetBird owner identity publication failed")
	}
	saved, err := vaultsecret.ReadBack(ctx, vault.Bundles, vault.Target.VaultID, identitySecretName, stored.Created || stored.Provisioning)
	if err != nil || saved != owner {
		return errors.New("NetBird retained owner identity verification failed")
	}
	escrow.OwnerID = owner
	return saveOwnerEscrow(identityDirectory, escrow)
}

type bootstrapStatus struct{ code int }

func (e *bootstrapStatus) Error() string {
	return fmt.Sprintf("NetBird local API returned HTTP %d", e.code)
}

func (c *bootstrapClient) request(ctx context.Context, method, path, authorization, contentType string, body io.Reader) ([]byte, http.Header, int, error) {
	if method != "GET" && c.beforeWrite != nil {
		if err := c.beforeWrite(); err != nil {
			return nil, nil, 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, nil, 0, errors.New("NetBird local request invalid")
	}
	req.Header.Set("Authorization", authorization)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, nil, 0, errors.New("NetBird local request failed")
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(wire) > 1<<20 {
		return nil, nil, 0, errors.New("NetBird local response unreadable or oversized")
	}
	return wire, response.Header, response.StatusCode, nil
}
func (c *bootstrapClient) api(ctx context.Context, method, path, authorization string, in, out any) error {
	var body io.Reader
	if in != nil {
		wire, err := json.Marshal(in)
		if err != nil {
			return errors.New("NetBird local request encoding failed")
		}
		body = bytes.NewReader(wire)
	}
	wire, _, status, err := c.request(ctx, method, "/api"+path, authorization, "application/json", body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &bootstrapStatus{status}
	}
	if out != nil && json.Unmarshal(wire, out) != nil {
		return errors.New("NetBird local response shape invalid")
	}
	return nil
}
func randomCredential() string {
	wire := make([]byte, 32)
	_, _ = rand.Read(wire)
	return base64.RawURLEncoding.EncodeToString(wire)
}

func keyCredential() string {
	wire := make([]byte, 32)
	_, _ = rand.Read(wire)
	return base64.StdEncoding.EncodeToString(wire)
}

// login follows the pinned embedded Dex code flow through loopback; no password grant or public setup PAT switch.
func (c *bootstrapClient) login(ctx context.Context, password string) (string, error) {
	state, verifier := randomCredential(), randomCredential()
	sum := sha256.Sum256([]byte(verifier))
	callback := publicOrigin + "/nb-auth"
	values := url.Values{"client_id": {"netbird-dashboard"}, "response_type": {"code"}, "redirect_uri": {callback}, "scope": {"openid profile email"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "connector_id": {"local"}}
	path := "/oauth2/auth?" + values.Encode()
	method := "GET"
	var body io.Reader
	contentType := ""
	submitted := false
	for range 12 {
		wire, headers, status, err := c.request(ctx, method, path, "", contentType, body)
		if err != nil {
			return "", err
		}
		if status >= 300 && status < 400 {
			next, err := url.Parse(headers.Get("Location"))
			if err != nil {
				return "", errors.New("NetBird login redirect invalid")
			}
			if next.IsAbs() && next.String() != "" && strings.HasPrefix(next.String(), callback+"?") {
				query := next.Query()
				if query.Get("state") != state || query.Get("code") == "" {
					return "", errors.New("NetBird login callback invalid")
				}
				form := url.Values{"client_id": {"netbird-dashboard"}, "grant_type": {"authorization_code"}, "code": {query.Get("code")}, "redirect_uri": {callback}, "code_verifier": {verifier}}
				tokenWire, _, tokenStatus, err := c.request(ctx, "POST", "/oauth2/token", "", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
				if err != nil {
					return "", err
				}
				var token struct {
					ID string `json:"id_token"`
				}
				if tokenStatus != 200 || json.Unmarshal(tokenWire, &token) != nil || token.ID == "" {
					return "", errors.New("NetBird login token exchange failed")
				}
				return token.ID, nil
			}
			if next.IsAbs() && next.Scheme+"://"+next.Host != publicOrigin {
				return "", errors.New("NetBird login refused foreign redirect")
			}
			if !strings.HasPrefix(next.Path, "/oauth2/") {
				return "", errors.New("NetBird login refused unexpected redirect")
			}
			path = next.RequestURI()
			method = "GET"
			body = nil
			contentType = ""
			continue
		}
		if status != 200 || submitted {
			return "", errors.New("NetBird embedded owner login failed")
		}
		document, err := html.Parse(bytes.NewReader(wire))
		if err != nil {
			return "", errors.New("NetBird login page invalid")
		}
		var action string
		var visit func(*html.Node)
		visit = func(node *html.Node) {
			if node.Type == html.ElementNode && node.Data == "form" {
				for _, attr := range node.Attr {
					if attr.Key == "action" {
						action = attr.Val
					}
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(document)
		target, err := url.Parse(action)
		if err != nil || target.IsAbs() || !strings.HasPrefix(target.Path, "/oauth2/auth/local/") {
			return "", errors.New("NetBird embedded login form changed")
		}
		path = target.RequestURI()
		method = "POST"
		contentType = "application/x-www-form-urlencoded"
		body = strings.NewReader(url.Values{"login": {ownerEmail}, "password": {password}}.Encode())
		submitted = true
	}
	return "", errors.New("NetBird login exceeded redirect limit")
}

type bootstrapVaultClient interface {
	vaultsecret.VaultClient
	vaultsecret.VersionClient
}
type fencedBootstrapVault struct {
	bootstrapVaultClient
	check func() error
}

func (v fencedBootstrapVault) CreateSecret(ctx context.Context, req ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error) {
	if err := v.check(); err != nil {
		return ocivault.CreateSecretResponse{}, err
	}
	policy := common.NoRetryPolicy()
	req.RequestMetadata.RetryPolicy = &policy
	return v.bootstrapVaultClient.CreateSecret(ctx, req)
}
func (v fencedBootstrapVault) UpdateSecret(ctx context.Context, req ocivault.UpdateSecretRequest) (ocivault.UpdateSecretResponse, error) {
	if err := v.check(); err != nil {
		return ocivault.UpdateSecretResponse{}, err
	}
	policy := common.NoRetryPolicy()
	req.RequestMetadata.RetryPolicy = &policy
	return v.bootstrapVaultClient.UpdateSecret(ctx, req)
}

type ownerEscrow struct {
	StoreGeneration string             `json:"store_generation"`
	SetupAttempt    string             `json:"setup_attempt"`
	Target          vaultsecret.Target `json:"vault_target"`
	Password        string             `json:"password"`
	OwnerID         string             `json:"owner_id"`
}

func ownerEscrowDirectory(directory string) (int, error) {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		unix.Close(fd)
		return -1, errors.New("NetBird owner escrow directory is not protected")
	}
	return fd, nil
}

func loadOwnerEscrow(directory string) (ownerEscrow, error) {
	fd, err := ownerEscrowDirectory(directory)
	if errors.Is(err, unix.ENOENT) {
		return ownerEscrow{}, nil
	}
	if err != nil {
		return ownerEscrow{}, errors.New("NetBird owner escrow directory is not protected")
	}
	defer unix.Close(fd)
	return loadOwnerEscrowAt(fd)
}

func loadOwnerEscrowAt(directory int) (ownerEscrow, error) {
	var result ownerEscrow
	fd, err := unix.Openat(directory, "owner.json", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return result, nil
	}
	if err != nil {
		return result, errors.New("NetBird owner escrow cannot be opened")
	}
	file := os.NewFile(uintptr(fd), "owner.json")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return result, errors.New("NetBird owner escrow file is not protected")
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return result, errors.New("NetBird owner escrow file ownership differs")
	}
	wire, err := io.ReadAll(io.LimitReader(file, 4097))
	defer clear(wire)
	if err != nil || json.Unmarshal(wire, &result) != nil || len(result.Password) < 32 || len(result.Password) > 256 {
		return ownerEscrow{}, errors.New("NetBird owner escrow is invalid")
	}
	return result, nil
}
func saveOwnerEscrow(directory string, value ownerEscrow) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return errors.New("NetBird owner escrow directory creation failed")
	}
	fd, err := ownerEscrowDirectory(directory)
	if err != nil {
		return errors.New("NetBird owner escrow directory is not protected")
	}
	defer unix.Close(fd)
	existing, err := loadOwnerEscrowAt(fd)
	if err != nil {
		return err
	}
	if existing.Password != "" && existing.Password != value.Password || existing.OwnerID != "" && existing.OwnerID != value.OwnerID || existing.Password != "" && existing.Target != value.Target || existing.StoreGeneration != "" && existing.StoreGeneration != value.StoreGeneration || existing.SetupAttempt != "" && existing.SetupAttempt != value.SetupAttempt {
		return errors.New("NetBird owner escrow replacement refused")
	}
	if existing == value {
		return nil
	}
	wire, err := json.Marshal(value)
	if err != nil {
		return errors.New("NetBird owner escrow encoding failed")
	}
	defer clear(wire)
	name := ".owner-" + randomCredential()
	temp, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("NetBird owner escrow write failed")
	}
	file := os.NewFile(uintptr(temp), name)
	defer unix.Unlinkat(fd, name, 0)
	if _, err = file.Write(wire); err != nil {
		file.Close()
		return errors.New("NetBird owner escrow write failed")
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return errors.New("NetBird owner escrow sync failed")
	}
	if err = file.Close(); err != nil {
		return errors.New("NetBird owner escrow close failed")
	}
	if err = unix.Renameat(fd, name, fd, "owner.json"); err != nil {
		return errors.New("NetBird owner escrow publication failed")
	}
	if unix.Fsync(fd) != nil {
		return errors.New("NetBird owner escrow directory sync failed")
	}
	return nil
}
