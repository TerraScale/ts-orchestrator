package tsauth

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// The tenant that holds ts-auth's own data in the production TerraBase, the
// one end users reach at https://gru.api.terrascale.tech.
const (
	OrganizationName = "terrascale-internal"
	ProjectName      = "auth"
	// BootstrapUser is the acting user that creates the organization and so
	// becomes its owner; ts-auth has no users before it runs.
	BootstrapUser = "ts-orchestrator"
)

// KeyScopes are the scopes of ts-auth's TerraBase API key.
var KeyScopes = []string{"documents:read", "documents:write"}

// TerraBase reaches one member's two listeners: the client listener (HTTPS,
// the Management API, authorized by the dashboard credential) and the
// loopback admin listener (HTTP, which issues API keys and trusts its
// caller). The operator reaches them through an SSH forward to the member.
type TerraBase struct {
	HTTP       *http.Client // trusts the cell's member CA for ClientURL
	ClientURL  string
	AdminURL   string
	Credential string // the member's dashboard credential
	User       string // acting user; empty means BootstrapUser
}

// Tenant is ts-auth's organization, project and database.
type Tenant struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	DatabaseID     string `json:"database_id"`
	Database       string `json:"database"`
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EnsureTenant finds or creates ts-auth's organization, project and database.
// It is safe to rerun: each is created only when the acting user has none of
// that name, and two of one name are refused rather than guessed between.
func (t TerraBase) EnsureTenant(ctx context.Context) (Tenant, error) {
	organizations := "/v1/management/organizations"
	organization, err := t.ensure(ctx, "", organizations, OrganizationName)
	if err != nil {
		return Tenant{}, fmt.Errorf("organization: %w", err)
	}
	projects := organizations + "/" + url.PathEscape(organization) + "/projects"
	project, err := t.ensure(ctx, organization, projects, ProjectName)
	if err != nil {
		return Tenant{}, fmt.Errorf("project: %w", err)
	}
	database, err := t.ensure(ctx, organization, projects+"/"+url.PathEscape(project)+"/databases", Database)
	if err != nil {
		return Tenant{}, fmt.Errorf("database: %w", err)
	}
	return Tenant{OrganizationID: organization, ProjectID: project, DatabaseID: database, Database: Database}, nil
}

func (t TerraBase) ensure(ctx context.Context, organization, path, name string) (string, error) {
	find := func() (string, error) {
		found := ""
		for after := ""; ; {
			query := url.Values{"limit": {"100"}}
			if after != "" {
				query.Set("after", after)
			}
			var page struct {
				Items []named `json:"items"`
				Next  *string `json:"next"`
			}
			if err := t.management(ctx, http.MethodGet, organization, path+"?"+query.Encode(), nil, http.StatusOK, &page); err != nil {
				return "", err
			}
			for _, item := range page.Items {
				if item.Name != name {
					continue
				}
				if found != "" {
					return "", fmt.Errorf("two named %q; remove one first", name)
				}
				found = item.ID
			}
			if page.Next == nil || *page.Next == "" || len(page.Items) == 0 {
				break
			}
			after = *page.Next
		}
		return found, nil
	}

	found, err := find()
	if err != nil {
		return "", err
	}
	if found != "" {
		return found, nil
	}
	var created named
	if err := t.management(ctx, http.MethodPost, organization, path, map[string]string{"name": name}, http.StatusCreated, &created); err != nil {
		if recovered, recoverErr := find(); recoverErr == nil && recovered != "" {
			return recovered, nil
		} else if recoverErr != nil {
			return "", recoverErr
		}
		return "", err
	}
	if created.ID == "" || created.Name != name {
		return "", fmt.Errorf("TerraBase created %q without its ID", name)
	}
	return created.ID, nil
}

func (t TerraBase) management(ctx context.Context, method, organization, path string, body any, status int, result any) error {
	user := t.User
	if user == "" {
		user = BootstrapUser
	}
	headers := http.Header{"Authorization": {"Bearer " + t.Credential}, "X-TerraBase-User-Id": {user}}
	if organization != "" {
		headers.Set("X-TerraBase-Organization-Id", organization)
	}
	return t.call(ctx, method, t.ClientURL+path, headers, body, status, result)
}

// IssueKey issues ts-auth's documents:read/write API key, narrowed to its
// database, through the admin listener. The secret is returned, never printed.
func (t TerraBase) IssueKey(ctx context.Context, tenant Tenant) (string, error) {
	var issued struct {
		Secret string `json:"secret"`
	}
	request := map[string]any{"name": "ts-auth", "scopes": KeyScopes, "organizationId": tenant.OrganizationID,
		"projectId": tenant.ProjectID, "databaseId": tenant.DatabaseID}
	if err := t.call(ctx, http.MethodPost, t.AdminURL+"/admin/api-keys", http.Header{}, request, http.StatusCreated, &issued); err != nil {
		return "", fmt.Errorf("issue ts-auth API key: %w", err)
	}
	if err := validSecret(EnvAPIKey, issued.Secret); err != nil {
		return "", errors.New("TerraBase issued an unusable API key")
	}
	return issued.Secret, nil
}

// CheckKey proves that key reaches the tenant's database: it lists the
// database's collections, which needs documents:read.
func (t TerraBase) CheckKey(ctx context.Context, tenant Tenant, key string) error {
	var collections any
	path := "/v1/projects/" + url.PathEscape(tenant.ProjectID) + "/databases/" + url.PathEscape(tenant.Database) + "/collections"
	return t.call(ctx, http.MethodGet, t.ClientURL+path, http.Header{"Authorization": {"Bearer " + key}}, nil, http.StatusOK, &collections)
}

// call sends one JSON request. An error carries the method, path and status
// only: response bodies may echo a request, and requests carry credentials.
func (t TerraBase) call(ctx context.Context, method, target string, headers http.Header, body any, status int, result any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
		headers.Set("Content-Type", "application/json")
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	request.Header = headers
	client := t.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	path := request.URL.Path
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return fmt.Errorf("%s %s: HTTP %d", method, path, response.StatusCode)
	}
	if err := json.UnmarshalRead(io.LimitReader(response.Body, 1<<20), result); err != nil {
		return fmt.Errorf("%s %s: decode reply: %w", method, path, err)
	}
	return nil
}
