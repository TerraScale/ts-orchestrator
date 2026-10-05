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

// TerraScale's own organization in the production TerraBase, the one end
// users reach at https://gru.api.terrascale.tech, and ts-auth's project in it.
const (
	OrganizationName = "terrascale"
	ProjectName      = "ts-auth"
	// BootstrapUser is the acting user that creates the organization and so
	// becomes its owner; ts-auth has no users before it runs. It is a fixed
	// service identity, not a ts-auth user, and stays an admin after
	// EnsureOwner hands the ownership to a person.
	BootstrapUser = "ts-orchestrator"
)

// KeyScopes are the scopes of every project's TerraBase API key.
var KeyScopes = []string{"documents:read", "documents:write"}

// Project is one project of TerraScale's own organization, OrganizationName,
// with its database and the Vault keys of its project ID and API key.
type Project struct {
	Name, Database          string
	ProjectIDKey, APIKeyKey string
}

// Projects is the ouroboros table: TerraScale's own services keep their data
// in the production TerraBase, each in its own project and database, reached
// with its own API key.
var Projects = []Project{
	{Name: ProjectName, Database: Database, ProjectIDKey: EnvProjectID, APIKeyKey: EnvAPIKey},
	dashboard,
}

// dashboard is ts-dashboard's project; fly-secrets hands it to the dashboard.
var dashboard = Project{Name: "ts-dashboard", Database: "dashboard",
	ProjectIDKey: "TS_DASHBOARD_TERRABASE_PROJECT_ID", APIKeyKey: "TS_DASHBOARD_TERRABASE_API_KEY"}

// TerraBase reaches one member's two listeners: the client listener (HTTPS,
// the data plane and, before TS-519, the Management API) and the loopback
// admin listener (HTTP, which issues API keys and trusts its caller). The operator reaches them through an SSH forward to the member.
// From TS-519 TerraBase accepts the Management service credential only on
// the loopback admin listener; ManagementOnAdmin sends Management requests
// there.
type TerraBase struct {
	HTTP              *http.Client // trusts the cell's member CA for ClientURL
	ClientURL         string
	AdminURL          string
	Credential        string // the member's Management service credential
	User              string // acting user; empty means BootstrapUser
	ManagementOnAdmin bool
}

// Tenant is one project's organization, project and database.
type Tenant struct {
	OrganizationID string `json:"organization_id"`
	Project        string `json:"project"`
	ProjectID      string `json:"project_id"`
	DatabaseID     string `json:"database_id"`
	Database       string `json:"database"`
}

type named struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EnsureTenant finds or creates project's organization, project and database.
// It is safe to rerun: each is created only when the acting user has none of
// that name, and two of one name are refused rather than guessed between.
func (t TerraBase) EnsureTenant(ctx context.Context, project Project) (Tenant, error) {
	organizations := "/v1/management/organizations"
	organization, err := t.ensure(ctx, "", organizations, OrganizationName)
	if err != nil {
		return Tenant{}, fmt.Errorf("organization: %w", err)
	}
	projects := organizations + "/" + url.PathEscape(organization) + "/projects"
	projectID, err := t.ensure(ctx, organization, projects, project.Name)
	if err != nil {
		return Tenant{}, fmt.Errorf("project: %w", err)
	}
	database, err := t.ensure(ctx, organization, projects+"/"+url.PathEscape(projectID)+"/databases", project.Database)
	if err != nil {
		return Tenant{}, fmt.Errorf("database: %w", err)
	}
	return Tenant{OrganizationID: organization, Project: project.Name, ProjectID: projectID, DatabaseID: database, Database: project.Database}, nil
}

func (t TerraBase) ensure(ctx context.Context, organization, path, name string) (string, error) {
	// find returns the ID of the one item named name, or "" when none is.
	find := func() (string, error) {
		items, err := list[named](ctx, t, organization, path)
		if err != nil {
			return "", err
		}
		found := ""
		for _, item := range items {
			if item.Name != name {
				continue
			}
			if found != "" {
				return "", fmt.Errorf("two named %q; remove one first", name)
			}
			found = item.ID
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

// list reads every page of a Management collection.
func list[T any](ctx context.Context, t TerraBase, organization, path string) ([]T, error) {
	var items []T
	for after := ""; ; {
		query := url.Values{"limit": {"100"}}
		if after != "" {
			query.Set("after", after)
		}
		var page struct {
			Items []T     `json:"items"`
			Next  *string `json:"next"`
		}
		if err := t.management(ctx, http.MethodGet, organization, path+"?"+query.Encode(), nil, http.StatusOK, &page); err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if page.Next == nil || *page.Next == "" || len(page.Items) == 0 {
			return items, nil
		}
		after = *page.Next
	}
}

// user is the acting user.
func (t TerraBase) user() string {
	if t.User == "" {
		return BootstrapUser
	}
	return t.User
}

func (t TerraBase) management(ctx context.Context, method, organization, path string, body any, status int, result any) error {
	headers := http.Header{"Authorization": {"Bearer " + t.Credential}, "X-TerraBase-User-Id": {t.user()}}
	if organization != "" {
		headers.Set("X-TerraBase-Organization-Id", organization)
	}
	base := t.ClientURL
	if t.ManagementOnAdmin {
		base = t.AdminURL
	}
	return t.call(ctx, method, base+path, headers, body, status, result)
}

// IssueKey issues the tenant's documents:read/write API key, named after its
// project and narrowed to its database, through the admin listener. The
// secret is returned, never printed.
func (t TerraBase) IssueKey(ctx context.Context, tenant Tenant) (string, error) {
	var issued struct {
		Secret string `json:"secret"`
	}
	request := map[string]any{"name": tenant.Project, "scopes": KeyScopes, "organizationId": tenant.OrganizationID,
		"projectId": tenant.ProjectID, "databaseId": tenant.DatabaseID}
	if err := t.call(ctx, http.MethodPost, t.AdminURL+"/admin/api-keys", http.Header{}, request, http.StatusCreated, &issued); err != nil {
		return "", fmt.Errorf("issue %s API key: %w", tenant.Project, err)
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

// EnsureOwner makes owner, the ts-auth user whose verified address is email,
// the organization's owner and keeps the acting user, BootstrapUser, as an
// admin. As the acting user it adds owner as a member and offers it the
// ownership; as owner it confirms the transfer and, since confirming leaves
// the acting user a member, makes it an admin again. Each step runs only
// while the members show it undone, so a rerun changes nothing. It returns
// the steps it took. Adding a member with the credential needs TerraBase
// TS-535 and so the admin listener: the credential carries no verified
// email, so it cannot accept an invitation.
func (t TerraBase) EnsureOwner(ctx context.Context, organization, owner, email string) ([]string, error) {
	nominee := t
	nominee.User = owner
	path := "/v1/management/organizations/" + url.PathEscape(organization)
	roles, err := t.roles(ctx, organization)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	// Only the acting user hands the organization over: once another user owns
	// it, a rerun with a different address must not add that user, since any
	// member manages every project and database.
	if roles[owner] != "owner" && roles[t.user()] != "owner" {
		return nil, fmt.Errorf("organization %s is owned by another user; refusing to add %s", organization, owner)
	}
	var steps []string
	if roles[owner] == "" {
		add := path + "/members/" + url.PathEscape(owner)
		if err := t.management(ctx, http.MethodPut, organization, add, map[string]string{"email": email}, http.StatusOK, nil); err != nil {
			return steps, fmt.Errorf("add %s as a member: %w", owner, err)
		}
		steps = append(steps, "added")
	}
	if roles[owner] != "owner" {
		transfer := path + "/ownership-transfer"
		if err := t.management(ctx, http.MethodPost, organization, transfer, map[string]string{"userId": owner}, http.StatusCreated, nil); err != nil {
			return steps, fmt.Errorf("offer the ownership to %s: %w", owner, err)
		}
		if err := nominee.management(ctx, http.MethodPost, organization, transfer+"/confirm", nil, http.StatusOK, nil); err != nil {
			return steps, fmt.Errorf("confirm the ownership as %s: %w", owner, err)
		}
		steps = append(steps, "transferred")
		if roles, err = nominee.roles(ctx, organization); err != nil {
			return steps, fmt.Errorf("list members: %w", err)
		}
	}
	if roles[t.user()] != "admin" {
		role := path + "/members/" + url.PathEscape(t.user()) + "/role"
		if err := nominee.management(ctx, http.MethodPut, organization, role, map[string]string{"role": "admin"}, http.StatusOK, nil); err != nil {
			return steps, fmt.Errorf("keep %s as admin: %w", t.user(), err)
		}
		steps = append(steps, "kept "+t.user()+" as admin")
	}
	return steps, nil
}

// roles maps each member of the organization to its role.
func (t TerraBase) roles(ctx context.Context, organization string) (map[string]string, error) {
	members, err := list[struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}](ctx, t, organization, "/v1/management/organizations/"+url.PathEscape(organization)+"/members")
	if err != nil {
		return nil, err
	}
	roles := make(map[string]string, len(members))
	for _, member := range members {
		roles[member.UserID] = member.Role
	}
	return roles, nil
}

// call sends one JSON request and decodes the reply into result, unless it
// is nil. An error carries the method, path and status only: response bodies
// may echo a request, and requests carry credentials.
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
	if result == nil {
		return nil
	}
	if err := json.UnmarshalRead(io.LimitReader(response.Body, 1<<20), result); err != nil {
		return fmt.Errorf("%s %s: decode reply: %w", method, path, err)
	}
	return nil
}
