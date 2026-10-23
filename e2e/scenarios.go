package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	tb "terrascale.tech/sdk/v1"
)

func scenarios() []scenario {
	return []scenario{
		{"terrabase.ready", []string{"terrabase", "status"}, []string{"TS-483", "TS-512", "terrabase#16"}, func(ctx context.Context, e *environment) error {
			return probe(ctx, e, e.TerraBaseURL, "/readyz")
		}},
		{"terrabase.management-and-documents", []string{"terrabase", "ts-go"}, []string{"TS-481", "TS-512"}, documents},
		{"terrabase.key-issuance", []string{"terrabase", "ts-go"}, []string{"TS-481", "TS-512"}, func(ctx context.Context, e *environment) error {
			if !e.DocumentsKeyIssued {
				return errors.New("document scenario did not issue its scoped API key")
			}
			return nil
		}},
		{"terrabase.shape", []string{"terrabase", "ts-go"}, []string{"TS-481"}, func(context.Context, *environment) error {
			return pending{"TS-481", "pinned SDK has no shape method; pinned TerraBase OpenAPI has no shape route"}
		}},
		{"auth.ready", []string{"ts-auth", "terrabase"}, []string{"TS-488", "TS-489"}, func(ctx context.Context, e *environment) error {
			err := probe(ctx, e, e.AuthURL, "/readyz")
			return knownUnavailable(err, e.Target, e.AuthUnavailable, http.StatusServiceUnavailable, "TS-489")
		}},
		{"auth.signup-oidc-pkce-tokens-userinfo", []string{"ts-auth", "ts-go", "terrabase"}, []string{"TS-489", "TS-490", "TS-491"}, func(context.Context, *environment) error {
			return pending{"TS-489,TS-490,TS-491", "signup and browser OIDC flow await the C# identity streams"}
		}},
		{"dashboard.signin-management-restart", []string{"ts-dashboard", "ts-auth", "terrabase"}, []string{"TS-472", "TS-492"}, func(context.Context, *environment) error {
			return pending{"TS-472,TS-492", "dashboard authentication and TerraBase-backed persistence have not shipped"}
		}},
		{"atlas.discovery-pin-misdirected", []string{"ts-atlas", "ts-go", "terrabase"}, []string{"TS-496"}, func(context.Context, *environment) error {
			return pending{"TS-496", "Atlas stack discovery and session pin/421 contract await release"}
		}},
		{"ouroboros.internal-state", []string{"ts-auth", "ts-dashboard", "terrabase"}, []string{"TS-472", "TS-489", "TS-492"}, func(context.Context, *environment) error {
			return pending{"TS-472,TS-489,TS-492", "requires both services to write and read their state in terrascale on this TerraBase"}
		}},
		{"status.reachable", []string{"ts-status"}, []string{"TS-512"}, func(ctx context.Context, e *environment) error {
			if e.Target == "local" {
				return pending{"TS-512", "ts-status has no local release artifact in the requested stack"}
			}
			return probe(ctx, e, e.StatusURL, "/")
		}},
	}
}

// The transport checks the actual server response without replacing it.
type regionTransport struct {
	base   http.RoundTripper
	region string
}

func (t regionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 && strings.HasPrefix(req.URL.Path, "/v1/projects/") && res.Header.Get("X-TerraBase-Region") != t.region {
		res.Body.Close()
		return nil, fmt.Errorf("%s: X-TerraBase-Region=%q, want %q", req.URL.Path, res.Header.Get("X-TerraBase-Region"), t.region)
	}
	return res, nil
}
func documents(ctx context.Context, e *environment) (err error) {
	if e.Target != "local" {
		return errors.New("mutating document scenarios require the disposable local stack")
	}
	m, err := tb.NewManagement(tb.Config{Resolver: tb.StaticResolver(e.AdminURL), Token: e.Credential, HTTPClient: e.HTTP, MaxRetries: -1})
	if err != nil {
		return err
	}
	u := m.As(e.UserID)
	org, createErr := u.CreateOrganization(ctx, "terrascale-e2e")
	if createErr != nil {
		return createErr
	}
	orgID := org.ID
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err = errors.Join(err, u.DeleteOrganization(cleanup, orgID))
	}()
	projectName := "e2e-" + strings.ToLower(rand.Text())
	// Register before the mutation: a lost create response still leaves an owned name.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, cleanupProject(cleanup, u, orgID, projectName))
	}()
	project, err := u.CreateProject(ctx, orgID, projectName)
	if err != nil {
		return err
	}
	dbInfo, err := u.CreateDatabase(ctx, orgID, project.ID, "main")
	if err != nil {
		return err
	}
	key, err := issueLocalKey(ctx, e, orgID, project.ID)
	if err != nil {
		return err
	}
	e.DocumentsKeyIssued = true
	e.APIKey = key
	hc := *e.HTTP
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = regionTransport{base: base, region: e.Region}
	c, err := tb.New(tb.Config{Resolver: tb.StaticResolver(e.TerraBaseURL), Token: key, HTTPClient: &hc, MaxRetries: -1})
	if err != nil {
		return err
	}
	db := c.Database(project.ID, dbInfo.Name)
	if _, err = db.CreateCollection(ctx, "items"); err != nil {
		return err
	}
	items := db.Collection("items")
	created, err := items.Create(ctx, map[string]any{"n": 1, "run": "TS-512"})
	if err != nil {
		return err
	}
	doc, err := items.Get(ctx, created.ID)
	if err != nil {
		return err
	}
	if doc.Version != created.Version {
		return errors.New("read version differs from create")
	}
	if err = expectNumber(doc, "1"); err != nil {
		return err
	}
	put, err := items.Put(ctx, created.ID, map[string]any{"n": 2, "run": "TS-512"}, tb.IfMatch(doc.Version))
	if err != nil {
		return err
	}
	patched, err := items.Patch(ctx, created.ID, tb.Ops(tb.Inc("/n", 1)), tb.IfMatch(put.Version))
	if err != nil {
		return err
	}
	doc, err = items.Get(ctx, created.ID)
	if err != nil {
		return err
	}
	if err = expectNumber(doc, "3"); err != nil {
		return err
	}
	list, err := items.List(ctx, tb.ListOptions{Limit: 10})
	if err != nil {
		return err
	}
	if len(list.Items) != 1 || list.Items[0].ID != created.ID {
		return errors.New("list did not return created document")
	}
	query, err := items.Query(ctx, tb.Query{Filter: tb.Eq("/n", 3), Count: true})
	if err != nil {
		return err
	}
	if len(query.Items) != 1 || query.Items[0].ID != created.ID || query.Count == nil || query.Count.Value != 1 {
		return errors.New("query/count did not match updated document")
	}
	txID := tb.NewID()
	tx, err := db.Tx().Put("items", txID, map[string]any{"n": 7}, tb.IfNoneMatchAny()).Patch("items", created.ID, tb.Ops(tb.Inc("/n", 1)), tb.IfMatch(patched.Version)).Commit(ctx)
	if err != nil {
		return err
	}
	if len(tx.Results) != 2 {
		return errors.New("transaction did not commit both operations")
	}
	_, err = db.Tx().Patch("items", txID, tb.Ops(tb.Inc("/n", 1))).Assert("items", created.ID, tb.Eq("/n", 999)).Commit(ctx)
	var rejected *tb.APIError
	if !errors.As(err, &rejected) || !errors.Is(err, tb.ErrPreconditionFailed) {
		return fmt.Errorf("transaction must reject its assertion: %v", err)
	}
	if op, ok := rejected.OpIndex(); !ok || op != 1 {
		return fmt.Errorf("transaction rejected the wrong operation: %v", err)
	}
	doc, err = items.Get(ctx, txID)
	if err != nil {
		return err
	}
	if err = expectNumber(doc, "7"); err != nil {
		return fmt.Errorf("transaction rollback: %w", err)
	}
	doc, err = items.Get(ctx, created.ID)
	if err != nil {
		return err
	}
	if err = expectNumber(doc, "4"); err != nil {
		return fmt.Errorf("transaction second write: %w", err)
	}
	if _, err = items.Delete(ctx, created.ID, tb.IfMatch(doc.Version)); err != nil {
		return err
	}
	_, err = items.Get(ctx, created.ID)
	if !errors.Is(err, tb.ErrNotFound) {
		return fmt.Errorf("deleted document must be not_found: %v", err)
	}
	return nil
}
func expectNumber(doc *tb.Document, want string) error {
	var body map[string]any
	if err := doc.Decode(&body); err != nil {
		return err
	}
	if body["n"] != json.Number(want) {
		return fmt.Errorf("document n=%v, want %s", body["n"], want)
	}
	return nil
}

// Key issuance is bootstrap on the loopback admin listener, absent from ts-go.
// Local keys and metadata disappear with the disposable TerraBase data directory.
func issueLocalKey(ctx context.Context, e *environment, org, project string) (string, error) {
	u, err := url.Parse(e.AdminURL)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() {
		return "", errors.New("key bootstrap requires a loopback admin listener")
	}
	body, err := json.Marshal(map[string]any{"name": "TS-512", "organizationId": org, "projectId": project, "scopes": []string{"documents:read", "documents:write"}})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.AdminURL+"/admin/api-keys", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := e.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("key bootstrap: HTTP %d", res.StatusCode)
	}
	var key struct {
		Secret string `json:"secret"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&key); err != nil {
		return "", err
	}
	if key.Secret == "" {
		return "", errors.New("key bootstrap returned no secret")
	}
	return key.Secret, nil
}

// Reconcile the local run's unique name even when a create response was lost.
func cleanupProject(ctx context.Context, u *tb.ManagementUser, org, name string) error {
	for cursor := ""; ; {
		page, err := u.Projects(ctx, org, tb.PageOptions{Limit: 100, After: cursor})
		if err != nil {
			return fmt.Errorf("cleanup find project %s: %w", name, err)
		}
		for _, project := range page.Items {
			if project.Name != name {
				continue
			}
			// Project deletion requires revoking the run's scoped keys first.
			for keyCursor := ""; ; {
				keys, err := u.ProjectAPIKeys(ctx, org, project.ID, tb.PageOptions{Limit: 100, After: keyCursor})
				if err != nil {
					return fmt.Errorf("cleanup list keys in %s: %w", project.ID, err)
				}
				for _, key := range keys.Items {
					if err := u.RevokeProjectAPIKey(ctx, org, project.ID, key.ID); err != nil {
						return fmt.Errorf("cleanup revoke key %s: %w", key.ID, err)
					}
				}
				if keys.Next == "" {
					break
				}
				keyCursor = keys.Next
			}
			for dbCursor := ""; ; {
				databases, err := u.Databases(ctx, org, project.ID, tb.PageOptions{Limit: 100, After: dbCursor})
				if err != nil {
					return fmt.Errorf("cleanup list databases in %s: %w", project.ID, err)
				}
				for _, database := range databases.Items {
					if database.Name != "main" {
						continue
					}
					if err := u.DeleteDatabase(ctx, org, project.ID, database.ID); err != nil {
						return fmt.Errorf("cleanup database %s: %w", database.ID, err)
					}
				}
				if databases.Next == "" {
					break
				}
				dbCursor = databases.Next
			}
			if err := u.DeleteProject(ctx, org, project.ID); err != nil {
				return fmt.Errorf("cleanup project %s: %w", project.ID, err)
			}
			return nil
		}
		if page.Next == "" {
			return nil
		}
		cursor = page.Next
	}
}

func knownUnavailable(err error, target, reason string, expected int, ticket string) error {
	status, ok := err.(probeError)
	if target == "local" && reason != "" && ok && status.status == expected {
		if ticket == "TS-489" && status.readinessStatus != "not_ready" {
			return err
		}
		return pending{ticket, reason}
	}
	return err
}
