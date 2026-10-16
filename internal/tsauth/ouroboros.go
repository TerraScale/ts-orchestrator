package tsauth

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// FlyApp is the dashboard's Fly app. TS-472 reads its TerraBase settings
// from the app's TERRABASE_* secrets.
const FlyApp = "ts-dashboard"

func ouroborosUsage() string {
	var projects []string
	for _, project := range Projects {
		projects = append(projects, project.Name+" (database "+project.Database+")")
	}
	return fmt.Sprintf(`Usage: ts-orch ouroboros <command> [flags]

  bootstrap    --plan FILE --client-url URL --admin-url URL --member NODE
               --member-ca FILE --dashboard-credential-file FILE
               [--management-listener client|admin]
               [--owner-email EMAIL --ts-auth-instance SLUG --ts-auth-key-file FILE
                [--ts-auth-url URL]]
      Find or create, in the production TerraBase, TerraScale's organization
      %[1]s and its projects
        %[2]s
      through one member's Management and admin APIs, acting as %[3]s,
      which so owns a new organization. For each project, store its ID and,
      unless the Vault holds one, a newly issued documents:read/write API key
      narrowed to its database in the cell's Vault; read both back and check
      the key reaches the database. Prints one line of tenant IDs per project.
      Management requests use the client listener, or with
      --management-listener admin the loopback admin listener, the only one
      that accepts the credential from TerraBase TS-519 on.
      With --owner-email and --management-listener admin, once that address
      has signed in to ts-auth: add its ts-auth user as a member, make it the
      owner and keep %[3]s as an admin. Prints the steps taken.
  fly-secrets  --plan FILE
      Hand the dashboard, Fly app %[4]s, TERRABASE_URL, TERRABASE_PROJECT_ID,
      TERRABASE_DATABASE and TERRABASE_API_KEY, and its ts-auth client
      TS_AUTH_ISSUER, TS_AUTH_CLIENT_ID, TS_AUTH_REDIRECT_URL and
      TS_AUTH_CLIENT_SECRET. With FLY_API_TOKEN set, stage them with flyctl
      secrets import --stage; otherwise print all but the key and the client
      secret and the names of the Vault secrets that hold them.
`, OrganizationName, strings.Join(projects, ", "), BootstrapUser, FlyApp)
}

// RunOuroboros dispatches the ouroboros commands. Output never carries a
// secret. loadPlan parses the reviewed cell plan, as for Run.
func RunOuroboros(ctx context.Context, args []string, output io.Writer, loadPlan func(string) (map[string]any, error)) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, ouroborosUsage())
		return err
	}
	flags := flag.NewFlagSet("ouroboros "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.String("plan", "", "reviewed cell plan (deploy/oci-region/plan.json)")
	clientURL := flags.String("client-url", "", "TerraBase member client listener, for example https://127.0.0.1:19465")
	adminURL := flags.String("admin-url", "", "TerraBase member admin listener, for example http://127.0.0.1:19464")
	member := flags.String("member", "", "TerraBase member node the client listener belongs to, for example gru-1-db-1")
	memberCA := flags.String("member-ca", "", "the cell's TerraBase member-ca.pem")
	credential := flags.String("dashboard-credential-file", "", "owner-only file holding the member's Management service credential (TERRABASE_MANAGEMENT_CREDENTIAL_FILE)")
	listener := flags.String("management-listener", "client", "listener serving the credential's Management API: client, or admin from TerraBase TS-519 on")
	ownerEmail := flags.String("owner-email", "", "verified address of the ts-auth user who becomes the owner")
	instance := flags.String("ts-auth-instance", "", "slug of the ts-auth instance the owner signed in to")
	keyFile := flags.String("ts-auth-key-file", "", "owner-only file holding that instance's sk_ management key")
	// The dashboard signs users in at gru's ts-auth.
	tsAuthURL := flags.String("ts-auth-url", PublicOrigin("gru"), "ts-auth's public origin")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected ouroboros arguments")
	}
	switch args[0] {
	case "bootstrap":
		if *plan == "" || *clientURL == "" || *adminURL == "" || *member == "" || *memberCA == "" || *credential == "" {
			return errors.New("bootstrap requires --plan, --client-url, --admin-url, --member, --member-ca and --dashboard-credential-file")
		}
		if *listener != "client" && *listener != "admin" {
			return errors.New("--management-listener must be client or admin")
		}
		var users TSAuthUsers
		if *ownerEmail != "" || *instance != "" || *keyFile != "" {
			if address, err := mail.ParseAddress(*ownerEmail); err != nil || address.Address != *ownerEmail || *instance == "" || *keyFile == "" {
				return errors.New("--owner-email needs one plain address, --ts-auth-instance and --ts-auth-key-file")
			}
			if *listener != "admin" {
				return errors.New("--owner-email needs --management-listener admin: only TerraBase's admin listener adds a member (TS-535)")
			}
			var err error
			if users, err = tsAuthUsers(*tsAuthURL, *instance, *keyFile); err != nil {
				return err
			}
		}
		terraBase, err := memberClient(*clientURL, *adminURL, *member, *memberCA, *credential)
		if err != nil {
			return err
		}
		terraBase.ManagementOnAdmin = *listener == "admin"
		cell, target, client, bundles, err := OperatorVault(*plan, loadPlan)
		if err != nil {
			return err
		}
		organization, err := bootstrap(ctx, terraBase, client, bundles, target, cell, output)
		if err != nil || *ownerEmail == "" {
			return err
		}
		return own(ctx, terraBase, users, organization, *ownerEmail, output)
	case "fly-secrets":
		if *plan == "" {
			return errors.New("fly-secrets requires --plan")
		}
		cell, target, _, bundles, err := OperatorVault(*plan, loadPlan)
		if err != nil {
			return err
		}
		return flySecrets(ctx, bundles, target.VaultID, cell, output)
	default:
		_, _ = io.WriteString(output, ouroborosUsage())
		return fmt.Errorf("unknown ouroboros command %q", args[0])
	}
}

// bootstrap prepares every project of Projects in TerraBase, stores each
// project's ID and API key in the Vault, and prints one line
// {"tenant":...,"secrets":[...]} per project. It returns the organization ID.
func bootstrap(ctx context.Context, terraBase TerraBase, client VaultClient, bundles BundleClient, target Target, cell string, output io.Writer) (string, error) {
	organization := ""
	for _, project := range Projects {
		tenant, secrets, err := bootstrapProject(ctx, terraBase, client, bundles, target, cell, project)
		if err != nil {
			return "", fmt.Errorf("project %s: %w", project.Name, err)
		}
		if err := printLine(output, map[string]any{"tenant": tenant, "secrets": secrets}); err != nil {
			return "", err
		}
		organization = tenant.OrganizationID
	}
	return organization, nil
}

// bootstrapProject ensures project's tenant and stores its project ID and,
// only when the Vault holds none, a newly issued API key. It then reads both
// back: a project ID or key of an earlier run must still name this tenant
// and reach its database, or it fails instead of reporting a stale tenant.
func bootstrapProject(ctx context.Context, terraBase TerraBase, client VaultClient, bundles BundleClient, target Target, cell string, project Project) (Tenant, []Stored, error) {
	tenant, err := terraBase.EnsureTenant(ctx, project)
	if err != nil {
		return Tenant{}, nil, err
	}
	projectID, err := Ensure(ctx, client, target, cell, project.ProjectIDKey, func(context.Context) (string, error) {
		return tenant.ProjectID, nil
	})
	if err != nil {
		return Tenant{}, nil, err
	}
	// A stale project ID must stop the command before a key is issued:
	// TerraBase cannot revoke one.
	storedID, err := readBack(ctx, bundles, target.VaultID, cell, project.ProjectIDKey, projectID.Created || projectID.Provisioning)
	if err != nil {
		return Tenant{}, nil, err
	}
	if storedID != tenant.ProjectID {
		return Tenant{}, nil, fmt.Errorf("Vault secret %s names project %s, TerraBase has %s; inspect both before rerunning", projectID.Secret, storedID, tenant.ProjectID)
	}
	key, err := Ensure(ctx, client, target, cell, project.APIKeyKey, func(ctx context.Context) (string, error) {
		return terraBase.IssueKey(ctx, tenant)
	})
	if err != nil {
		return Tenant{}, nil, err
	}
	apiKey, err := readBack(ctx, bundles, target.VaultID, cell, project.APIKeyKey, key.Created || key.Provisioning)
	if err != nil {
		return Tenant{}, nil, err
	}
	if err := terraBase.CheckKey(ctx, tenant, apiKey); err != nil {
		return Tenant{}, nil, fmt.Errorf("Vault secret %s does not reach database %s: %w", key.Secret, tenant.Database, err)
	}
	return tenant, []Stored{projectID, key}, nil
}

// own makes the ts-auth user whose verified address is email the
// organization's owner, keeping BootstrapUser as an admin, and prints
// {"organization_id":...,"owner":...,"admin":...,"steps":[...]}. A rerun
// takes no step.
func own(ctx context.Context, terraBase TerraBase, users TSAuthUsers, organization, email string, output io.Writer) error {
	owner, err := users.UserID(ctx, email)
	if err != nil {
		return err
	}
	steps, err := terraBase.EnsureOwner(ctx, organization, owner, email)
	if err != nil {
		return fmt.Errorf("%w (steps taken: %v)", err, steps)
	}
	return printLine(output, map[string]any{"organization_id": organization, "owner": owner, "admin": terraBase.user(), "steps": steps})
}

// TSAuthUsers lists one ts-auth instance's users through its Management API:
// GET /v1/{instance}/users with the instance's sk_ management key.
type TSAuthUsers struct {
	HTTP     *http.Client
	URL      string // ts-auth's origin, for example https://gru.auth.terrascale.tech
	Instance string
	Key      string
}

func tsAuthUsers(origin, instance, keyFile string) (TSAuthUsers, error) {
	if !strings.HasPrefix(origin, "https://") {
		return TSAuthUsers{}, errors.New("--ts-auth-url must be https://")
	}
	key, err := readOwnerOnly(keyFile, 4096)
	if err != nil {
		return TSAuthUsers{}, fmt.Errorf("--ts-auth-key-file: %w", err)
	}
	return TSAuthUsers{HTTP: &http.Client{Timeout: terraBaseRequestTimeout}, URL: strings.TrimSuffix(origin, "/"),
		Instance: instance, Key: strings.TrimSpace(string(key))}, nil
}

// UserID returns the id of the one ts-auth user with address email. That
// user becomes an owner of TerraScale's own organization, so it must have
// verified the address and be neither banned nor anonymous.
func (u TSAuthUsers) UserID(ctx context.Context, email string) (string, error) {
	type user struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Anonymous     bool   `json:"is_anonymous"`
		Banned        bool   `json:"banned"`
	}
	var found []user
	for after := ""; ; {
		query := url.Values{"limit": {"100"}}
		if after != "" {
			query.Set("starting_after", after)
		}
		var page struct {
			Data []user `json:"data"`
		}
		target := u.URL + "/v1/" + url.PathEscape(u.Instance) + "/users?" + query.Encode()
		if err := (TerraBase{HTTP: u.HTTP}).call(ctx, http.MethodGet, target, http.Header{"Authorization": {"Bearer " + u.Key}}, nil, http.StatusOK, &page); err != nil {
			return "", fmt.Errorf("list ts-auth users: %w", err)
		}
		for _, item := range page.Data {
			if !entityid.Valid(item.ID) {
				return "", errors.New("ts-auth returned a noncanonical user ID")
			}
			if strings.EqualFold(item.Email, email) {
				found = append(found, item)
			}
		}
		if len(page.Data) < 100 || page.Data[len(page.Data)-1].ID == after {
			break
		}
		after = page.Data[len(page.Data)-1].ID
	}
	switch {
	case len(found) == 0:
		return "", fmt.Errorf("ts-auth instance %s has no user %s yet: sign in once with that address (for example on the dashboard), then rerun", u.Instance, email)
	case len(found) > 1:
		return "", fmt.Errorf("ts-auth instance %s has %d users %s; resolve that before rerunning", u.Instance, len(found), email)
	}
	owner := found[0]
	if !owner.EmailVerified || owner.Anonymous || owner.Banned {
		return "", fmt.Errorf("ts-auth user %s must have verified %s and be neither anonymous nor banned", owner.ID, email)
	}
	if !entityid.Valid(owner.ID) || owner.ID == BootstrapUser {
		return "", fmt.Errorf("ts-auth user %s has an unusable id", email)
	}
	return owner.ID, nil
}

// flySecrets hands the dashboard its TerraBase settings and its ts-auth
// client. With FLY_API_TOKEN set it reads the project ID, the API key and the
// client secret from the Vault and stages all eight with flyctl, values on
// stdin so no argument carries a secret; the dashboard loads them at its next
// deploy. Otherwise it reads only the project ID and prints the settings
// without the two secrets, naming the Vault secrets that hold them. The
// endpoints are those of cell, a cell name such as gru-1.
func flySecrets(ctx context.Context, bundles BundleClient, vaultID, cell string, output io.Writer) error {
	projectID, err := readSecret(ctx, bundles, vaultID, cell, dashboard.ProjectIDKey)
	if err != nil {
		return err
	}
	region, _, _ := strings.Cut(cell, "-")
	settings := map[string]string{"TERRABASE_URL": APIURL(region), "TERRABASE_PROJECT_ID": projectID, "TERRABASE_DATABASE": dashboard.Database,
		"TS_AUTH_ISSUER": Issuer(region), "TS_AUTH_CLIENT_ID": DashboardClientID, "TS_AUTH_REDIRECT_URL": DashboardRedirectURI}
	result := map[string]any{"app": FlyApp, "settings": settings, "api_key_secret": SecretName(cell, dashboard.APIKeyKey),
		"client_secret_secret": SecretName(cell, EnvDashboardClientSecret), "staged": false}
	if os.Getenv("FLY_API_TOKEN") == "" {
		return printLine(output, result)
	}
	key, err := readSecret(ctx, bundles, vaultID, cell, dashboard.APIKeyKey)
	if err != nil {
		return err
	}
	// ts-auth secrets creates the client secret; a Vault prepared before it
	// existed needs that rerun, which keeps every existing secret.
	clientSecret, err := readSecret(ctx, bundles, vaultID, cell, EnvDashboardClientSecret)
	if err != nil {
		return fmt.Errorf("%w; create it with ts-orch ts-auth secrets --plan FILE, then rerun", err)
	}
	input := []byte("TERRABASE_API_KEY=" + key + "\nTS_AUTH_CLIENT_SECRET=" + clientSecret + "\n")
	for name, value := range settings {
		input = fmt.Appendf(input, "%s=%s\n", name, value)
	}
	defer clear(input)
	command := exec.CommandContext(ctx, "flyctl", "secrets", "import", "--app", FlyApp, "--stage")
	command.Stdin = bytes.NewReader(input)
	if reply, err := command.CombinedOutput(); err != nil {
		redacted := strings.NewReplacer(key, "[redacted]", clientSecret, "[redacted]").Replace(string(reply))
		return fmt.Errorf("flyctl secrets import: %w: %s", err, redacted)
	}
	result["staged"] = true
	return printLine(output, result)
}

// printLine writes value as one JSON line.
func printLine(output io.Writer, value any) error {
	if err := json.MarshalWrite(output, value); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output)
	return err
}
