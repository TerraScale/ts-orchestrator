package vaultsecret

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const usage = `Usage: ts-orch vault <command> [flags]

  put     --vault-id OCID --key-id OCID --compartment-id OCID --name NAME --file FILE
      Store FILE once as secret NAME (operator ~/.oci/config). An existing secret is
      never replaced: put reads it back and fails unless it equals FILE.
  render  --vault-id OCID --scope SCOPE --template FILE --out FILE
      On a host, as root: replace each {{KEY}} of the template with the JSON-quoted
      secret <scope>-<key>, read with the instance principal, and write FILE
      atomically, mode 0600.

Output names secrets and OCIDs, never a value. See docs/secrets.md.
`

// maxValue bounds one secret; OCI refuses bundles over 25 KB.
const maxValue = 16 << 10

var placeholderRE = regexp.MustCompile(`\{\{([A-Z][A-Z0-9_]*)\}\}`)

// Run dispatches the vault commands.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, usage)
		return err
	}
	flags := flag.NewFlagSet("vault "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	vaultID := flags.String("vault-id", "", "the Vault OCID")
	keyID := flags.String("key-id", "", "the Vault master key OCID")
	compartmentID := flags.String("compartment-id", "", "the compartment of a new secret")
	name := flags.String("name", "", "the secret name")
	file := flags.String("file", "", "the secret value")
	scope := flags.String("scope", "", "the secret name prefix, a cell such as gru-1")
	template := flags.String("template", "", "the template to render")
	out := flags.String("out", "", "the rendered file")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected vault arguments")
	}
	if err := safeEnv(); err != nil {
		return err
	}
	parts := strings.Split(*vaultID, ".")
	region := ""
	if len(parts) >= 5 && parts[1] == "vault" && catalog.IsOCIRegion(parts[3]) {
		region = parts[3]
	}
	switch args[0] {
	case "put":
		if *vaultID == "" || *keyID == "" || *compartmentID == "" || *name == "" || *file == "" {
			return errors.New("put requires --vault-id, --key-id, --compartment-id, --name and --file")
		}
		if region == "" || !strings.HasPrefix(*keyID, "ocid1.key.") ||
			!strings.HasPrefix(*compartmentID, "ocid1.compartment.") && !strings.HasPrefix(*compartmentID, "ocid1.tenancy.") {
			return errors.New("put needs a regional Vault, a key and a compartment OCID")
		}
		value, err := readValue(*file)
		if err != nil {
			return err
		}
		defer clear(value)
		factory, err := ociclient.OperatorConfig(region)
		if err != nil {
			return err
		}
		client, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
		if err != nil {
			return err
		}
		client.SetRegion(factory.Region())
		factory.Configure(&client.BaseClient, ociclient.ServiceVault)
		bundles, err := secretsClient(factory)
		if err != nil {
			return err
		}
		stored, err := Put(ctx, client, bundles, Target{CompartmentID: *compartmentID, VaultID: *vaultID, KeyID: *keyID}, *name, value)
		if err != nil {
			return err
		}
		return printLine(output, stored)
	case "render":
		if *vaultID == "" || *scope == "" || *template == "" || *out == "" {
			return errors.New("render requires --vault-id, --scope, --template and --out")
		}
		if region == "" || !nameRE.MatchString(*scope) {
			return errors.New("render needs a regional Vault OCID and a lowercase hyphenated scope")
		}
		if os.Geteuid() != 0 {
			return errors.New("render runs as root: its file holds secrets")
		}
		text, err := os.ReadFile(*template)
		if err != nil {
			return err
		}
		factory, err := ociclient.InstancePrincipal(region)
		if err != nil {
			return err
		}
		bundles, err := secretsClient(factory)
		if err != nil {
			return err
		}
		rendered, names, err := Render(ctx, bundles, *vaultID, *scope, text)
		if err != nil {
			return err
		}
		defer clear(rendered)
		if err := writeFile(*out, rendered); err != nil {
			return err
		}
		return printLine(output, map[string]any{"file": *out, "secrets": names})
	default:
		_, _ = io.WriteString(output, usage)
		return fmt.Errorf("unknown vault command %q", args[0])
	}
}

// Put stores value as secret name once, then reads the Vault's current
// version back: an existing secret that differs from value is an error, so a
// rerun either proves the stored copy or stops.
func Put(ctx context.Context, client VaultClient, bundles BundleClient, target Target, name string, value []byte) (Stored, error) {
	if len(name) > 255 || !nameRE.MatchString(name) || strings.Count(name, "-") < 2 {
		return Stored{}, fmt.Errorf("secret name %q must be lowercase words joined by hyphens: <scope>-<service>-<key>", name)
	}
	if len(value) == 0 || len(value) > maxValue {
		return Stored{}, fmt.Errorf("secret %s must hold 1 to %d bytes", name, maxValue)
	}
	stored, err := Ensure(ctx, client, target, name, name+"; stored once by ts-orch vault put.",
		func(context.Context) (string, error) { return string(value), nil })
	if err != nil {
		return stored, err
	}
	current, err := ReadBack(ctx, bundles, target.VaultID, name, stored.Created || stored.Provisioning)
	if err != nil {
		return stored, err
	}
	if subtle.ConstantTimeCompare([]byte(current), value) != 1 {
		return stored, fmt.Errorf("Vault secret %s differs from the file; inspect it before rerunning", name)
	}
	return stored, nil
}

// Render replaces each {{KEY}} of template with the JSON-quoted current value
// of secret Name(scope, KEY) and returns the names it read.
func Render(ctx context.Context, bundles BundleClient, vaultID, scope string, template []byte) ([]byte, []string, error) {
	if bytes.Contains(placeholderRE.ReplaceAll(template, nil), []byte("{{")) {
		return nil, nil, errors.New("template placeholders must be {{KEY}} with KEY in A-Z, 0-9 and _")
	}
	values := map[string][]byte{}
	names := []string{}
	for _, match := range placeholderRE.FindAllSubmatch(template, -1) {
		key := string(match[1])
		if values[key] != nil {
			continue
		}
		name := Name(scope, key)
		value, err := Read(ctx, bundles, vaultID, name)
		if err != nil {
			return nil, nil, err
		}
		if values[key], err = json.Marshal(value); err != nil {
			return nil, nil, fmt.Errorf("Vault secret %s is not valid UTF-8", name)
		}
		names = append(names, name)
	}
	rendered := placeholderRE.ReplaceAllFunc(template, func(match []byte) []byte {
		return values[string(match[2:len(match)-2])]
	})
	for _, value := range values {
		clear(value)
	}
	return rendered, names, nil
}

func secretsClient(factory *ociclient.Factory) (ocisecrets.SecretsClient, error) {
	client, err := ocisecrets.NewSecretsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return client, err
	}
	// The constructors take the profile's region; the Vault OCID names its own.
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceVault)
	return client, nil
}

// readValue reads a secret file, a pipe or /dev/stdin, as it is.
func readValue(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxValue+1))
	if err == nil && len(value) > maxValue {
		clear(value)
		return nil, fmt.Errorf("--file holds over %d bytes", maxValue)
	}
	return value, err
}

// writeFile replaces path atomically with an owner-only file: a temporary
// file in its directory, fsync, rename and a directory fsync.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = file.Chmod(0o600)
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), path)
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func printLine(output io.Writer, value any) error {
	if err := json.MarshalWrite(output, value); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output)
	return err
}
