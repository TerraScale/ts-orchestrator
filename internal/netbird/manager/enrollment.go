package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

var ErrEnrollmentUncertain = errors.New("NetBird setup-key request is unresolved; quiesce the dedicated manager before retrying")

// EnrollmentAuthority fences writes and drains earlier management requests after
// a lost POST. Quiesce must stop/wait/restart the same persistent manager store.
type EnrollmentAuthority struct {
	Check   func() error
	Quiesce func(context.Context) error
}

// EnrollmentVault uses create-once OCI storage and verifies CURRENT bytes before
// delivery succeeds. It never rotates an existing secret or accepts a name alone.
type EnrollmentVault struct {
	Target     vaultsecret.Target
	Management vaultsecret.VaultClient
	Bundles    vaultsecret.BundleClient
	Name       string
}

type EnrollmentResult struct {
	OperationID string `json:"operation_id"`
	KeyID       string `json:"key_id"`
	SecretID    string `json:"secret_id"`
}

// ReconcileServerEnrollment creates one regional key, escrows its plaintext
// before delivery, and resumes interrupted OCI writes without replacing keys.
// The directory belongs on the dedicated manager's protected persistent volume.
func ReconcileServerEnrollment(ctx context.Context, api *API, d Desired, directory string, vault EnrollmentVault, authority EnrollmentAuthority) (EnrollmentResult, error) {
	if api == nil || authority.Check == nil || vault.Management == nil || vault.Bundles == nil {
		return EnrollmentResult{}, errors.New("NetBird enrollment requires GRU authority and OCI Vault clients")
	}
	if err := authority.Check(); err != nil {
		return EnrollmentResult{}, err
	}
	d, err := d.withServerGroups([]string{d.ServersGroup})
	if err != nil {
		return EnrollmentResult{}, err
	}
	if err := d.Validate(); err != nil {
		return EnrollmentResult{}, err
	}
	cell := strings.TrimSuffix(d.ServersGroup, "-servers")
	if err := vaultsecret.ValidateDeliveryRefs(cell, "netbird", map[string]vaultsecret.Ref{
		"SETUP_KEY": {Vault: vault.Target.VaultID, Name: vault.Name},
	}, nil); err != nil {
		return EnrollmentResult{}, err
	}
	store, err := openEnrollmentStore(directory)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer store.close()
	state, err := store.read()
	if err != nil {
		return EnrollmentResult{}, err
	}
	client := *api
	client.beforeWrite = func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if api.beforeWrite != nil {
			if err := api.beforeWrite(); err != nil {
				return err
			}
		}
		return authority.Check()
	}
	if state.Operation == "" {
		// Refuse an unknown delivery before creating any key.
		_, err := vaultsecret.ReadVersioned(ctx, vault.Bundles, vault.Target.VaultID, vault.Name)
		if !vaultsecret.Absent(err) {
			return EnrollmentResult{}, errors.New("NetBird Vault delivery exists or is unavailable without its enrollment intent")
		}
		state = enrollmentState{Origin: api.base, Group: d.ServersGroup, Name: d.SetupKeyName, Operation: newEnrollmentOperation(),
			Vault: vault.Target.VaultID, VaultName: vault.Name, Compartment: vault.Target.CompartmentID, MasterKey: vault.Target.KeyID}
		if err := store.write(state); err != nil {
			return EnrollmentResult{}, err
		}
	}
	if state.Origin != api.base || state.Group != d.ServersGroup || state.Name != d.SetupKeyName ||
		state.Vault != vault.Target.VaultID || state.VaultName != vault.Name || state.Compartment != vault.Target.CompartmentID || state.MasterKey != vault.Target.KeyID ||
		!IsManagedSetupKeyName(d.SetupKeyName, state.Name+"-enrollment-"+state.Operation) ||
		state.Key != "" && !validEnrollmentKey(state.Key) || state.SecretID != "" && (state.Key == "" || state.KeyID == "") {
		return EnrollmentResult{}, errors.New("NetBird enrollment intent differs from its management scope")
	}
	var groups []apiGroup
	if err := client.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return EnrollmentResult{}, err
	}
	var servers string
	for _, group := range groups {
		if group.Name == d.ServersGroup {
			if servers != "" || group.ID == "" || group.Issued != "api" {
				return EnrollmentResult{}, errors.New("NetBird enrollment servers group is ambiguous or not API owned")
			}
			servers = group.ID
		}
	}
	if servers == "" {
		return EnrollmentResult{}, errors.New("NetBird enrollment awaits its reconciled regional servers group")
	}
	name := state.Name + "-enrollment-" + state.Operation
	key, err := enrollmentKey(ctx, &client, name, servers)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if state.Key == "" && state.Attempted {
		// A GET alone cannot rule out a late commit from the interrupted POST.
		if key == nil {
			if authority.Quiesce == nil {
				return EnrollmentResult{}, ErrEnrollmentUncertain
			}
			if err := client.beforeWrite(); err != nil {
				return EnrollmentResult{}, err
			}
			if err := authority.Quiesce(ctx); err != nil {
				return EnrollmentResult{}, errors.New("cannot quiesce unresolved NetBird enrollment")
			}
			key, err = enrollmentKey(ctx, &client, name, servers)
			if err != nil {
				return EnrollmentResult{}, err
			}
		}
		if key != nil && !key.Revoked {
			if err := client.do(ctx, "PUT", "/setup-keys/"+url.PathEscape(key.ID), struct {
				AutoGroups []string `json:"auto_groups"`
				Revoked    bool     `json:"revoked"`
			}{[]string{servers}, true}, nil); err != nil {
				return EnrollmentResult{}, err
			}
		}
		state.Operation, state.Attempted, state.KeyID = newEnrollmentOperation(), false, ""
		if err := store.write(state); err != nil {
			return EnrollmentResult{}, err
		}
		name, key = state.Name+"-enrollment-"+state.Operation, nil
	}
	if state.Key == "" {
		if key != nil {
			return EnrollmentResult{}, errors.New("NetBird enrollment found a key without its creation attempt")
		}
		state.Attempted = true
		if err := store.write(state); err != nil {
			return EnrollmentResult{}, err
		}
		var response struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		if err := client.do(ctx, "POST", "/setup-keys", setupKeyRequest{Name: name, Type: "reusable", AutoGroups: []string{servers}}, &response); err != nil {
			return EnrollmentResult{}, err
		}
		if response.ID == "" || !validEnrollmentKey(response.Key) {
			return EnrollmentResult{}, errors.New("NetBird enrollment creation returned no recoverable value")
		}
		state.KeyID, state.Key = response.ID, response.Key
		if err := store.write(state); err != nil {
			return EnrollmentResult{}, err
		}
		key, err = enrollmentKey(ctx, &client, name, servers)
		if err != nil {
			return EnrollmentResult{}, err
		}
	}
	if key == nil || key.ID != state.KeyID || key.Revoked || !key.Valid || key.State != "valid" {
		return EnrollmentResult{}, errors.New("NetBird escrowed enrollment key is no longer valid; refusing rotation")
	}
	if err := client.beforeWrite(); err != nil {
		return EnrollmentResult{}, err
	}
	stored, err := vaultsecret.Ensure(ctx, fencedEnrollmentVault{vault.Management, client.beforeWrite}, vault.Target, vault.Name, "Managed NetBird regional enrollment", func(context.Context) (string, error) { return state.Key, nil })
	if err != nil {
		return EnrollmentResult{}, err
	}
	current, err := vaultsecret.ReadVersioned(ctx, vault.Bundles, vault.Target.VaultID, vault.Name)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if current.Value != state.Key || current.SecretID != stored.ID || state.SecretID != "" && state.SecretID != stored.ID {
		return EnrollmentResult{}, errors.New("NetBird Vault enrollment material differs; refusing replacement")
	}
	state.SecretID = stored.ID
	if err := store.write(state); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{OperationID: state.Operation, KeyID: state.KeyID, SecretID: state.SecretID}, nil
}

func newEnrollmentOperation() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

func validEnrollmentKey(value string) bool {
	parsed, err := uuid.Parse(value)
	return len(value) == 36 && err == nil && parsed != uuid.Nil()
}

func enrollmentKey(ctx context.Context, api *API, name, group string) (*apiSetupKey, error) {
	var keys []apiSetupKey
	if err := api.do(ctx, "GET", "/setup-keys", nil, &keys); err != nil {
		return nil, err
	}
	var found *apiSetupKey
	for _, key := range keys {
		if key.Name != name {
			continue
		}
		if found != nil || key.ID == "" || key.Type != "reusable" || key.Ephemeral || !slices.Equal(key.AutoGroups, []string{group}) {
			return nil, errors.New("NetBird enrollment operation has ambiguous or altered keys")
		}
		found = new(key)
	}
	return found, nil
}

type fencedEnrollmentVault struct {
	vaultsecret.VaultClient
	check func() error
}

func (v fencedEnrollmentVault) CreateSecret(ctx context.Context, request ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error) {
	if err := v.check(); err != nil {
		return ocivault.CreateSecretResponse{}, err
	}
	return v.VaultClient.CreateSecret(ctx, request)
}
