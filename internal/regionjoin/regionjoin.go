// Package regionjoin lets a second host of a region join the region's
// SwarmKit cluster by itself: the founder publishes join material in the
// gru-vault secret ts-orch-join-<region>, and a fresh host reads it with its
// instance principal. The first fresh host of a region with no secret claims
// it atomically and founds the cluster.
package regionjoin

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// Material is the region's join material. It holds the SwarmKit worker join
// token, so it is never logged or printed.
type Material struct {
	// Founder is the hostname of the host that founded the region's cluster.
	Founder string `json:"founder"`
	// Manager is the founder's SwarmKit remote API, <private VCN IP>:4242.
	Manager     string `json:"manager,omitempty"`
	WorkerToken string `json:"workerToken,omitempty"`
}

// SecretName is the gru-vault secret holding region's join material.
func SecretName(region string) string { return "ts-orch-join-" + region }

type vault struct {
	factory    *ociclient.Factory
	bundles    vaultsecret.BundleClient
	management *ocivault.VaultsClient
}

func open(ctx context.Context) (vault, error) {
	factory, err := ociclient.InstancePrincipalContext(ctx, mesh.SharedVaultRegion)
	if err != nil {
		return vault{}, err
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return vault{}, err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return vault{}, err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	return vault{factory: factory, bundles: bundles, management: &management}, nil
}

func decode(region, value string) (Material, error) {
	var m Material
	if err := json.Unmarshal([]byte(value), &m); err != nil || m.Founder == "" {
		return Material{}, fmt.Errorf("Vault secret %s is not join material", SecretName(region))
	}
	return m, nil
}

// Claim makes hostname the region's founder unless the region already has
// join material, and returns the region's material. OCI keeps secret names
// unique in a Vault, so exactly one concurrent claimer creates it.
func Claim(ctx context.Context, region, hostname string) (Material, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	v, err := open(ctx)
	if err != nil {
		return Material{}, err
	}
	name := SecretName(region)
	value, err := vaultsecret.Read(ctx, v.bundles, mesh.SharedVault.VaultID, name)
	if err == nil {
		return decode(region, value)
	}
	if !vaultsecret.Absent(err) {
		return Material{}, err
	}
	claim, err := json.Marshal(Material{Founder: hostname})
	if err != nil {
		return Material{}, err
	}
	stored, err := vaultsecret.Ensure(ctx, v.management, mesh.SharedVault, name, "ts-orch in-region join material",
		func(context.Context) (string, error) { return string(claim), nil })
	if err != nil {
		return Material{}, errors.Join(errors.New("claim region founder"), err)
	}
	value, err = vaultsecret.ReadBack(ctx, v.bundles, mesh.SharedVault.VaultID, name, stored.Created || stored.Provisioning)
	if err != nil {
		return Material{}, err
	}
	return decode(region, value)
}

// Publish stores m as the region's join material unless Vault holds it already.
func Publish(ctx context.Context, region string, m Material) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	v, err := open(ctx)
	if err != nil {
		return err
	}
	value, err := json.Marshal(m)
	if err != nil {
		return err
	}
	ref := vaultsecret.Ref{Vault: mesh.SharedVault.VaultID, Name: SecretName(region)}
	current, err := vaultsecret.ReadCurrent(ctx, v.bundles, ref)
	if vaultsecret.Absent(err) {
		_, err = vaultsecret.Ensure(ctx, v.management, mesh.SharedVault, ref.Name, "ts-orch in-region join material",
			func(context.Context) (string, error) { return string(value), nil })
		return err // a concurrent creator's value is compared on the next round
	}
	if err != nil || current.Value() == string(value) {
		return err
	}
	_, err = vaultsecret.Publish(ctx, v.factory, ref, current.ID, current.Version, value)
	return err
}

// Instance is what IMDS says about this OCI host.
type Instance struct {
	Region, ID, PrivateIP string
}

// Local reads this host's region, instance OCID and private VCN address.
func Local(ctx context.Context) (Instance, error) {
	region, err := mesh.OwnRegion(ctx)
	if err != nil {
		return Instance{}, err
	}
	id, err := imds(ctx, "instance/id")
	if err != nil {
		return Instance{}, err
	}
	vnics, err := imds(ctx, "vnics/")
	if err != nil {
		return Instance{}, err
	}
	var listed []struct {
		PrivateIP string `json:"privateIp"`
	}
	if err := json.Unmarshal([]byte(vnics), &listed); err != nil || len(listed) == 0 || listed[0].PrivateIP == "" {
		return Instance{}, errors.New("IMDS lists no VNIC private IP")
	}
	return Instance{Region: region, ID: strings.TrimSpace(id), PrivateIP: listed[0].PrivateIP}, nil
}

func imds(ctx context.Context, path string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/opc/v2/"+path, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := hostenroll.NewIMDSClient().Do(request)
	if err != nil {
		return "", fmt.Errorf("read IMDS %s: %w", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read IMDS %s: status %d", path, response.StatusCode)
	}
	return string(body), nil
}
