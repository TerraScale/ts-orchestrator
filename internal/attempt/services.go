package attempt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
)

// The ports every cell's TerraBase members listen on; the plans' NSG rules
// admit them.
const terraBasePeerPort, terraBaseClientPort = 9443, 9465

// apiURL and authOrigin are a cell's regional TerraBase API and ts-auth
// origins, sfo.api.terrascale.tech and sfo.auth.terrascale.tech.
func apiURL(cell catalog.Entry) string { return "https://" + cell.Name() + ".api.terrascale.tech" }
func authOrigin(cell catalog.Entry) string {
	return "https://" + cell.Name() + ".auth.terrascale.tech"
}

// derivedProfile is where the services phase writes the profile of role it
// derives from the plan.
func (a *Attempt) derivedProfile(role string) string { return a.Path("services", role+".profile.json") }

// terraBaseProfile is the TerraBase profile the cell runs: terrabase_profile,
// or the one the services phase derived.
func (a *Attempt) terraBaseProfile() string {
	if path := str(a.Config, "terrabase_profile"); path != "" {
		return path
	}
	if path := a.derivedProfile(terrabase.Role); exists(path) {
		return path
	}
	return ""
}

type node struct{ name, ip string }

// terraBaseMembers are the plan's TerraBase members in placement order, the
// first the catalog primary: its database hosts, or in a colocated cell,
// which has none, its controllers.
func terraBaseMembers(cell catalog.Entry, plan Object) ([]node, error) {
	var members, controllers []node
	for _, v := range rows(plan["hosts"]) {
		host := object(v)
		slot := str(host, "slot")
		var name string
		var err error
		switch {
		case strings.HasPrefix(slot, "member-"):
			name, err = naming.RegionCell(cell.Cell).MemberSlot(slot)
			members = append(members, node{name, str(host, "private_ip")})
		case strings.HasPrefix(slot, "controller-"):
			name, err = naming.RegionCell(cell.Cell).ControllerSlot(slot)
			controllers = append(controllers, node{name, str(host, "private_ip")})
		}
		if err != nil {
			return nil, err
		}
	}
	if len(members) == 0 {
		members = controllers
	}
	if len(members) == 0 {
		return nil, errors.New("attempt plan has no TerraBase member hosts")
	}
	return members, nil
}

// deriveTerraBase is the cell's first TerraBase profile.
//
// TerraBase is ready only once it fetched its auth issuer's signing keys,
// and ts-auth is ready only once TerraBase is (the gru-1 re-found's
// deadlock). A cell other than the home cell trusts the home cell's ts-auth,
// which already serves, so its profile carries the issuer from the start,
// and audiences for both its own API and the home API that issuer's tokens
// name. The home cell's own ts-auth cannot serve yet: its profile carries
// only the Management credential, and a later root-signed amendment adds
// the issuer once ts-auth serves.
func deriveTerraBase(cell catalog.Entry, plan Object) (Object, error) {
	members, err := terraBaseMembers(cell, plan)
	if err != nil {
		return nil, err
	}
	region, err := naming.RegionCell(cell.Cell).Name()
	if err != nil {
		return nil, err
	}
	var peers []string
	for _, m := range members {
		peers = append(peers, m.name+"="+m.ip+":"+strconv.Itoa(terraBasePeerPort))
	}
	env := Object{
		"TERRABASE_REGION":      region,
		terrabase.EnvPeerPort:   strconv.Itoa(terraBasePeerPort),
		terrabase.EnvClientPort: strconv.Itoa(terraBaseClientPort),
		terrabase.EnvPeers:      strings.Join(peers, ","),
		// One member writes the catalog; the others follow it (TerraBase
		// decision 0009). Naming it on every member makes it the primary.
		"TERRABASE_CATALOG_PRIMARY": members[0].name,
	}
	profile := Object{"resources": Object{"cpu": 1, "memory_bytes": 4 << 30, "disk_bytes": 20 << 30}, "env": env}
	home, _ := catalog.Lookup(catalog.Bootstrap)
	if cell.Cell != home.Cell {
		env["TERRABASE_AUTH_ISSUER"] = authOrigin(home) + "/terrascale"
		env["TERRABASE_AUTH_AUDIENCE"] = apiURL(cell) + "," + apiURL(home)
		return profile, nil
	}
	// The bootstrap path before ts-auth serves; the host delivers it as an
	// in-memory file from Vault (TS-745).
	vault := str(object(plan["resource_ids"]), "vault")
	if vault == "" {
		return nil, errors.New("attempt plan binds no vault for TerraBase's Management credential")
	}
	profile["secrets"] = Object{"TERRABASE_MANAGEMENT_CREDENTIAL_FILE": Object{"vault": vault,
		"name": region + "-terrabase-management-credential"}}
	return profile, nil
}

// deriveTSAuth is the cell's ts-auth profile and service spec: its own
// regional origin and API, storage on the TerraBase members of terraBase
// (the primary preferred) trusting the attempt's member CA, and its secrets
// as <cell>-ts-auth-* in the plan's Vault. tsauth.ValidateProfile accepts
// only the home cell's until its contract takes any catalog cell.
func (a *Attempt) deriveTSAuth(cell catalog.Entry, plan Object, terraBase map[string]string) (Object, Object, error) {
	vault := str(object(plan["resource_ids"]), "vault")
	if vault == "" {
		return nil, nil, errors.New("attempt plan binds no vault for ts-auth's secrets")
	}
	ca, err := os.ReadFile(a.Path("material", "terrabase-member-ca.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("ts-auth trusts the TerraBase member CA: %w", err)
	}
	members, err := terrabase.ParseProfile(terraBase)
	if err == nil && members.ClientPort == 0 {
		err = errors.New("the TerraBase profile sets no client port")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("ts-auth stores through TerraBase's client port: %w", err)
	}
	var endpoints []string
	for _, peer := range members.Peers {
		endpoints = append(endpoints, "https://"+peer.Address.Addr().String()+":"+strconv.Itoa(members.ClientPort))
	}
	env := Object{
		tsauth.EnvPublicOrigin: authOrigin(cell), tsauth.EnvAPIURL: apiURL(cell), tsauth.EnvAudiences: apiURL(cell),
		tsauth.EnvAPIEndpoints: strings.Join(endpoints, ";"), tsauth.EnvAPICA: string(ca),
		tsauth.EnvAPIFailover: strconv.FormatBool(len(endpoints) > 1), tsauth.EnvDatabase: tsauth.Database,
		tsauth.EnvDashboardRedirectURIs: tsauth.DashboardRedirectURI, tsauth.EnvDashboardLogoutURIs: tsauth.DashboardLogoutURI,
		"TS_AUTH_SMTP_HOST": "smtp.email." + cell.OCIRegion + ".oci.oraclecloud.com", "TS_AUTH_SMTP_PORT": "587",
		"TS_AUTH_SMTP_FROM_ADDRESS": "noreply@terrascale.tech", "TS_AUTH_SMTP_CHECK_REVOCATION": "false",
	}
	name, err := naming.RegionCell(cell.Cell).Name()
	if err != nil {
		return nil, nil, err
	}
	secrets := Object{}
	for _, key := range slices.Concat(tsauth.Secrets, []string{"TS_AUTH_SMTP_USERNAME", "TS_AUTH_SMTP_PASSWORD"}) {
		secrets[key] = Object{"vault": vault, "name": tsauth.SecretName(name, key)}
	}
	profile := Object{"resources": Object{"cpu": 1, "memory_bytes": 1 << 30, "disk_bytes": 2 << 30}, "env": env, "secrets": secrets}
	spec := Object{"role": tsauth.Role, "environment": "canary", "kind": "stateless",
		"replicas": Object{"min": tsauth.Replicas, "max": tsauth.Replicas}, "placement": Object{"max_per_failure_domain": 1},
		"rollout": Object{"max_surge": 1, "max_unavailable": 1}}
	return profile, spec, nil
}

// profileEnv reads a profile's env.
func (a *Attempt) profileEnv(path string) map[string]string {
	env := map[string]string{}
	for key, value := range object(a.read(path)["env"]) {
		env[key], _ = value.(string)
	}
	return env
}

// grantHosts plans a host grant for every controller node of the plan with
// the colocated roles the cell delivers in services: ts-auth, and
// TerraBase where the TerraBase profile lists the node as a member. A grant
// gives a host credentials, so a root signs it. A grant the spec already
// holds plans nothing, so a rerun changes nothing.
func (a *Attempt) grantHosts(services []any, apply func(candidate, signed string, root bool)) {
	roles := map[string]string{}
	for _, v := range services {
		roles[str(object(v), "role")] = str(object(v), "profile")
	}
	var members terrabase.Profile
	if path, ok := roles[terrabase.Role]; ok {
		var err error
		members, err = terrabase.ParseProfile(a.profileEnv(path))
		a.fail(err)
	}
	plan := a.read(a.Plan())
	cell := a.Cell()
	if a.err != nil {
		return
	}
	hosts := hostMap(plan)
	cli, config := a.Path("release", OperatorCLI), filepath.Join(a.OperatorDirectory(), "operator.json")
	for _, slot := range Slots {
		name, err := naming.RegionCell(cell.Cell).ControllerSlot(slot)
		a.fail(err)
		ip := str(hosts[slot], "private_ip")
		var granted []string
		if _, ok := roles[tsauth.Role]; ok {
			granted = append(granted, tsauth.Role)
		}
		if _, ok := members.Member(name, ip); ok {
			granted = append(granted, terrabase.Role)
		}
		if a.err != nil || len(granted) == 0 {
			continue
		}
		slices.Sort(granted)
		candidate, signed := a.Path("services", "grant-"+name+".candidate.json"), a.Path("services", "grant-"+name+".signed.json")
		a.sudo(false, "rm", "-f", "--", candidate, signed)
		a.sudo(true, cli, "service", "grant-host", "--config", config, "--node", name, "--private-ip", ip,
			"--roles", strings.Join(granted, ","), "--environment", "canary", "--controller", slot, "--out", candidate)
		if a.err == nil && exists(candidate) {
			apply(candidate, signed, true)
		}
	}
}

// deriveServices writes the profiles of the cell's roles the attempt config
// does not name, from the attempt's bound plan, and returns their paths.
func (a *Attempt) deriveServices(terraBaseConfigured string, tsAuth bool) (map[string][2]string, error) {
	plan := a.read(a.Plan())
	cell := a.Cell()
	if a.err != nil {
		return nil, a.err
	}
	paths := map[string][2]string{}
	terraBase := terraBaseConfigured
	if terraBase == "" {
		profile, err := deriveTerraBase(cell, plan)
		if err != nil {
			return nil, err
		}
		terraBase = a.derivedProfile(terrabase.Role)
		a.writeJSON(terraBase, profile)
		paths[terrabase.Role] = [2]string{terraBase}
	}
	if tsAuth {
		env := a.profileEnv(terraBase)
		if a.err != nil {
			return nil, a.err
		}
		profile, spec, err := a.deriveTSAuth(cell, plan, env)
		if err != nil {
			return nil, err
		}
		path, specPath := a.derivedProfile(tsauth.Role), a.Path("services", tsauth.Role+".service.json")
		a.writeJSON(path, profile)
		a.writeJSON(specPath, spec)
		paths[tsauth.Role] = [2]string{path, specPath}
	}
	return paths, a.err
}
