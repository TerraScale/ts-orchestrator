package host

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// A placed role's members get their own files from the host (TS-651), in
// <managed runtime root>/roles/<role>, each 0600 and owned by the workload
// user. A Vault secret whose key ends in _FILE is written there and the key
// names the file, so the value never enters an environment. A role that
// roleidentity grants buckets gets a NATS user and client certificate there
// too. The host renews both on its running poll, as it renews a TerraBase
// member's certificate; a running process sees them at its next read.

// RoleIdentityIssuer issues node's member of role a NATS user JWT for
// userKey and a client certificate chain for csrPEM.
type RoleIdentityIssuer func(ctx context.Context, role, node, userKey, csrPEM string) (string, []byte, error)

type roleIdentityQuery struct {
	Role    string `json:"role"`
	UserKey string `json:"user_key"`
	CSR     string `json:"csr"`
}

type roleIdentityReply struct {
	JWT         string `json:"jwt"`
	Certificate []byte `json:"certificate"`
}

// serveRoleIdentity issues a role's identity to a host whose current desired
// runs that role.
func (c *Controller) serveRoleIdentity(ctx context.Context, req request, r Registration) (any, error) {
	if c.roleIdentity == nil {
		return nil, errors.New("role identities are not configured")
	}
	var query roleIdentityQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if _, granted := roleidentity.Grants[query.Role]; !granted || !slices.Contains(r.Roles, query.Role) {
		return nil, errors.New("role has no NATS grant on this host")
	}
	d, _, exists, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil {
		return nil, err
	}
	if !exists || d.Withdrawn || d.ManagedMember != nil {
		return nil, errors.New("host has no active member of the role")
	}
	if err := validateDesired(d, c.cell, r); err != nil {
		return nil, err
	}
	raw, chain, err := c.roleIdentity(ctx, query.Role, req.Node, query.UserKey, query.CSR)
	if err != nil {
		return nil, err
	}
	return roleIdentityReply{JWT: raw, Certificate: chain}, nil
}

// secretFilesRefresh is how often a running member's secret files are read
// from the Vault again.
const secretFilesRefresh = time.Minute

func (a *Agent) roleDir(role string) string {
	return filepath.Join(a.cfg.ManagedRuntimeRoot, "roles", role)
}

// prepareRoleFiles writes d's file secrets, taking them out of secrets, and
// its NATS identity, and returns the launch settings that name them. A NATS
// identity the host cannot renew is left out, so the member starts without
// it; the running poll reports and retries the renewal. A host without a
// managed runtime root (a lab host) holds no NATS identities.
func (a *Agent) prepareRoleFiles(ctx context.Context, d Desired, secrets map[string]string) (map[string]string, error) {
	files := map[string]string{}
	for key, value := range secrets {
		if vaultsecret.FileKey(key) {
			files[key] = value
			delete(secrets, key)
		}
	}
	grant, granted := roleidentity.Grants[d.Role]
	if len(files) == 0 && (!granted || a.cfg.ManagedRuntimeRoot == "") {
		return nil, nil
	}
	dir, err := a.ensureRoleDir(d.Role)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	if err := a.writeSecretFiles(dir, files); err != nil {
		return nil, err
	}
	for key := range files {
		env[key] = filepath.Join(dir, strings.ToLower(key))
	}
	if granted {
		_ = a.ensureRoleIdentity(ctx, d.Role, dir)
		if _, current := roleIdentityExpiry(dir); current {
			env[grant.EnvPrefix+"URL"] = a.cfg.NATSURL
			env[grant.EnvPrefix+"CREDENTIALS_FILE"] = filepath.Join(dir, "nats.creds")
			env[grant.EnvPrefix+"CERTIFICATE"] = filepath.Join(dir, "nats.pem")
			env[grant.EnvPrefix+"PRIVATE_KEY"] = filepath.Join(dir, "nats.key")
			env[grant.EnvPrefix+"CA"] = filepath.Join(dir, "nats-ca.pem")
		}
	}
	return env, nil
}

// roleFilesRetry is how long a member waits after a failed renewal.
const roleFilesRetry = time.Minute

type roleFilesFailure struct {
	at  time.Time
	err error
}

// refreshRoleFiles renews a running member's files when they are due: its
// secret files each minute and its NATS identity at half its lifetime. After a
// failure it reports the same error for a minute before it tries again.
func (a *Agent) refreshRoleFiles(ctx context.Context, d Desired) error {
	fileRefs := maps.Clone(d.Secrets)
	maps.DeleteFunc(fileRefs, func(key string, _ vaultsecret.Ref) bool { return !vaultsecret.FileKey(key) })
	_, granted := roleidentity.Grants[d.Role]
	if len(fileRefs) == 0 && (!granted || a.cfg.ManagedRuntimeRoot == "") {
		return nil
	}
	if failure, failed := a.roleFilesFailures[d.Role]; failed && time.Since(failure.at) < roleFilesRetry {
		return failure.err
	}
	err := a.renewRoleFiles(ctx, d, fileRefs, granted)
	if a.roleFilesFailures == nil {
		a.roleFilesFailures = map[string]roleFilesFailure{}
	}
	if err != nil {
		// Logged once per distinct error, so a renewal that keeps failing is not silent.
		if previous, failed := a.roleFilesFailures[d.Role]; !failed || previous.err.Error() != err.Error() {
			slog.Warn("role files renewal failed", "component", "roles", "role", d.Role, "error", err)
		}
		a.roleFilesFailures[d.Role] = roleFilesFailure{at: time.Now(), err: err}
	} else {
		delete(a.roleFilesFailures, d.Role)
	}
	return err
}

func (a *Agent) renewRoleFiles(ctx context.Context, d Desired, fileRefs map[string]vaultsecret.Ref, granted bool) error {
	dir, err := a.ensureRoleDir(d.Role)
	if err != nil {
		return err
	}
	var errs []error
	if len(fileRefs) != 0 && secretFilesDue(dir, fileRefs) {
		values, err := a.resolveSecrets(ctx, Desired{Role: d.Role, Secrets: fileRefs})
		if err == nil {
			err = a.writeSecretFiles(dir, values)
		}
		errs = append(errs, err)
	}
	if granted {
		errs = append(errs, a.ensureRoleIdentity(ctx, d.Role, dir))
	}
	return errors.Join(errs...)
}

func secretFilesDue(dir string, refs map[string]vaultsecret.Ref) bool {
	for key := range refs {
		info, err := os.Stat(filepath.Join(dir, strings.ToLower(key)))
		if err != nil || time.Since(info.ModTime()) > secretFilesRefresh {
			return true
		}
	}
	return false
}

func (a *Agent) ensureRoleDir(role string) (string, error) {
	if a.cfg.ManagedRuntimeRoot == "" {
		return "", errors.New(role + " needs role files, which need the host's managed runtime root")
	}
	roles := filepath.Join(a.cfg.ManagedRuntimeRoot, "roles")
	if err := validateWorkloadRoot("role files", roles, a.cfg.WorkloadIdentity,
		a.cfg.InstallRoot, a.cfg.StateRoot, a.cfg.TerraBaseRoot, a.cfg.TSAuthRoot); err != nil {
		return "", err
	}
	supervisor, gid := os.Geteuid(), int(a.cfg.WorkloadIdentity.GID)
	if err := ensureOwnedDir(roles, supervisor, gid, 0o750); err != nil {
		return "", err
	}
	if a.cfg.MemoryRuntime {
		if err := vaultsecret.RequireMemoryFilesystem(roles); err != nil {
			return "", err
		}
	}
	dir := a.roleDir(role)
	return dir, ensureOwnedDir(dir, supervisor, gid, 0o750)
}

func (a *Agent) writeSecretFiles(dir string, values map[string]string) error {
	for key, value := range values {
		if err := a.writeRoleFile(filepath.Join(dir, strings.ToLower(key)), []byte(value)); err != nil {
			return fmt.Errorf("write secret file %s: %w", key, err)
		}
	}
	return nil
}

// writeRoleFile atomically replaces a 0600 file the workload user owns. The
// agent sets the mode before it gives the file away: it holds CAP_CHOWN but
// not CAP_FOWNER.
func (a *Agent) writeRoleFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	_, err = temporary.Write(data)
	if err == nil {
		err = temporary.Chmod(0o600)
	}
	if err == nil {
		err = temporary.Chown(int(a.cfg.WorkloadIdentity.UID), int(a.cfg.WorkloadIdentity.GID))
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// roleIdentityExpiry reads the NATS client certificate in dir, which is
// written last and expires with the user JWT, and reports whether it is
// still current.
func roleIdentityExpiry(dir string) (*x509.Certificate, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "nats.pem"))
	if err != nil {
		return nil, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, false
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}
	return certificate, time.Now().Before(certificate.NotAfter)
}

// ensureRoleIdentity asks the controller for a new NATS identity once less
// than half of the current one's lifetime remains.
func (a *Agent) ensureRoleIdentity(ctx context.Context, role, dir string) error {
	if certificate, current := roleIdentityExpiry(dir); current &&
		time.Until(certificate.NotAfter) > certificate.NotAfter.Sub(certificate.NotBefore)/2 {
		return nil
	}
	if a.cfg.NATSURL == "" || a.cfg.NATSCAFile == "" {
		return errors.New(role + " NATS identity needs the host's NATS URL and CA")
	}
	ca, err := os.ReadFile(a.cfg.NATSCAFile)
	if err != nil {
		return err
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		return err
	}
	defer user.Wipe()
	userKey, err := user.PublicKey()
	if err != nil {
		return err
	}
	seed, err := user.Seed()
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	var reply roleIdentityReply
	if err := a.request(ctx, "role-identity", roleIdentityQuery{Role: role, UserKey: userKey,
		CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}, &reply); err != nil {
		return fmt.Errorf("%s NATS identity: %w", role, err)
	}
	claim, err := jwt.DecodeUserClaims(reply.JWT)
	block, _ := pem.Decode(reply.Certificate)
	if err != nil || claim.Subject != userKey || block == nil {
		return errors.New("controller returned an unusable role NATS identity")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if public, ok := leaf.PublicKey.(*ecdsa.PublicKey); err != nil || !ok || !public.Equal(&key.PublicKey) {
		return errors.New("controller returned a certificate for another key")
	}
	creds, err := jwt.FormatUserConfig(reply.JWT, seed)
	if err != nil {
		return err
	}
	defer clear(creds)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	// The certificate goes last: it marks a complete identity.
	for _, file := range []struct {
		name string
		data []byte
	}{{"nats.creds", creds}, {"nats.key", keyPEM}, {"nats-ca.pem", ca}, {"nats.pem", bytes.Clone(reply.Certificate)}} {
		if err := a.writeRoleFile(filepath.Join(dir, file.name), file.data); err != nil {
			return fmt.Errorf("write %s NATS identity: %w", role, err)
		}
	}
	return nil
}
