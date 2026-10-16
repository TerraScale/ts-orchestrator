package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// HostCredentialDirectory holds a host's enrollment identity and its
// credentials in memory (TS-745). host-setup's RuntimeDirectory outlives the
// oneshot, so the host agent reads the credentials host.json names. A reboot
// empties it: host-setup restores the identity from its Vault record and the
// credentials from the kept response. A pending renewal request is public
// (signed, public keys only) and stays beside host.json, so after a reboot
// host-setup replays exactly the request the controller may have committed.
const HostCredentialDirectory = "/run/terrascale-orchestrator-host-credentials"

// hostResponseFile, beside host.json, keeps the installed credentials'
// public half: the controller's response with the NATS user JWT and the TLS
// chain, useless without the identity's keys. A reboot rebuilds the
// credentials in memory from it, since the controller renews only within a
// credential's last day (TS-745).
const hostResponseFile = "host-enrollment-response.json"

// hostIdentityRefFile, beside host.json, names the Vault record of the
// host's enrollment identity: {"vault": "<Vault OCID>", "name": "<secret>"}.
const hostIdentityRefFile = "host-enrollment-vault.json"

// hostIdentityRecord is the durable copy of .host-enrollment-pending.json:
// the host's identity, NATS and TLS keys and its signed enrollment request.
// Every change is published as a new CURRENT version before it is used.
type hostIdentityRecord struct {
	// read returns the record's OCID, CURRENT version and value; publish
	// adds value after the expected version and returns the new one.
	read    func(context.Context) (string, int64, []byte, error)
	publish func(ctx context.Context, id string, expected int64, value []byte) (int64, error)
	id      string
	version int64
}

// loadHostIdentityRecord reads root's reference file; the record must already
// exist in Vault. It reads and publishes with the instance principal.
func loadHostIdentityRecord(root, region string) (*hostIdentityRecord, error) {
	file, err := os.Open(filepath.Join(root, hostIdentityRefFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("host enrollment identity has no Vault record: write %s first",
			filepath.Join(root, hostIdentityRefFile))
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, 4<<10))
	if err != nil {
		return nil, err
	}
	var ref vaultsecret.Ref
	if err := json.Unmarshal(wire, &ref, json.RejectUnknownMembers(true)); err != nil ||
		!strings.Contains(ref.Vault, "."+region+".") || ref.Name == "" {
		return nil, fmt.Errorf("%s must name a %s Vault and secret", hostIdentityRefFile, region)
	}
	return &hostIdentityRecord{
		read: func(ctx context.Context) (string, int64, []byte, error) {
			current, err := vaultsecret.ReadCurrentRefs(ctx, map[string]vaultsecret.Ref{"HOST_ENROLLMENT_FILE": ref})
			record := current["HOST_ENROLLMENT_FILE"]
			return record.ID, record.Version, []byte(record.Value()), err
		},
		publish: func(ctx context.Context, id string, expected int64, value []byte) (int64, error) {
			factory, err := ociclient.InstancePrincipal(region)
			if err != nil {
				return 0, err
			}
			current, err := vaultsecret.Publish(ctx, factory, ref, id, expected, value)
			return current.Version, err
		}}, nil
}

// restore writes the identity into secrets unless it is there already. A
// host enrolled before its identity moved to memory keeps it below legacy:
// that copy is imported once, published first when the record differs, but
// only while host.json names the on-disk credentials issued for it. It is
// then removed, so a later restore never takes a stale disk copy over a newer
// record (a rename publishes before it enrolls). Otherwise CURRENT is restored.
func (record *hostIdentityRecord) restore(ctx context.Context, legacy, secrets string) error {
	path := filepath.Join(secrets, pendingHostEnrollmentFile)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	value, err := record.current(ctx)
	if err != nil {
		return err
	}
	defer clear(value)
	old, err := os.ReadFile(filepath.Join(legacy, pendingHostEnrollmentFile))
	if errors.Is(err, os.ErrNotExist) {
		return writeAtomicHostFile(path, value, 0o600)
	}
	if err != nil {
		return err
	}
	defer clear(old)
	if !bytes.Equal(old, value) && liveLegacyIdentity(legacy, old) {
		if err := record.save(ctx, old); err != nil {
			return err
		}
		value = old
	}
	if err := writeAtomicHostFile(path, value, 0o600); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(legacy, pendingHostEnrollmentFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// liveLegacyIdentity reports whether host.json names on-disk credentials
// issued for the identity in wire: an identity key file below legacy that
// holds its key.
func liveLegacyIdentity(legacy string, wire []byte) bool {
	var pending pendingHostEnrollment
	if json.Unmarshal(wire, &pending) != nil || pending.IdentityKey == "" {
		return false
	}
	config, err := LoadConfig(filepath.Join(legacy, "host.json"))
	if err != nil || filepath.Dir(filepath.Dir(config.Host.IdentityKeyFile)) != legacy {
		return false
	}
	key, err := os.ReadFile(config.Host.IdentityKeyFile)
	defer clear(key)
	return err == nil && string(key) == pending.IdentityKey+"\n"
}

// current reads the record's CURRENT version and remembers which one it is.
func (record *hostIdentityRecord) current(ctx context.Context) ([]byte, error) {
	id, version, value, err := record.read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the host enrollment identity from Vault: %w", err)
	}
	record.id, record.version = id, version
	return value, nil
}

// save publishes a changed identity before host-setup writes or uses it.
func (record *hostIdentityRecord) save(ctx context.Context, wire []byte) error {
	if record == nil {
		return nil
	}
	if record.id == "" {
		value, err := record.current(ctx)
		clear(value)
		if err != nil {
			return err
		}
	}
	version, err := record.publish(ctx, record.id, record.version, wire)
	if err != nil {
		return fmt.Errorf("publish the host enrollment identity to Vault: %w", err)
	}
	record.version = version
	return nil
}

// removeLegacyHostEnrollment deletes the enrollment files a host kept below
// root before its identity and credentials moved to memory, once host.json
// names credentials in secrets: the identity is in Vault, and the
// credentials are renewed from it.
func removeLegacyHostEnrollment(root, secrets string) error {
	config, err := LoadConfig(filepath.Join(root, "host.json"))
	if err != nil {
		return err
	}
	if filepath.Dir(filepath.Dir(config.NATS.CredentialsFile)) != secrets {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == pendingHostEnrollmentFile ||
			entry.IsDir() && strings.HasPrefix(name, "host-credentials-") {
			if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
				return err
			}
		}
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// recoverHostCredentials reinstalls, in secrets, the credentials host.json
// names when they are missing there: after a reboot from the saved response,
// and once from the on-disk credentials an earlier release installed. Only a
// response that still validates against the enrolled identity is reused;
// otherwise host-setup renews or enrolls as before.
func recoverHostCredentials(ctx context.Context, root, secrets string, bundle hostenroll.PublicBundle,
	descriptor hostboot.Descriptor, pending pendingHostEnrollment, request hostenroll.Request, runtime hostSetupRuntime,
) error {
	config, err := LoadConfig(filepath.Join(root, "host.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var response hostenroll.Response
	switch filepath.Dir(filepath.Dir(config.NATS.CredentialsFile)) {
	case secrets:
		complete := true
		for _, path := range []string{config.Host.IdentityKeyFile, config.NATS.CredentialsFile,
			config.NATS.TLS.KeyFile, config.NATS.TLS.CertFile, config.NATS.TLS.CAFile} {
			if _, err := os.Stat(path); err != nil {
				complete = false
			}
		}
		if complete {
			return nil
		}
		wire, err := os.ReadFile(filepath.Join(root, hostResponseFile))
		if err != nil || json.Unmarshal(wire, &response, json.RejectUnknownMembers(true)) != nil {
			return nil
		}
	case root:
		chain, chainErr := os.ReadFile(config.NATS.TLS.CertFile)
		creds, credsErr := os.ReadFile(config.NATS.CredentialsFile)
		defer clear(creds)
		if chainErr != nil || credsErr != nil {
			return nil
		}
		raw, err := nkeys.ParseDecoratedJWT(creds)
		block, _ := pem.Decode(chain)
		if err != nil || block == nil {
			return nil
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		response = hostenroll.Response{NATSUserJWT: raw, TLSCertificatePEM: string(chain), ExpiresAt: leaf.NotAfter,
			Roles: config.Host.Roles}
	default:
		return nil
	}
	if !time.Now().Before(response.ExpiresAt) || validateHostCredentials(bundle, descriptor.Node, pending, request, response) != nil {
		return nil
	}
	return installHostEnrollment(ctx, root, secrets, bundle, descriptor, pending, response, runtime.ownerUID, runtime.netbird)
}
