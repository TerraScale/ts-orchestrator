//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const materialChunkBytes = 16 << 10
const maxManagedHostFileBytes = 1 << 20
const sqlSchemaBundleName = "sql-schema-bundle.tbsqb"
const managedSQLSchemaBundleMaxBytes = 4 << 10

var managedHostFileNames = [...]string{
	"authority.tbca", "trusted-public-key", "server.crt", "server.key",
	"server-ca.pem", "client-ca.pem", "client-chain.pem", "client-private-key.pem",
	"client-api-keys.json", "client-config.json", "client-managed-manifest.json",
	"signed-v2-s3-config.json", sqlSchemaBundleName,
	backupManifestFileName, backupS3ConfigFileName,
}

const managedCredentialFileName = "client-credentials-current.json"

type materialQuery struct {
	Role                   string `json:"role"`
	File                   string `json:"file"`
	DesiredGeneration      uint64 `json:"desired_generation"`
	DesiredFingerprint     string `json:"desired_fingerprint"`
	MemberID               string `json:"member_id"`
	HostAttempt            uint64 `json:"host_attempt"`
	RegistrationGeneration uint64 `json:"registration_generation"`
	InstanceID             string `json:"instance_id"`
	Offset                 int    `json:"offset"`
	Length                 int    `json:"length"`
	EphemeralPublicKey     []byte `json:"ephemeral_public_key"`
}

type materialReply struct {
	File               string `json:"file"`
	Offset             int    `json:"offset"`
	Total              int    `json:"total"`
	SHA256             string `json:"sha256"`
	EphemeralPublicKey []byte `json:"ephemeral_public_key"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

func materialAAD(req request, query materialQuery) ([]byte, error) {
	return protocol.EncodeJSON(struct {
		Node      string        `json:"node"`
		SessionID string        `json:"session_id"`
		Epoch     uint64        `json:"epoch"`
		Nonce     string        `json:"nonce"`
		Query     materialQuery `json:"query"`
	}{req.Node, req.SessionID, req.Epoch, req.Nonce, query})
}

func materialAEAD(shared, aad []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, aad, "TS-MANAGED-HOST-MATERIAL-V1", 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *Controller) serveMaterial(ctx context.Context, req request, registration Registration, session session) (any, error) {
	if c.materialProvider == nil || c.managedVerifier == nil || registration.ManagedMember == nil ||
		registration.ManagedOCI == nil || registration.ManagedPlacement == nil ||
		registration.Generation != session.RegistrationGeneration {
		return nil, errors.New("managed material delivery is unavailable")
	}
	var query materialQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !slices.Contains(managedHostFileNames[:], query.File) && query.File != managedCredentialFileName || query.Role == "" ||
		query.Length < 1 || query.Length > materialChunkBytes || query.Offset < 0 ||
		query.Offset >= maxManagedHostFileBytes || len(query.EphemeralPublicKey) != 32 ||
		query.RegistrationGeneration != registration.Generation ||
		query.MemberID != registration.ManagedMember.Scope.MemberID ||
		query.HostAttempt != registration.ManagedMember.HostAttempt ||
		query.InstanceID != registration.ManagedOCI.InstanceID {
		return nil, errors.New("managed material query differs from current host registration")
	}
	desired, _, exists, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil {
		return nil, err
	}
	if !exists || desired.Withdrawn || desired.ManagedMember == nil ||
		desired.Generation != query.DesiredGeneration ||
		desired.ManagedMember.Member != *registration.ManagedMember ||
		desired.ManagedMember.OCI != *registration.ManagedOCI ||
		validateDesired(desired, c.cell, registration) != nil {
		return nil, errors.New("managed material is not current desired for this host")
	}
	if slices.Contains(managedHostFileNames[:], query.File) && !managedHostFileEnabled(desired, query.File) {
		return nil, errors.New("managed material file is not enabled by signed desired")
	}
	if slices.Contains(managedHostFileNames[:], query.File) && query.Offset >= managedHostFileLimit(query.File) {
		return nil, errors.New("managed material chunk offset exceeds its file limit")
	}
	fingerprint, err := desiredFingerprint(desired)
	if err != nil || fingerprint != query.DesiredFingerprint {
		return nil, errors.New("managed material desired fingerprint changed")
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return nil, err
	}
	files, err := c.materialProvider(ctx, desired, registration)
	if err != nil {
		return nil, err
	}
	contents := files[query.File]
	if len(contents) == 0 || len(contents) > managedHostFileLimit(query.File) || query.Offset >= len(contents) {
		return nil, errors.New("managed material file is missing or oversized")
	}
	end := min(len(contents), query.Offset+query.Length)
	return encryptMaterialChunk(req, query, contents[query.Offset:end], len(contents), contents)
}

func managedHostFileLimit(name string) int {
	if name == sqlSchemaBundleName {
		return managedSQLSchemaBundleMaxBytes
	}
	if name == backupManifestFileName || name == backupS3ConfigFileName {
		return 16 << 10
	}
	if name == backupCredentialFileName {
		return 4 << 10
	}
	if name == backupDataKeyFileName {
		return 32
	}
	return maxManagedHostFileBytes
}

func managedHostFileEnabled(desired Desired, name string) bool {
	switch name {
	case sqlSchemaBundleName:
		return desired.ManagedMember != nil && desired.ManagedMember.Runtime != nil &&
			desired.ManagedMember.Runtime.SQLSchemaBundleSHA256 != ""
	case backupManifestFileName, backupS3ConfigFileName:
		return desired.ManagedMember != nil && desired.ManagedMember.Runtime != nil &&
			desired.ManagedMember.Runtime.BackupManifestSHA256 != ""
	default:
		return slices.Contains(managedHostFileNames[:], name)
	}
}

func managedHostFilesFor(desired Desired) []string {
	names := make([]string, 0, len(managedHostFileNames))
	for _, name := range managedHostFileNames {
		if managedHostFileEnabled(desired, name) {
			names = append(names, name)
		}
	}
	return names
}

func encryptMaterialChunk(req request, query materialQuery, chunk []byte, total int, whole []byte) (materialReply, error) {
	public, err := ecdh.X25519().NewPublicKey(query.EphemeralPublicKey)
	if err != nil {
		return materialReply{}, err
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return materialReply{}, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return materialReply{}, err
	}
	defer clear(shared)
	aad, err := materialAAD(req, query)
	if err != nil {
		return materialReply{}, err
	}
	aead, err := materialAEAD(shared, aad)
	if err != nil {
		return materialReply{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return materialReply{}, err
	}
	sum := sha256.Sum256(whole)
	return materialReply{File: query.File, Offset: query.Offset, Total: total,
		SHA256: hex.EncodeToString(sum[:]), EphemeralPublicKey: private.PublicKey().Bytes(),
		Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, chunk, aad)}, nil
}

// ensureManagedMemberLayout creates the per-attempt member, material and
// control directories below the image-provisioned runtime root: root-owned,
// workload group, modes 0750/0750/0730. A fresh OCI host has none of them.
// An existing entry must already be exact; nothing is repaired or replaced.
func ensureManagedMemberLayout(root string, launch ManagedMemberLaunch, identity WorkloadIdentity) (managedRuntimePaths, error) {
	paths, err := runtimePaths(root, launch)
	if err != nil {
		return managedRuntimePaths{}, err
	}
	if err := verifyManagedDirectory(root, identity, 0750); err != nil {
		return managedRuntimePaths{}, err
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{paths.memberDir, 0750}, {paths.material, 0750}, {filepath.Dir(paths.socket), 0730}} {
		if err := os.Mkdir(entry.path, 0700); err == nil {
			if err := os.Chown(entry.path, 0, int(identity.GID)); err != nil {
				return managedRuntimePaths{}, err
			}
			if err := os.Chmod(entry.path, entry.mode); err != nil {
				return managedRuntimePaths{}, err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return managedRuntimePaths{}, err
		}
		if err := verifyManagedDirectory(entry.path, identity, entry.mode); err != nil {
			return managedRuntimePaths{}, err
		}
	}
	return paths, nil
}

func (a *Agent) fetchManagedMaterial(ctx context.Context, desired Desired, registration Registration) error {
	if desired.ManagedMember == nil || registration.ManagedMember == nil ||
		desired.ManagedMember.Member != *registration.ManagedMember || a.cfg.ManagedRuntimeRoot == "" {
		return errors.New("managed material delivery lacks exact host binding")
	}
	paths, err := ensureManagedMemberLayout(a.cfg.ManagedRuntimeRoot, *desired.ManagedMember, a.cfg.WorkloadIdentity)
	if err != nil {
		return err
	}
	fingerprint, err := desiredFingerprint(desired)
	if err != nil {
		return err
	}
	for _, name := range managedHostFilesFor(desired) {
		contents, digest, err := a.downloadManagedFile(ctx, desired, registration, fingerprint, name)
		if err != nil {
			return fmt.Errorf("retrieve managed material %s: %w", name, err)
		}
		if want := expectedHostMaterialDigest(desired, name); want != "" && digest != want {
			return fmt.Errorf("managed material %s differs from signed desired", name)
		}
		if err := installManagedFile(paths.material, name, contents, digest, a.cfg.WorkloadIdentity); err != nil {
			return fmt.Errorf("install managed material %s: %w", name, err)
		}
	}
	return nil
}

func expectedHostMaterialDigest(desired Desired, name string) string {
	launch := desired.ManagedMember
	if launch == nil || launch.Runtime == nil {
		return ""
	}
	switch name {
	case "authority.tbca":
		return launch.Authority.CertificateSHA256
	case "trusted-public-key":
		return launch.Runtime.TrustedKeySHA256
	case "server.crt":
		return launch.Runtime.ServerCertificateSHA256
	case "server.key":
		return launch.Runtime.ServerPrivateKeySHA256
	case "client-ca.pem":
		return launch.Runtime.ClientCARootsSHA256
	case "server-ca.pem":
		return launch.Runtime.ReplicationServerCASHA256
	case "client-managed-manifest.json":
		return launch.Runtime.ClientManagedMaterialManifestSHA256
	case "signed-v2-s3-config.json":
		return launch.Runtime.LiveS3ConfigSHA256
	case sqlSchemaBundleName:
		return launch.Runtime.SQLSchemaBundleSHA256
	case backupManifestFileName:
		return launch.Runtime.BackupManifestSHA256
	case backupS3ConfigFileName:
		return launch.Runtime.BackupS3ConfigSHA256
	default:
		return ""
	}
}

func (a *Agent) downloadManagedFile(ctx context.Context, desired Desired, registration Registration,
	fingerprint, name string,
) ([]byte, string, error) {
	var contents []byte
	var digest string
	total := 0
	for total == 0 || len(contents) < total {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		query := materialQuery{Role: desired.Role, File: name, DesiredGeneration: desired.Generation,
			DesiredFingerprint: fingerprint, MemberID: desired.ManagedMember.Member.Scope.MemberID,
			HostAttempt:            desired.ManagedMember.Member.HostAttempt,
			RegistrationGeneration: registration.Generation,
			InstanceID:             desired.ManagedMember.OCI.InstanceID, Offset: len(contents), Length: materialChunkBytes,
			EphemeralPublicKey: private.PublicKey().Bytes()}
		var reply materialReply
		req, err := a.sendToLeader(ctx, "material", query, &reply, nil, nil)
		if err != nil {
			return nil, "", err
		}
		if reply.File != name || reply.Offset != query.Offset || reply.Total < 1 ||
			reply.Total > managedHostFileLimit(name) || !lowerHex(reply.SHA256, 64) ||
			len(reply.EphemeralPublicKey) != 32 || len(reply.Nonce) != 12 ||
			total != 0 && (reply.Total != total || reply.SHA256 != digest) {
			return nil, "", errors.New("managed material chunk identity changed")
		}
		public, err := ecdh.X25519().NewPublicKey(reply.EphemeralPublicKey)
		if err != nil {
			return nil, "", err
		}
		shared, err := private.ECDH(public)
		if err != nil {
			return nil, "", err
		}
		aad, err := materialAAD(req, query)
		if err != nil {
			clear(shared)
			return nil, "", err
		}
		aead, err := materialAEAD(shared, aad)
		clear(shared)
		if err != nil {
			return nil, "", err
		}
		chunk, err := aead.Open(nil, reply.Nonce, reply.Ciphertext, aad)
		if err != nil || len(chunk) == 0 || len(chunk) > materialChunkBytes || len(contents)+len(chunk) > reply.Total {
			return nil, "", errors.New("managed material chunk cannot be authenticated")
		}
		contents = append(contents, chunk...)
		total, digest = reply.Total, reply.SHA256
	}
	sum := sha256.Sum256(contents)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, "", errors.New("managed material file digest changed")
	}
	return contents, digest, nil
}

func installManagedFile(directory, name string, contents []byte, digest string, identity WorkloadIdentity) error {
	allowed := slices.Contains(managedHostFileNames[:], name) ||
		name == backupCredentialFileName || name == backupDataKeyFileName
	if !allowed || len(contents) == 0 ||
		len(contents) > managedHostFileLimit(name) {
		return errors.New("invalid managed material installation")
	}
	sum := sha256.Sum256(contents)
	if hex.EncodeToString(sum[:]) != digest {
		return errors.New("managed material install digest mismatch")
	}
	target := filepath.Join(directory, name)
	if _, err := os.Lstat(target); err == nil {
		_, err = verifyManagedMaterial(target, digest, identity, int64(managedHostFileLimit(name)))
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	token, err := randomID()
	if err != nil {
		return err
	}
	temporary := "." + name + "." + token
	fileFD, err := unix.Openat(dirFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0440)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dirFD, temporary, 0)
	file := os.NewFile(uintptr(fileFD), temporary)
	if err := unix.Fchown(fileFD, 0, int(identity.GID)); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0440); err != nil {
		file.Close()
		return err
	}
	if _, err := io.Copy(file, bytes.NewReader(contents)); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(dirFD, temporary, dirFD, name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			_, err = verifyManagedMaterial(target, digest, identity, int64(managedHostFileLimit(name)))
		}
		return err
	}
	return unix.Fsync(dirFD)
}
