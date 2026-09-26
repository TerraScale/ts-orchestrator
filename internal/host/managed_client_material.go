//go:build linux

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	managedClientManifestName = "client-managed-manifest.json"
	managedClientConfigName   = "client-config.json"
	managedClientChainName    = "client-chain.pem"
	managedClientKeyName      = "client-private-key.pem"
	managedClientRegistryName = "client-api-keys.json"
)

type managedClientManifest struct {
	Version                uint64 `json:"version"`
	ClientConfigSHA256     string `json:"client_config_sha256"`
	CertificateChainSHA256 string `json:"certificate_chain_sha256"`
	PrivateKeySHA256       string `json:"private_key_sha256"`
	APIKeyRegistrySHA256   string `json:"api_key_registry_sha256"`
}

type managedClientConfig struct {
	Version            uint64 `json:"version"`
	ListenAddress      string `json:"listen_addr,omitempty"`
	CertificateChain   string `json:"certificate_chain"`
	PrivateKey         string `json:"private_key"`
	APIKeyRegistry     string `json:"api_key_registry"`
	HandshakeTimeoutMS uint64 `json:"handshake_timeout_ms,omitzero"`
}

func readManagedClientFile(path, digest string, identity WorkloadIdentity, maximum int64, ownerUID uint32) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !lowerHex(digest, 64) {
		return nil, errors.New("managed client material path or digest is invalid")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || !info.Mode().IsRegular() || !os.SameFile(before, info) ||
		stat.Uid != ownerUID || stat.Gid != identity.GID || stat.Mode&07777 != 0440 ||
		info.Size() == 0 || info.Size() > maximum {
		return nil, fmt.Errorf("managed client material has unsafe owner, type, mode or length: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || int64(len(data)) != info.Size() || after.ModTime() != info.ModTime() {
		return nil, fmt.Errorf("managed client material changed while reading: %s", path)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("managed client material digest mismatch: %s", path)
	}
	return data, nil
}

func readManagedClientMaterial(material, digest string, identity WorkloadIdentity, ownerUID uint32) ([]string, error) {
	manifestPath := filepath.Join(material, managedClientManifestName)
	manifestBytes, err := readManagedClientFile(manifestPath, digest, identity, 4<<10, ownerUID)
	if err != nil {
		return nil, err
	}
	var manifest managedClientManifest
	if err := json.Unmarshal(manifestBytes, &manifest, json.RejectUnknownMembers(true)); err != nil ||
		manifest.Version != 1 || !lowerHex(manifest.ClientConfigSHA256, 64) ||
		!lowerHex(manifest.CertificateChainSHA256, 64) || !lowerHex(manifest.PrivateKeySHA256, 64) ||
		!lowerHex(manifest.APIKeyRegistrySHA256, 64) {
		return nil, errors.New("managed client material manifest is invalid")
	}
	configPath := filepath.Join(material, managedClientConfigName)
	configBytes, err := readManagedClientFile(configPath, manifest.ClientConfigSHA256, identity, 16<<10, ownerUID)
	if err != nil {
		return nil, err
	}
	var config managedClientConfig
	if err := json.Unmarshal(configBytes, &config, json.RejectUnknownMembers(true)); err != nil || config.Version != 1 ||
		config.CertificateChain != filepath.Join(material, managedClientChainName) ||
		config.PrivateKey != filepath.Join(material, managedClientKeyName) ||
		config.APIKeyRegistry != filepath.Join(material, managedClientRegistryName) ||
		config.HandshakeTimeoutMS != 0 && (config.HandshakeTimeoutMS < 1000 || config.HandshakeTimeoutMS > 10000) {
		return nil, errors.New("managed client config does not bind deterministic material paths")
	}
	address := config.ListenAddress
	if address == "" {
		address = "127.0.0.1:9465"
	}
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	number, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || number < 1 || number > 65535 || ip == nil || ip.IsUnspecified() {
		return nil, errors.New("managed client listener must be a concrete IP and port")
	}
	for _, file := range []struct {
		name, digest string
		maximum      int64
	}{
		{managedClientChainName, manifest.CertificateChainSHA256, 2 << 20},
		{managedClientKeyName, manifest.PrivateKeySHA256, 2 << 20},
		{managedClientRegistryName, manifest.APIKeyRegistrySHA256, 256 << 10},
	} {
		contents, err := readManagedClientFile(filepath.Join(material, file.name), file.digest, identity, file.maximum, ownerUID)
		if err != nil {
			return nil, err
		}
		clear(contents)
	}
	args := []string{
		"--client-config", configPath,
		"--client-managed-material-manifest", manifestPath,
		"--client-managed-material-manifest-sha256", digest,
	}
	if !ip.IsLoopback() {
		args = append(args, "--client-allow-nonloopback")
	}
	return args, nil
}
