//go:build linux

package host

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

const (
	managedVolumeFirecrackerRoot      = "/srv/ts-managed"
	managedVolumeFirecrackerUUID      = "76f1b43d-7d79-4f41-9a6e-cc1f4aaab102"
	managedVolumeFirecrackerAlias     = "/dev/oracleoci/oraclevdb"
	managedVolumeFirecrackerMemberDir = "/srv/ts-managed/6efe9447512debbf02bcd921c78d666c"
	managedVolumeAuthoritySHA256      = "e9885a5c3c5eac8efbf5d6854866244c54d4adeb862fe91a57d3c8f173d190f0"
	managedVolumeTrustedKeySHA256     = "adf52c840c161baf342951546c0482ad4239288e5a85922fe747f156eab1fc10"
	managedVolumeServerCertSHA256     = "45c3a23d09dca88712bad1046329a71c8976c502b0108b06b65d31cb0fd08fef"
	managedVolumeServerKeySHA256      = "907092f426b6a38f9d40e60779f070754a596eca1a453218c2d804deeb9e4e24"
	managedVolumeClientCASHA256       = "f9a5bc265028693ecc6acc85249983b050851bb33c606ffac639a659da3d5b9d"
	managedVolumeClientManifestSHA256 = "6bc94cb7163f97229a76bbb0682bd11f9a8065cd5c6c5216fb10544bb7e751b9"
	managedVolumeClientConfigSHA256   = "3ae7950f7cb17ecc6daa014389d75cd198d4501411f71690b0061bdde75cd446"
	managedVolumeClientChainSHA256    = "1f91c353063e9a0b5a9a3b3496cc6400703db8542acd26890a6c9101416fb0d8"
	managedVolumeClientKeySHA256      = "ed38bd9962273a9bc63f62b9f3734692c4197a683f26d4d12fb5adaf793e69d7"
	managedVolumeAPIKeysSHA256        = "7c9ad3ef69c9fbf2fe7f32931e24c3ff7da8b8ef295b6cf563c6d1bee22f3c0b"
	managedVolumeServerTLSLeafSHA256  = "3d644bacdddacbba9fe0c753dbbd369220175381672fa579b6b9b9b063c0119d"
	managedVolumeReplicationDNS       = "member-a.terrabase.test"
	managedVolumeReplicationIP        = "10.77.39.11"
	managedVolumePeerMemberID         = "018f0000-0000-7000-8000-000000000002"
	managedVolumePeerAddress          = "10.77.39.12:7000"
)

func TestManagedRuntimeFirecrackerMountedVolume(t *testing.T) {
	// Requires the pinned Firecracker managed-volume fixture.
	volumeUUID := tier.Qualification(t, "TS_FC_VOLUME_UUID")[0]
	if volumeUUID != managedVolumeFirecrackerUUID {
		t.Fatalf("TS_FC_VOLUME_UUID = %q, want fixture UUID %q", volumeUUID, managedVolumeFirecrackerUUID)
	}
	if os.Geteuid() != 0 {
		t.Fatal("Firecracker managed-volume verification requires the trusted root-owned setup")
	}

	registration, desired, _ := managedContractFixture()
	root := managedVolumeFirecrackerRoot
	paths, err := runtimePaths(root, *desired.ManagedMember)
	if err != nil {
		t.Fatalf("derive host-managed runtime paths: %v", err)
	}
	mountPath, err := ManagedMountPath(root, desired.ManagedMember.Member)
	if err != nil {
		t.Fatalf("ManagedMountPath(): %v", err)
	}
	wantMountPath := filepath.Join(managedVolumeFirecrackerMemberDir, "volume")
	if paths.memberDir != managedVolumeFirecrackerMemberDir || paths.mount != wantMountPath || mountPath != wantMountPath {
		t.Fatalf("fixture mount path = runtime %q/%q, exported %q; want %q",
			paths.memberDir, paths.mount, mountPath, wantMountPath)
	}

	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	materialPaths := map[string]string{
		"authority.tbca":               filepath.Join(paths.material, "authority.tbca"),
		"trusted-public-key":           filepath.Join(paths.material, "trusted-public-key"),
		"server.crt":                   filepath.Join(paths.material, "server.crt"),
		"server.key":                   filepath.Join(paths.material, "server.key"),
		"client-ca.pem":                filepath.Join(paths.material, "client-ca.pem"),
		"server-ca.pem":                filepath.Join(paths.material, "server-ca.pem"),
		"client-managed-manifest.json": filepath.Join(paths.material, "client-managed-manifest.json"),
		"client-config.json":           filepath.Join(paths.material, "client-config.json"),
		"client-chain.pem":             filepath.Join(paths.material, "client-chain.pem"),
		"client-private-key.pem":       filepath.Join(paths.material, "client-private-key.pem"),
		"client-api-keys.json":         filepath.Join(paths.material, "client-api-keys.json"),
	}
	expectedDigests := map[string]string{
		"authority.tbca":               managedVolumeAuthoritySHA256,
		"trusted-public-key":           managedVolumeTrustedKeySHA256,
		"server.crt":                   managedVolumeServerCertSHA256,
		"server.key":                   managedVolumeServerKeySHA256,
		"client-ca.pem":                managedVolumeClientCASHA256,
		"server-ca.pem":                managedVolumeClientCASHA256,
		"client-managed-manifest.json": managedVolumeClientManifestSHA256,
		"client-config.json":           managedVolumeClientConfigSHA256,
		"client-chain.pem":             managedVolumeClientChainSHA256,
		"client-private-key.pem":       managedVolumeClientKeySHA256,
		"client-api-keys.json":         managedVolumeAPIKeysSHA256,
	}
	material := make(map[string][]byte, len(materialPaths))
	digests := make(map[string]string, len(materialPaths))
	for name, path := range materialPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read trusted fixture material %s: %v", name, err)
		}
		digest := sha256.Sum256(data)
		material[name] = data
		digests[name] = hex.EncodeToString(digest[:])
		if digests[name] != expectedDigests[name] {
			t.Fatalf("fixture material %s SHA-256 = %s, want %s", name, digests[name], expectedDigests[name])
		}
	}
	if !bytes.Equal(material["client-ca.pem"], material["server-ca.pem"]) {
		t.Fatal("server-ca.pem is not the pinned shared client-ca.pem fixture")
	}
	if len(material["trusted-public-key"]) != 32 {
		t.Fatalf("trusted-public-key length = %d, want 32 bytes", len(material["trusted-public-key"]))
	}
	serverPair, err := tls.X509KeyPair(material["server.crt"], material["server.key"])
	if err != nil || len(serverPair.Certificate) == 0 {
		t.Fatalf("parse matching managed server TLS material: certificate count=%d err=%v", len(serverPair.Certificate), err)
	}
	leaf, err := x509.ParseCertificate(serverPair.Certificate[0])
	if err != nil {
		t.Fatalf("parse managed server TLS leaf: %v", err)
	}
	leafDigest := sha256.Sum256(leaf.Raw)
	if got := hex.EncodeToString(leafDigest[:]); got != managedVolumeServerTLSLeafSHA256 {
		t.Fatalf("managed server TLS leaf SHA-256 = %s, want %s", got, managedVolumeServerTLSLeafSHA256)
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("replication TLS leaf EKUs = %v, want serverAuth and clientAuth", leaf.ExtKeyUsage)
	}
	serverRoots := x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(material["server-ca.pem"]) {
		t.Fatal("server-ca.pem contains no valid CA certificates")
	}
	for _, keyUsage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: serverRoots, KeyUsages: []x509.ExtKeyUsage{keyUsage}}); err != nil {
			t.Fatalf("verify replication TLS leaf for EKU %v: %v", keyUsage, err)
		}
	}
	for _, host := range []string{managedVolumeReplicationDNS, managedVolumeReplicationIP} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Fatalf("verify replication TLS leaf name %q: %v", host, err)
		}
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(material["client-ca.pem"]) {
		t.Fatal("client-ca.pem contains no valid CA certificates")
	}
	clientPair, err := tls.X509KeyPair(material["client-chain.pem"], material["client-private-key.pem"])
	if err != nil || len(clientPair.Certificate) == 0 {
		t.Fatalf("parse matching managed client HTTPS TLS material: certificate count=%d err=%v", len(clientPair.Certificate), err)
	}
	clientLeaf, err := x509.ParseCertificate(clientPair.Certificate[0])
	if err != nil {
		t.Fatalf("parse managed client HTTPS TLS leaf: %v", err)
	}
	if !slices.Contains(clientLeaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("client HTTPS TLS leaf EKUs = %v, want serverAuth", clientLeaf.ExtKeyUsage)
	}
	if err := clientLeaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("verify client HTTPS TLS leaf listener IP: %v", err)
	}
	if _, err := clientLeaf.Verify(x509.VerifyOptions{
		Roots: clientCAPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify client HTTPS TLS leaf: %v", err)
	}

	launch := *desired.ManagedMember
	launch.AttachmentETag = "firecracker-attachment-etag"
	launch.Authority.CertificateSHA256 = digests["authority.tbca"]
	launch.Authority.TLSLeafSHA256 = managedVolumeServerTLSLeafSHA256
	launch.Runtime = &ManagedRuntimePins{
		DevicePath: managedVolumeFirecrackerAlias, MountPath: mountPath,
		FileSystemUUID: volumeUUID, FileSystemType: "ext4",
		TrustedKeySHA256:                    digests["trusted-public-key"],
		ServerCertificateSHA256:             digests["server.crt"],
		ServerPrivateKeySHA256:              digests["server.key"],
		ClientCARootsSHA256:                 digests["client-ca.pem"],
		ClientManagedMaterialManifestSHA256: digests["client-managed-manifest.json"],
		ReplicationListenAddress:            managedVolumeReplicationIP + ":7000",
		ReplicationPeerMemberID:             managedVolumePeerMemberID,
		ReplicationPeerAddress:              managedVolumePeerAddress,
		ReplicationServerCASHA256:           digests["server-ca.pem"],
	}
	desired.ManagedMember = &launch
	if err := validateDesired(desired, registration.Cell, registration); err != nil {
		t.Fatalf("validate pinned Firecracker desired: %v", err)
	}
	cfg := AgentConfig{ManagedRuntimeRoot: root, WorkloadIdentity: identity}
	executable := "/opt/terrascale/bin/terrabase"
	fingerprint := strings.Repeat("f", 64)
	workload, mount, socket, err := prepareManagedRuntime(t.Context(), cfg, desired, executable, fingerprint)
	if err != nil {
		t.Fatalf("prepareManagedRuntime(): %v", err)
	}
	defer mount.close()

	aliasTarget, err := os.Readlink(managedVolumeFirecrackerAlias)
	if err != nil || aliasTarget != "../vdb" {
		t.Fatalf("OCI block alias target = %q, err=%v; want ../vdb", aliasTarget, err)
	}
	deviceInfo, err := os.Lstat("/dev/vdb")
	if err != nil {
		t.Fatalf("stat attached Firecracker data device: %v", err)
	}
	deviceStat, ok := deviceInfo.Sys().(*syscall.Stat_t)
	if !ok || deviceInfo.Mode()&os.ModeDevice == 0 || deviceInfo.Mode()&os.ModeCharDevice != 0 ||
		deviceStat.Uid != 0 || mount.witness == nil || mount.witness.stat.Rdev != deviceStat.Rdev {
		t.Fatalf("held OCI device witness does not identify root-owned /dev/vdb: stat=%+v mount=%+v", deviceStat, mount)
	}
	if mount.id == 0 || mount.device != managedVolumeFirecrackerAlias || mount.uuid != volumeUUID || mount.fsType != "ext4" {
		t.Fatalf("mounted volume identity = id:%d device:%q uuid:%q fs:%q", mount.id, mount.device, mount.uuid, mount.fsType)
	}
	if id, err := findExclusiveMount("/proc/self/mountinfo", mountPath, deviceStat.Rdev, "ext4"); err != nil || id != mount.id {
		t.Fatalf("mounted ext4 is not the one exclusive read-write mount: id=%d held=%d err=%v", id, mount.id, err)
	}
	if err := verifyManagedDeviceWitness(mount); err != nil {
		t.Fatalf("verify held Firecracker device witness: %v", err)
	}
	if socket != paths.socket {
		t.Fatalf("managed control socket = %q, want %q", socket, paths.socket)
	}
	shardPath := filepath.Join(mountPath, "replication", "shard")
	if _, err := os.Lstat(shardPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replication shard path is not initially absent: lstat err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(mountPath, managedVolumeClaimName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only prepare created or found a volume claim: lstat err=%v", err)
	}
	wantArgs := []string{
		"--data-dir", filepath.Join(mountPath, "data"),
		"--memory-limit-bytes", "4294967296",
		"--memory-headroom-bytes", "1073741824",
		"--replication-listen-addr", managedVolumeReplicationIP + ":7000",
		"--replication-data-dir", shardPath,
		"--authority-certificate", filepath.Join(paths.material, "authority.tbca"),
		"--trusted-public-key", filepath.Join(paths.material, "trusted-public-key"),
		"--replication-server-certificate", filepath.Join(paths.material, "server.crt"),
		"--replication-server-private-key", filepath.Join(paths.material, "server.key"),
		"--replication-client-ca-roots", filepath.Join(paths.material, "client-ca.pem"),
		"--cluster-id", launch.Member.Scope.ClusterID,
		"--tenant-id", launch.Member.Scope.TenantID,
		"--database-id", launch.Member.Scope.DatabaseID,
		"--shard-id", "1",
		"--member-id", launch.Member.Scope.MemberID,
		"--member-incarnation", launch.Member.Scope.Incarnation,
		"--member-control-socket", socket,
		"--replication-peer-member-id", managedVolumePeerMemberID,
		"--replication-peer-addr", managedVolumePeerAddress,
		"--replication-server-ca-roots", filepath.Join(paths.material, "server-ca.pem"),
		"--client-config", filepath.Join(paths.material, "client-config.json"),
		"--client-managed-material-manifest", filepath.Join(paths.material, "client-managed-manifest.json"),
		"--client-managed-material-manifest-sha256", managedVolumeClientManifestSHA256,
	}
	if workload.Role != desired.Role || workload.Digest != desired.Digest || workload.Fingerprint != fingerprint ||
		workload.Executable != executable || workload.CgroupMemoryMaxBytes != launch.CgroupMemoryMaxBytes ||
		workload.SystemReserveBytes != launch.SystemReserveBytes ||
		!slices.Equal(workload.Args, wantArgs) {
		t.Fatalf("prepared TerraBase workload differs from pinned runtime: role=%q digest=%q executable=%q memory=%d args=%v",
			workload.Role, workload.Digest, workload.Executable, workload.CgroupMemoryMaxBytes, workload.Args)
	}
	wrongUUID := "00000000-0000-0000-0000-000000000000"
	if wrongUUID == volumeUUID {
		wrongUUID = "11111111-1111-1111-1111-111111111111"
	}
	wrongUUIDDesired := desiredWithManagedRuntime(desired, func(pins *ManagedRuntimePins) {
		pins.FileSystemUUID = wrongUUID
	})
	if _, wrongMount, _, err := prepareManagedRuntime(t.Context(), cfg, wrongUUIDDesired, executable, fingerprint); err == nil {
		wrongMount.close()
		t.Fatal("managed volume accepted a filesystem UUID that differs from the fixture pin")
	}
	wrongMountDesired := desiredWithManagedRuntime(desired, func(pins *ManagedRuntimePins) {
		pins.MountPath = filepath.Join(mountPath, "wrong-mount")
	})
	if _, wrongMount, _, err := prepareManagedRuntime(t.Context(), cfg, wrongMountDesired, executable, fingerprint); err == nil {
		wrongMount.close()
		t.Fatal("managed volume accepted a mount path outside ManagedMountPath")
	}

	if err := retargetManagedVolumeAliasForTest(managedVolumeFirecrackerAlias, "../vda"); err != nil {
		t.Fatalf("retarget OCI volume alias for witness rejection: %v", err)
	}
	restored := false
	defer func() {
		if !restored {
			if err := retargetManagedVolumeAliasForTest(managedVolumeFirecrackerAlias, "../vdb"); err != nil {
				t.Errorf("restore OCI volume alias after retarget check: %v", err)
			}
		}
	}()
	if err := verifyManagedDeviceWitness(mount); err == nil {
		t.Fatal("held device witness accepted a retargeted OCI block alias")
	}
	if _, replacementMount, _, err := prepareManagedRuntime(t.Context(), cfg, desired, executable, fingerprint); err == nil {
		replacementMount.close()
		t.Fatal("managed runtime accepted a retargeted OCI block alias")
	}
	if err := retargetManagedVolumeAliasForTest(managedVolumeFirecrackerAlias, "../vdb"); err != nil {
		t.Fatalf("restore OCI block alias: %v", err)
	}
	restored = true
	if err := verifyManagedDeviceWitness(mount); err != nil {
		t.Fatalf("restored volume alias no longer matches the held witness: %v", err)
	}
	t.Logf("managed-volume-v1 device=%s uuid=%s mount=%s mount_id=%d replication_shard=absent", mount.device, mount.uuid, mountPath, mount.id)
}

func desiredWithManagedRuntime(desired Desired, change func(*ManagedRuntimePins)) Desired {
	copy := desired
	launch := *desired.ManagedMember
	pins := *launch.Runtime
	change(&pins)
	launch.Runtime = &pins
	copy.ManagedMember = &launch
	return copy
}

func retargetManagedVolumeAliasForTest(alias, target string) error {
	temporary := alias + ".managed-volume-test"
	if _, err := os.Lstat(temporary); err == nil {
		return fmt.Errorf("temporary alias path already exists: %s", temporary)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, alias); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}
