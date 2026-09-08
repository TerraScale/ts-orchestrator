package vmimage

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"

	"golang.org/x/crypto/ssh"
	"terrascale.tech/orchestrator/src/orchestrator/tsnodebootstrap"
)

const (
	NoCloudVolumeLabel = "cidata"
	GuestControlPath   = "/usr/local/libexec/terrascale-vmqual-control"
	GuestSeedPath      = "/etc/terrascale/vmqual-guest-seed.json"
	defaultDataMount   = "/var/lib/terrascale"
	maxGuestControl    = 32 << 20
)

// NoCloudSeedSpec is the complete, non-secret per-guest cloud-init input.
// The SSH public key is temporary test access. Its private half never enters
// the seed, repository, logs, or qualification report.
type NoCloudSeedSpec struct {
	InstanceID       string
	Hostname         string
	Region           string
	Address          string
	PrefixBits       int
	Gateway          string
	MACAddress       string
	Nameservers      []string
	SSHAuthorizedKey string
	DataDevice       string
	DataMount        string
	GuestSeed        []byte
	GuestControl     []byte
	TSNode           TSNodeBootstrap
}

// NoCloudSeed contains the three files consumed by cloud-init's NoCloud data
// source. Qualification writes them into /var/lib/cloud/seed/nocloud in the
// private guest root filesystem before boot.
type NoCloudSeed struct {
	MetaData      []byte
	NetworkConfig []byte
	UserData      []byte
	RootFiles     []NoCloudRootFile
}

// NoCloudRootFile is validated bootstrap material installed in the private root before boot.
// Paths and modes are fixed by BuildNoCloudSeed, never supplied by guest input.
type NoCloudRootFile struct {
	runPath   string
	runDigest [32]byte
	// Owner is the verified final bootstrap principal; empty means root.
	Owner   string
	Path    string
	Mode    uint32
	Content []byte
}

// Validate rejects root file destinations, permissions and sizes outside the seed contract.
func (file NoCloudRootFile) Validate() error {
	if file.runPath != "" {
		if file.Path != file.runPath || file.Owner != membershipServiceUser || file.Mode != 0400 || len(file.Content) == 0 || len(file.Content) > 1<<20 || sha256.Sum256(file.Content) != file.runDigest {
			return errors.New("vmimage: run root file differs from admitted sideband")
		}
		return nil
	}
	engineOwner := (vmengineconfig.IsTLSPath(file.Path) || vmengineconfig.IsTransitionTrustPath(file.Path) || vmengineconfig.IsBackupPath(file.Path) || vmengineconfig.IsIdentityPath(file.Path)) && file.Owner == vmengineconfig.ServiceUser
	if file.Owner != "" && !engineOwner && ((file.Path != MembershipIdentityPath && !vmcontrolseed.IsFilePath(file.Path) && !vmcandidateseed.IsServiceFile(file.Path) && !vmengineconfig.IsControlPath(file.Path) && !vmengineconfig.IsDatabasePath(file.Path)) || file.Owner != membershipServiceUser) {
		return errors.New("vmimage: unbound root file bootstrap owner")
	}
	limit := 0
	switch {
	case (vmengineconfig.IsControlPath(file.Path) || vmengineconfig.IsDatabasePath(file.Path)) && file.Mode == 0400 && file.Owner == membershipServiceUser:
		limit = 64 << 10
	case (file.Path == vmengineconfig.ObserverCertificatePath || file.Path == vmengineconfig.ObserverPrivateKeyPath || file.Path == vmengineconfig.ObserverCAPath) && file.Mode == 0600 && file.Owner == "":
		limit = 64 << 10
	case engineOwner && file.Mode == 0400:
		limit = 64 << 10
	case vmcandidateseed.IsServiceFile(file.Path) && file.Mode == 0400 && file.Owner == membershipServiceUser:
		limit = 64 << 10
	case vmcontrolseed.IsAuthorityFilePath(file.Path) && file.Mode == 0400 && file.Owner == "":
		limit = 64 << 10
	case vmcontrolseed.IsFilePath(file.Path) && file.Mode == 0400 && file.Owner == membershipServiceUser:
		limit = 64 << 10
	case file.Path == BootstrapGrantPath && file.Mode == 0400:
		limit = 128 << 10
	case file.Path == BootstrapPublicKeyPath && file.Mode == 0400:
		limit = 1024
	case file.Path == MembershipIdentityPath && file.Mode == 0400 && file.Owner == membershipServiceUser:
		limit = 64 << 10
	case (file.Path == commandTrustPath(0) || file.Path == commandTrustPath(1) || file.Path == commandTrustPath(2) || file.Path == commandTrustPath(3)) && file.Mode == 0444:
		limit = 1024
	case file.Path == MembershipPinsPath && file.Mode == 0444:
		limit = 256 << 10
	case file.Path == GuestControlPath && file.Mode == 0500:
		limit = maxGuestControl
	case file.Path == tsNodeBootstrapBinaryPath && file.Mode == 0600:
		limit = maxTSNodeBinaryBytes
	case (file.Path == tsNodeNKeyPath || file.Path == tsNodeTLSCAPath || file.Path == tsNodeTLSCertPath || file.Path == tsNodeTLSKeyPath) && file.Mode == 0600:
		limit = 64 << 10
	case (file.Path == "/usr/sbin/chronyd" || file.Path == "/usr/bin/chronyc") && file.Mode == 0555:
		limit = 2 << 20
	}
	if limit == 0 || len(file.Content) == 0 || len(file.Content) > limit {
		return errors.New("vmimage: invalid NoCloud root file")
	}
	return nil
}

// BuildNoCloudSeed validates the guest identity and produces deterministic
// cloud-init data and private root files. Credentials never enter cloud-init data.
func BuildNoCloudSeed(spec NoCloudSeedSpec) (NoCloudSeed, error) {
	if !instanceIDPattern.MatchString(spec.InstanceID) {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud instance id is not safe")
	}
	if !namePattern.MatchString(spec.Hostname) || len(spec.Hostname) > 253 {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud hostname is not safe")
	}
	if !namePattern.MatchString(spec.Region) || len(spec.Region) > 32 {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud region is not safe")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(spec.Address))
	if err != nil || !address.Is4() || !address.IsPrivate() || spec.PrefixBits < 24 || spec.PrefixBits > 30 {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud address must be IPv4 with a /24-/30 prefix")
	}
	gateway, err := netip.ParseAddr(strings.TrimSpace(spec.Gateway))
	if err != nil || !gateway.Is4() || !gateway.IsPrivate() {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud gateway must be IPv4")
	}
	prefix := netip.PrefixFrom(address, spec.PrefixBits).Masked()
	if !prefix.Contains(gateway) || address == gateway || !usablePrefixAddress(address, prefix) || !usablePrefixAddress(gateway, prefix) {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud address and gateway must share the declared subnet")
	}
	authorizedKey, err := canonicalSSHPublicKey(spec.SSHAuthorizedKey)
	if err != nil {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud SSH public key is not an admitted key")
	}
	spec.SSHAuthorizedKey = authorizedKey
	guestMAC, err := canonicalGuestMAC(spec.MACAddress)
	if err != nil {
		return NoCloudSeed{}, err
	}
	dataDevice := strings.TrimSpace(spec.DataDevice)
	if dataDevice == "" {
		dataDevice = "/dev/vdb"
	}
	if dataDevice != "/dev/vdb" {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud data device must be /dev/vdb")
	}
	dataMount := strings.TrimSpace(spec.DataMount)
	if dataMount == "" {
		dataMount = defaultDataMount
	}
	if dataMount != defaultDataMount {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud data mount must be /var/lib/terrascale")
	}
	if len(spec.GuestSeed) == 0 || len(spec.GuestSeed) > 64<<10 {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud guest seed must contain 1-65536 bytes")
	}
	guestSeed, err := DecodeGuestChannelSeed(spec.GuestSeed)
	if err != nil {
		return NoCloudSeed{}, fmt.Errorf("vmimage: NoCloud guest seed: %w", err)
	}
	if guestSeed.InstanceID != spec.InstanceID || guestSeed.Hostname != spec.Hostname || guestSeed.Region != spec.Region || guestSeed.DataDiskPath != dataDevice {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud metadata does not match the guest seed")
	}
	if err := validateGuestControl(spec.GuestControl, guestSeed.Image.Architecture); err != nil {
		return NoCloudSeed{}, err
	}
	if spec.TSNode.Candidate != nil && spec.TSNode.Candidate.Config.Region != spec.Region {
		return NoCloudSeed{}, errors.New("vmimage: candidate material belongs to another region")
	}
	if spec.TSNode.Controller != nil && (spec.TSNode.Controller.Address != spec.Address || spec.Region != "gru") {
		return NoCloudSeed{}, errors.New("vmimage: controller seed must match the declared GRU guest address")
	}
	if spec.TSNode.Engine != nil && spec.TSNode.Engine.Address() != spec.Address {
		return NoCloudSeed{}, errors.New("vmimage: engine material belongs to another guest address")
	}
	tsNode, err := canonicalTSNodeBootstrap(spec.TSNode, guestSeed.Image.Architecture)
	if err != nil {
		return NoCloudSeed{}, err
	}
	if err := validateNoCloudBindings(spec, guestSeed, gateway, tsNode); err != nil {
		return NoCloudSeed{}, err
	}

	nameservers, err := canonicalNameservers(spec.Nameservers)
	if err != nil {
		return NoCloudSeed{}, err
	}
	seed := NoCloudSeed{
		MetaData:      buildNoCloudMetaData(spec),
		NetworkConfig: buildNoCloudNetwork(address, spec.PrefixBits, gateway, guestMAC, nameservers),
		UserData:      buildNoCloudUserData(spec, dataDevice, dataMount, tsNode),
		RootFiles: append([]NoCloudRootFile{
			{Path: GuestControlPath, Mode: 0500, Content: append([]byte(nil), spec.GuestControl...)},
			{Path: tsNodeBootstrapBinaryPath, Mode: 0600, Content: tsNode.binary},
			{Path: tsNodeNKeyPath, Mode: 0600, Content: tsNode.identity.NKeySeed},
			{Path: tsNodeTLSCAPath, Mode: 0600, Content: tsNode.identity.TLSCA},
			{Path: tsNodeTLSCertPath, Mode: 0600, Content: tsNode.identity.TLSCertificate},
			{Path: tsNodeTLSKeyPath, Mode: 0600, Content: tsNode.identity.TLSPrivateKey},
			{Path: MembershipIdentityPath, Mode: 0400, Owner: membershipServiceUser, Content: tsNode.membershipPrivate},
			{Path: MembershipPinsPath, Mode: 0444, Content: tsNode.membershipPins},
		}, tsNode.commandTrustFiles...),
	}
	seen := map[string]bool{}
	for _, file := range seed.RootFiles {
		if seen[file.Path] {
			return NoCloudSeed{}, errors.New("vmimage: repeated root payload path")
		}
		seen[file.Path] = true
		if err := file.Validate(); err != nil {
			return NoCloudSeed{}, err
		}
	}
	return seed, nil
}

func validateNoCloudBindings(spec NoCloudSeedSpec, guestSeed GuestChannelSeed, gateway netip.Addr, tsNode tsNodeBootstrapMaterial) error {
	if spec.TSNode.Config.NodeID != guestSeed.InstanceID {
		return errors.New("vmimage: ts-node node id does not match the NoCloud instance id")
	}
	wantGateway := gateway.String()
	if spec.TSNode.Config.NATSURL != "tls://"+wantGateway+":4222" {
		return errors.New("vmimage: ts-node NATS endpoint does not match the NoCloud gateway")
	}
	if tsNode.hostAddress != wantGateway {
		return errors.New("vmimage: artifact host address does not match the NoCloud gateway")
	}
	if guestSeed.NetworkExchangeEndpoint != wantGateway+":18080" {
		return errors.New("vmimage: guest network exchange endpoint does not match the NoCloud gateway")
	}

	artifacts := make(map[string]GuestArtifact, len(guestSeed.Artifacts))
	for _, artifact := range guestSeed.Artifacts {
		artifacts[artifact.Component] = artifact
	}
	bootstrapArtifact := artifacts["ts-node"]
	if tsNode.version != bootstrapArtifact.Version || tsNode.digest != bootstrapArtifact.SHA256 || int64(len(tsNode.binary)) != bootstrapArtifact.Size {
		return errors.New("vmimage: ts-node bootstrap does not match the guest seed artifact")
	}
	for _, component := range tsNode.desired.Components {
		artifact := artifacts[component.Name]
		versionMatches := component.Version == artifact.Version
		if strings.HasPrefix(component.Version, "ctl-") {
			versionMatches = component.ArtifactURL == "https://"+artifactReleaseHost+":"+artifactReleasePort+"/releases/"+component.Name+"/"+artifact.Version+"/"+component.Name
		}
		if !versionMatches || component.Sha256 != artifact.SHA256 {
			return fmt.Errorf("vmimage: desired %s component does not match the guest seed artifact", component.Name)
		}
	}
	return nil
}

func usablePrefixAddress(address netip.Addr, prefix netip.Prefix) bool {
	valueBytes := address.As4()
	networkBytes := prefix.Addr().As4()
	value := binary.BigEndian.Uint32(valueBytes[:])
	network := binary.BigEndian.Uint32(networkBytes[:])
	hostMask := ^uint32(0) >> prefix.Bits()
	return value != network && value != network|hostMask
}

func canonicalSSHPublicKey(value string) (string, error) {
	if len(value) == 0 || len(value) > 1024 || value != strings.TrimSpace(value) {
		return "", errors.New("SSH public key size is invalid")
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("SSH public key contains a control character")
		}
	}
	publicKey, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("SSH public key encoding is invalid")
	}
	switch publicKey.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoSKED25519:
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))), nil
	default:
		return "", errors.New("SSH public key algorithm is not admitted")
	}
}

func canonicalGuestMAC(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("vmimage: NoCloud MAC address is missing or malformed")
	}
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 || parsed[0]&0x01 != 0 || parsed[0]&0x02 == 0 {
		return "", errors.New("vmimage: NoCloud MAC address must be a locally administered unicast MAC")
	}
	return parsed.String(), nil
}

func canonicalNameservers(input []string) ([]netip.Addr, error) {
	if len(input) == 0 {
		input = []string{"1.1.1.1"}
	}
	if len(input) > 3 {
		return nil, errors.New("vmimage: NoCloud permits at most three nameservers")
	}
	seen := make(map[netip.Addr]bool, len(input))
	result := make([]netip.Addr, 0, len(input))
	for _, value := range input {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
			return nil, errors.New("vmimage: NoCloud nameserver must be a usable IPv4 address")
		}
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result, nil
}

func buildNoCloudMetaData(spec NoCloudSeedSpec) []byte {
	var output bytes.Buffer
	fmt.Fprintf(&output, "instance-id: %s\n", yamlScalar(spec.InstanceID))
	fmt.Fprintf(&output, "local-hostname: %s\n", yamlScalar(spec.Hostname))
	fmt.Fprintf(&output, "terrascale-region: %s\n", yamlScalar(spec.Region))
	return output.Bytes()
}

func buildNoCloudNetwork(address netip.Addr, prefixBits int, gateway netip.Addr, guestMAC string, nameservers []netip.Addr) []byte {
	var output bytes.Buffer
	output.WriteString("version: 2\n")
	output.WriteString("ethernets:\n")
	output.WriteString("  eth0:\n")
	output.WriteString("    match:\n")
	fmt.Fprintf(&output, "      macaddress: %s\n", yamlScalar(guestMAC))
	output.WriteString("    set-name: eth0\n")
	fmt.Fprintf(&output, "    addresses: [%s/%d]\n", address, prefixBits)
	output.WriteString("    routes:\n")
	fmt.Fprintf(&output, "      - {to: 0.0.0.0/0, via: %s}\n", gateway)
	output.WriteString("    nameservers:\n")
	output.WriteString("      addresses: [")
	for index, nameserver := range nameservers {
		if index > 0 {
			output.WriteString(", ")
		}
		output.WriteString(nameserver.String())
	}
	output.WriteString("]\n")
	return output.Bytes()
}

func buildNoCloudUserData(spec NoCloudSeedSpec, dataDevice, dataMount string, tsNode tsNodeBootstrapMaterial) []byte {
	var output bytes.Buffer
	output.WriteString("#cloud-config\n")
	output.WriteString("preserve_hostname: false\n")
	fmt.Fprintf(&output, "hostname: %s\n", yamlScalar(spec.Hostname))
	output.WriteString("manage_etc_hosts: true\n")
	output.WriteString("disable_root: false\n")
	output.WriteString("ssh_pwauth: false\n")
	output.WriteString("bootcmd:\n")
	output.WriteString("  - [/usr/bin/install, -d, -o, root, -g, root, -m, '0700', " + tsNodeBootstrapDirectory + "]\n")
	output.WriteString("  - [/usr/bin/install, -d, -o, root, -g, root, -m, '0755', /etc/terrascale]\n")
	output.WriteString("users:\n")
	output.WriteString("  - name: root\n")
	output.WriteString("    lock_passwd: true\n")
	output.WriteString("    ssh_authorized_keys:\n")
	fmt.Fprintf(&output, "      - %s\n", yamlScalar(`restrict,command="`+GuestControlPath+`" `+strings.TrimSpace(spec.SSHAuthorizedKey)))
	output.WriteString("fs_setup:\n")
	output.WriteString("  - label: terrascale-data\n")
	output.WriteString("    filesystem: ext4\n")
	fmt.Fprintf(&output, "    device: %s\n", yamlScalar(dataDevice))
	output.WriteString("    overwrite: false\n")
	output.WriteString("mounts:\n")
	fmt.Fprintf(&output, "  - [%s, %s, ext4, 'defaults,nofail,nodev,nosuid', '0', '2']\n", yamlScalar(dataDevice), yamlScalar(dataMount))
	output.WriteString("write_files:\n")
	writeNoCloudChrony(&output, tsNode.hostAddress)
	versionDirectory := "/opt/terrascale/ts-node/" + tsNode.version
	writeNoCloudFile(&output, versionDirectory+"/ts-node.launch.json", "root:root", "0444", tsNode.launchManifest)
	writeNoCloudFile(&output, versionDirectory+"/ts-node.config", "root:root", "0444", nil)
	writeNoCloudFile(&output, versionDirectory+"/ts-node.sha256", "root:root", "0444", []byte(tsNode.digest))
	writeNoCloudFile(&output, tsNodeBootstrapSigPath, "root:root", "0600", tsNode.signature)
	writeNoCloudFile(&output, tsNodeBootstrapKeyPath, "root:root", "0600", tsNode.publicKeyPEM)
	writeNoCloudFile(&output, tsNodeBootstrapDigestPath, "root:root", "0600", []byte(tsNode.digest+"  "+tsNodeBootstrapBinaryPath+"\n"))
	writeNoCloudFile(&output, tsNodeConfigPath, "root:root", "0600", tsNode.config)
	writeNoCloudFile(&output, tsNodeBootstrapManifestPath, "root:root", "0600", tsNode.manifest)
	writeNoCloudLiteralFile(&output, "/etc/systemd/system/"+tsnodebootstrap.UnitName, "root:root", "0644", tsNode.unit)
	writeNoCloudLiteralFile(&output, tsNodeBootstrapScriptPath, "root:root", "0500", buildTSNodeBootstrapScript(tsNode))
	output.WriteString("  - path: " + cloudHostsTemplatePath + "\n")
	output.WriteString("    owner: root:root\n")
	output.WriteString("    permissions: '0644'\n")
	output.WriteString("    append: true\n")
	output.WriteString("    content: |\n")
	output.WriteString("      " + tsNode.hostAddress + " " + artifactReleaseHost + "\n")
	if len(tsNode.ca) != 0 {
		writeNoCloudFile(&output, artifactCAPath, "root:root", "0644", tsNode.ca)
	}
	output.WriteString("  - path: " + GuestSeedPath + "\n")
	output.WriteString("    owner: root:root\n")
	output.WriteString("    permissions: '0600'\n")
	output.WriteString("    encoding: b64\n")
	fmt.Fprintf(&output, "    content: %s\n", base64.StdEncoding.EncodeToString(spec.GuestSeed))
	output.WriteString("runcmd:\n")
	output.WriteString("  - [/bin/sh, " + tsNodeBootstrapScriptPath + "]\n")
	return output.Bytes()
}

func writeNoCloudFile(output *bytes.Buffer, path, owner, permissions string, content []byte) {
	output.WriteString("  - path: " + path + "\n")
	output.WriteString("    owner: " + owner + "\n")
	output.WriteString("    permissions: '" + permissions + "'\n")
	output.WriteString("    encoding: b64\n")
	if len(content) == 0 {
		output.WriteString("    content: ''\n")
	} else {
		output.WriteString("    content: " + base64.StdEncoding.EncodeToString(content) + "\n")
	}
}

func writeNoCloudLiteralFile(output *bytes.Buffer, path, owner, permissions, content string) {
	output.WriteString("  - path: " + path + "\n")
	output.WriteString("    owner: " + owner + "\n")
	output.WriteString("    permissions: '" + permissions + "'\n")
	output.WriteString("    content: |\n")
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		output.WriteString("      " + line + "\n")
	}
}

func validateGuestControl(data []byte, architecture Architecture) error {
	if len(data) == 0 || len(data) > maxGuestControl {
		return errors.New("vmimage: guest control binary size is invalid")
	}
	if err := validateStaticELF(data, architecture); err != nil {
		return fmt.Errorf("vmimage: guest control binary %w", err)
	}
	return nil
}

func validateStaticELF(data []byte, architecture Architecture) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("is not ELF")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Type != elf.ET_EXEC || (file.OSABI != elf.ELFOSABI_NONE && file.OSABI != elf.ELFOSABI_LINUX) {
		return errors.New("format is not admitted")
	}
	want := elf.EM_X86_64
	if architecture == ArchitectureARM64 {
		want = elf.EM_AARCH64
	}
	if file.Machine != want {
		return errors.New("architecture does not match guest")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("requires a dynamic interpreter")
		}
	}
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 || program.Filesz == 0 || program.Memsz < program.Filesz || program.Off > uint64(len(data)) || program.Filesz > uint64(len(data))-program.Off || program.Vaddr > ^uint64(0)-program.Filesz {
			continue
		}
		if file.Entry >= program.Vaddr && file.Entry < program.Vaddr+program.Filesz {
			return nil
		}
	}
	return errors.New("has no executable entry segment")
}

// MACForIPv4 returns the locally administered Firecracker MAC spelling that
// encodes the guest address. It matches Firecracker's Ubuntu test-image
// convention and remains deterministic across process restarts.
func MACForIPv4(address string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(address)).To4()
	if ip == nil {
		return "", errors.New("vmimage: MAC source must be IPv4")
	}
	return fmt.Sprintf("06:00:%02x:%02x:%02x:%02x", ip[0], ip[1], ip[2], ip[3]), nil
}
