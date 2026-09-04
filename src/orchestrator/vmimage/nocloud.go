package vmimage

import (
	"bytes"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
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
}

// NoCloudSeed contains the three files consumed by cloud-init's NoCloud data
// source. The caller writes these bytes into an ISO or VFAT image labelled
// "cidata" and attaches it read-only to the guest.
type NoCloudSeed struct {
	MetaData      []byte
	NetworkConfig []byte
	UserData      []byte
}

// BuildNoCloudSeed validates the guest identity and produces deterministic
// cloud-init data. It does not execute a shell or embed a private credential.
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

	nameservers, err := canonicalNameservers(spec.Nameservers)
	if err != nil {
		return NoCloudSeed{}, err
	}
	return NoCloudSeed{
		MetaData:      buildNoCloudMetaData(spec),
		NetworkConfig: buildNoCloudNetwork(address, spec.PrefixBits, gateway, guestMAC, nameservers),
		UserData:      buildNoCloudUserData(spec, dataDevice, dataMount),
	}, nil
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

func buildNoCloudUserData(spec NoCloudSeedSpec, dataDevice, dataMount string) []byte {
	var output bytes.Buffer
	output.WriteString("#cloud-config\n")
	output.WriteString("preserve_hostname: false\n")
	fmt.Fprintf(&output, "hostname: %s\n", yamlScalar(spec.Hostname))
	output.WriteString("manage_etc_hosts: true\n")
	output.WriteString("disable_root: false\n")
	output.WriteString("ssh_pwauth: false\n")
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
	output.WriteString("  - path: " + GuestControlPath + "\n")
	output.WriteString("    owner: root:root\n")
	output.WriteString("    permissions: '0500'\n")
	output.WriteString("    encoding: b64\n")
	fmt.Fprintf(&output, "    content: %s\n", base64.StdEncoding.EncodeToString(spec.GuestControl))
	output.WriteString("  - path: " + GuestSeedPath + "\n")
	output.WriteString("    owner: root:root\n")
	output.WriteString("    permissions: '0600'\n")
	output.WriteString("    encoding: b64\n")
	fmt.Fprintf(&output, "    content: %s\n", base64.StdEncoding.EncodeToString(spec.GuestSeed))
	output.WriteString("runcmd:\n")
	output.WriteString("  - [systemctl, daemon-reload]\n")
	return output.Bytes()
}

func validateGuestControl(data []byte, architecture Architecture) error {
	if len(data) == 0 || len(data) > maxGuestControl {
		return errors.New("vmimage: guest control binary size is invalid")
	}
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("vmimage: guest control binary is not ELF")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Type != elf.ET_EXEC || (file.OSABI != elf.ELFOSABI_NONE && file.OSABI != elf.ELFOSABI_LINUX) {
		return errors.New("vmimage: guest control binary format is not admitted")
	}
	want := elf.EM_X86_64
	if architecture == ArchitectureARM64 {
		want = elf.EM_AARCH64
	}
	if file.Machine != want {
		return errors.New("vmimage: guest control binary architecture does not match guest")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("vmimage: guest control binary requires a dynamic interpreter")
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
	return errors.New("vmimage: guest control binary has no executable entry segment")
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
