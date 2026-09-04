package vmimage

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const (
	NoCloudVolumeLabel = "cidata"
	defaultDataMount   = "/var/lib/terrascale"
)

var sshPublicKeyPattern = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/]+={0,2}(?: [^\r\n]{1,128})?$`)

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
	Nameservers      []string
	SSHAuthorizedKey string
	DataDevice       string
	DataMount        string
	GuestSeed        []byte
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
	if err != nil || !address.Is4() || spec.PrefixBits < 24 || spec.PrefixBits > 30 {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud address must be IPv4 with a /24-/30 prefix")
	}
	gateway, err := netip.ParseAddr(strings.TrimSpace(spec.Gateway))
	if err != nil || !gateway.Is4() {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud gateway must be IPv4")
	}
	prefix := netip.PrefixFrom(address, spec.PrefixBits).Masked()
	if !prefix.Contains(gateway) || address == gateway || address == prefix.Addr() {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud address and gateway must share the declared subnet")
	}
	if !sshPublicKeyPattern.MatchString(strings.TrimSpace(spec.SSHAuthorizedKey)) {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud SSH public key is not an admitted key")
	}
	dataDevice := strings.TrimSpace(spec.DataDevice)
	if dataDevice == "" {
		dataDevice = "/dev/vdb"
	}
	if !validDataDiskPath(dataDevice) || !strings.HasPrefix(dataDevice, "/dev/") {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud data device must be an absolute /dev path")
	}
	dataMount := strings.TrimSpace(spec.DataMount)
	if dataMount == "" {
		dataMount = defaultDataMount
	}
	if !validDataDiskPath(dataMount) || dataMount == "/" || strings.HasPrefix(dataMount, "/dev/") {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud data mount is invalid")
	}
	if len(spec.GuestSeed) == 0 || len(spec.GuestSeed) > 64<<10 {
		return NoCloudSeed{}, errors.New("vmimage: NoCloud guest seed must contain 1-65536 bytes")
	}
	if _, err := DecodeGuestChannelSeed(spec.GuestSeed); err != nil {
		return NoCloudSeed{}, fmt.Errorf("vmimage: NoCloud guest seed: %w", err)
	}

	nameservers, err := canonicalNameservers(spec.Nameservers)
	if err != nil {
		return NoCloudSeed{}, err
	}
	return NoCloudSeed{
		MetaData:      buildNoCloudMetaData(spec),
		NetworkConfig: buildNoCloudNetwork(address, spec.PrefixBits, gateway, nameservers),
		UserData:      buildNoCloudUserData(spec, dataDevice, dataMount),
	}, nil
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
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
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

func buildNoCloudNetwork(address netip.Addr, prefixBits int, gateway netip.Addr, nameservers []netip.Addr) []byte {
	var output bytes.Buffer
	output.WriteString("version: 2\n")
	output.WriteString("ethernets:\n")
	output.WriteString("  eth0:\n")
	output.WriteString("    match:\n")
	output.WriteString("      name: 'eth*'\n")
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
	fmt.Fprintf(&output, "      - %s\n", yamlScalar(strings.TrimSpace(spec.SSHAuthorizedKey)))
	output.WriteString("fs_setup:\n")
	output.WriteString("  - label: terrascale-data\n")
	output.WriteString("    filesystem: ext4\n")
	fmt.Fprintf(&output, "    device: %s\n", yamlScalar(dataDevice))
	output.WriteString("    overwrite: false\n")
	output.WriteString("mounts:\n")
	fmt.Fprintf(&output, "  - [%s, %s, ext4, 'defaults,nofail,nodev,nosuid', '0', '2']\n", yamlScalar(dataDevice), yamlScalar(dataMount))
	output.WriteString("write_files:\n")
	output.WriteString("  - path: /run/terrascale/guest-seed.json\n")
	output.WriteString("    owner: root:root\n")
	output.WriteString("    permissions: '0600'\n")
	output.WriteString("    encoding: b64\n")
	fmt.Fprintf(&output, "    content: %s\n", base64.StdEncoding.EncodeToString(spec.GuestSeed))
	output.WriteString("runcmd:\n")
	output.WriteString("  - [systemctl, daemon-reload]\n")
	output.WriteString("  - [systemctl, is-system-running, --wait]\n")
	return output.Bytes()
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
