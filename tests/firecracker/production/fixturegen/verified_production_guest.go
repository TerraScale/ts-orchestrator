package fixturegen

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/tests/firecracker/production"
)

// SimulatorConfig is one instance's signed, host-only IMDS identity and exact
// read inventory. It is validated through the real simulator constructor.
func (packet VerifiedPacket) SimulatorConfig(slot string) (production.Config, error) {
	var instance string
	for _, controller := range packet.manifest.Controllers {
		if controller.Slot == slot {
			instance = controller.InstanceOCID
		}
	}
	if instance == "" {
		return production.Config{}, fmt.Errorf("unknown simulator slot %q", slot)
	}
	root := "simulator/imds/" + slot + "/"
	tenancy, err := packet.readListedFile(root + "tenancy.txt")
	if err != nil {
		return production.Config{}, err
	}
	certificate, err := packet.readListedFile(root + "leaf.pem")
	if err != nil {
		return production.Config{}, err
	}
	key, err := packet.readListedFile(root + "leaf.key")
	if err != nil {
		return production.Config{}, err
	}
	intermediate, err := packet.readListedFile(root + "intermediate.pem")
	if err != nil {
		return production.Config{}, err
	}
	reads, missing, err := packet.SimulatorRoutes(slot)
	if err != nil {
		return production.Config{}, err
	}
	config := production.Config{Region: "sa-saopaulo-1", InstanceID: instance,
		DescriptorSlot: slot, TenancyID: string(tenancy), LeafCertificate: certificate,
		LeafPrivateKey: key, Intermediate: intermediate, Reads: reads, Missing: missing}
	if _, err := production.NewSimulator(config); err != nil {
		return production.Config{}, fmt.Errorf("validate %s simulator: %w", slot, err)
	}
	return config, nil
}

// PrivateAddress returns the signed completed-install VNIC address for one VM.
func (packet VerifiedPacket) PrivateAddress(slot string) (string, error) {
	files, err := packet.GuestFiles(slot)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if file.GuestPath != "/var/lib/terrascale-orchestrator-bootstrap/accepted-install.json" {
			continue
		}
		var marker bootstrapstart.AcceptedInstall
		if err := protocol.DecodeStrict(file.Body, &marker, 1<<20); err != nil ||
			marker.Slot != slot || marker.PrimaryPrivateIP == "" {
			return "", fmt.Errorf("controller %q has invalid signed restart marker", slot)
		}
		return marker.PrimaryPrivateIP, nil
	}
	return "", fmt.Errorf("controller %q lacks signed restart marker", slot)
}

// SimulatorTLS returns the signed HTTPS server pair for the host-only OCI
// simulator. Its private key is never a GuestFile.
func (packet VerifiedPacket) SimulatorTLS(now time.Time) ([]byte, []byte, error) {
	certificate, err := packet.readListedFile("simulator/tls/oci.crt")
	if err != nil {
		return nil, nil, err
	}
	key, err := packet.readListedFile("simulator/tls/oci.key")
	if err != nil {
		return nil, nil, err
	}
	var ca []byte
	for _, controller := range packet.manifest.Controllers {
		files, err := packet.GuestFiles(controller.Slot)
		if err != nil {
			return nil, nil, err
		}
		found := false
		for _, file := range files {
			if file.GuestPath != fixtureCAGuestPath {
				continue
			}
			if found || ca != nil && !bytes.Equal(ca, file.Body) {
				return nil, nil, errors.New("guest OCI trust anchors differ across controllers")
			}
			ca = file.Body
			found = true
		}
		if !found {
			return nil, nil, fmt.Errorf("controller %q lacks guest OCI trust anchor", controller.Slot)
		}
	}
	if err := validateSimulatorTLS(ca, certificate, key, now); err != nil {
		return nil, nil, err
	}
	return certificate, key, nil
}

// ValidateProductionGuests closes the packet's config, credential, marker,
// VNIC, CA and HTTPS-server boundary before an image is touched.
func (packet VerifiedPacket) ValidateProductionGuests(now time.Time) error {
	if _, _, err := packet.SimulatorTLS(now); err != nil {
		return err
	}
	observations := make(map[string]GuestObservation, len(packet.manifest.Controllers))
	configs := make(map[string][]byte, len(packet.manifest.Controllers))
	credentials := make(map[string]map[string][]byte, len(packet.manifest.Controllers))
	network := make(map[string]map[string][]byte, len(packet.manifest.Controllers))
	for _, controller := range packet.manifest.Controllers {
		config, err := packet.SimulatorConfig(controller.Slot)
		if err != nil {
			return err
		}
		leafBlock, _ := pem.Decode(config.LeafCertificate)
		issuerBlock, _ := pem.Decode(config.Intermediate)
		if leafBlock == nil || issuerBlock == nil {
			return fmt.Errorf("controller %q IMDS chain is absent", controller.Slot)
		}
		leaf, leafErr := x509.ParseCertificate(leafBlock.Bytes)
		issuer, issuerErr := x509.ParseCertificate(issuerBlock.Bytes)
		if leafErr != nil || issuerErr != nil || !issuer.IsCA || leaf.IsCA ||
			now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
			now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
			return fmt.Errorf("controller %q IMDS certificate chain is not current", controller.Slot)
		}
		files, err := packet.GuestFiles(controller.Slot)
		if err != nil {
			return err
		}
		material := make(map[string][]byte)
		network[controller.Slot] = make(map[string][]byte, 5)
		var markerWire []byte
		for _, file := range files {
			switch {
			case file.GuestPath == controllerConfigGuestPath:
				configs[controller.Slot] = file.Body
			case file.GuestPath == "/var/lib/terrascale-orchestrator-bootstrap/accepted-install.json":
				markerWire = file.Body
			case strings.HasPrefix(file.GuestPath, serviceSecretsGuestDir+"/"):
				material[strings.TrimPrefix(file.GuestPath, serviceSecretsGuestDir+"/")] = file.Body
			case file.GuestPath == guestNetworkPath || file.GuestPath == guestTimesyncPath ||
				file.GuestPath == guestHostsPath || file.GuestPath == guestCloudDisabledPath ||
				file.GuestPath == guestSSHConfigPath:
				network[controller.Slot][file.GuestPath] = file.Body
			}
		}
		var marker bootstrapstart.AcceptedInstall
		if len(markerWire) == 0 || protocol.DecodeStrict(markerWire, &marker, 1<<20) != nil {
			return fmt.Errorf("controller %q has no canonical restart marker", controller.Slot)
		}
		canonical, err := protocol.EncodeJSON(marker)
		if err != nil || !bytes.Equal(canonical, markerWire) ||
			marker.Slot != controller.Slot || marker.InstanceOCID != controller.InstanceOCID ||
			marker.BinarySHA256 != packet.manifest.Binary.SHA256 ||
			len(marker.MaterialSHA256) != len(material) {
			return fmt.Errorf("controller %q restart marker differs from signed packet", controller.Slot)
		}
		for name, body := range material {
			digest := sha256.Sum256(body)
			if marker.MaterialSHA256[name] != hex.EncodeToString(digest[:]) {
				return fmt.Errorf("controller %q credential %q differs from restart marker", controller.Slot, name)
			}
		}
		observations[controller.Slot] = GuestObservation{
			PrimaryVNICOCID: marker.PrimaryVNICOCID, PrimaryPrivateIP: marker.PrimaryPrivateIP}
		credentials[controller.Slot] = material
	}
	for _, controller := range packet.manifest.Controllers {
		expectedNetwork, err := productionNetworkFiles(observations[controller.Slot].PrimaryPrivateIP)
		if err != nil || len(network[controller.Slot]) != len(expectedNetwork) {
			return fmt.Errorf("controller %q lacks isolated network configuration: %w", controller.Slot, err)
		}
		for path, body := range expectedNetwork {
			if !bytes.Equal(network[controller.Slot][path], body) {
				return fmt.Errorf("controller %q has unexpected signed network file %q", controller.Slot, path)
			}
		}
		if err := validateControllerConfig(configs[controller.Slot], controller.Slot,
			controller.InstanceOCID, observations[controller.Slot].PrimaryPrivateIP,
			observations, credentials[controller.Slot]); err != nil {
			return fmt.Errorf("controller %q production configuration: %w", controller.Slot, err)
		}
		if _, err := packet.GuestDirectories(controller.Slot); err != nil {
			return err
		}
	}
	return nil
}

func (packet VerifiedPacket) readListedFile(name string) ([]byte, error) {
	if packet.root == "" {
		return nil, errors.New("packet was not verified")
	}
	for _, entry := range packet.manifest.Files {
		if entry.Path != name {
			continue
		}
		path := filepath.Join(packet.root, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != entry.Mode {
			return nil, fmt.Errorf("signed host file %q changed type or mode", name)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(body)
		if int64(len(body)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return nil, fmt.Errorf("signed host file %q changed bytes", name)
		}
		return body, nil
	}
	return nil, fmt.Errorf("signed host file %q is absent", name)
}
