// Package fixturegen validates the host-only production restart fixture packet.
// Its manifest inventories every byte that the Firecracker driver may install
// or serve. Signing material stays outside the guest root.
package fixturegen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/tests/firecracker/production"
)

const (
	ManifestVersion = 1
	maxPacketBytes  = 640 << 20
	maxRouteBodies  = 32 << 20
	maxSourcePins   = 256
)

type FileEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Mode      uint32 `json:"mode"`
	OwnerRole string `json:"ownerRole"`
}

type Route struct {
	ControllerSlot string    `json:"controllerSlot"`
	InstanceOCID   string    `json:"instanceOcid"`
	Host           string    `json:"host"`
	RequestURI     string    `json:"requestUri"`
	Status         int       `json:"status"`
	BodyPath       string    `json:"bodyPath,omitzero"`
	ETag           string    `json:"etag,omitzero"`
	LastModified   time.Time `json:"lastModified,omitzero"`
}

type Controller struct {
	Slot         string `json:"slot"`
	InstanceOCID string `json:"instanceOcid"`
	GuestRoot    string `json:"guestRoot"`
}

type BinaryInput struct {
	Path         string `json:"path"`
	GuestPath    string `json:"guestPath"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Architecture string `json:"architecture"`
}

type SourcePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	DeploymentID  string       `json:"deploymentId"`
	Cell          string       `json:"cell"`
	Environment   string       `json:"environment"`
	FixtureNow    time.Time    `json:"fixtureNow"`
	Binary        BinaryInput  `json:"binary"`
	Controllers   []Controller `json:"controllers"`
	SourcePins    []SourcePin  `json:"sourcePins"`
	Files         []FileEntry  `json:"files"`
	Routes        []Route      `json:"routes"`
}

// VerifiedPacket is produced only after the signature, full file inventory,
// and per-controller copy boundary have passed validation.
type VerifiedPacket struct {
	root     string
	manifest Manifest
}

type GuestFile struct {
	SourcePath string
	GuestPath  string
	File       FileEntry
	Body       []byte
}

type GuestExecutable struct {
	GuestPath    string
	Mode         uint32
	Architecture string
	SHA256       string
	Body         []byte
}

func (packet VerifiedPacket) Manifest() Manifest {
	manifest := packet.manifest
	manifest.Controllers = slices.Clone(manifest.Controllers)
	manifest.Files = slices.Clone(manifest.Files)
	manifest.Routes = slices.Clone(manifest.Routes)
	manifest.SourcePins = slices.Clone(manifest.SourcePins)
	return manifest
}

// Executable supplies the exact binary bytes and fixed destination consumed
// by the shipped systemd units. The driver must install these bytes at this
// path and verify the signed image receipt binds the same hash and size.
func (packet VerifiedPacket) Executable() (GuestExecutable, error) {
	if packet.root == "" {
		return GuestExecutable{}, errors.New("packet was not verified")
	}
	binary := packet.manifest.Binary
	body, err := os.ReadFile(filepath.Join(packet.root, filepath.FromSlash(binary.Path)))
	if err != nil {
		return GuestExecutable{}, err
	}
	digest := sha256.Sum256(body)
	if int64(len(body)) != binary.Size || hex.EncodeToString(digest[:]) != binary.SHA256 {
		return GuestExecutable{}, errors.New("pinned orchestrator executable changed after packet validation")
	}
	return GuestExecutable{GuestPath: binary.GuestPath, Mode: 0o755,
		Architecture: binary.Architecture, SHA256: binary.SHA256, Body: body}, nil
}

// GuestFiles returns only the entries belonging to one exact controller.
// The driver must apply each entry's owner role and mode when installing it.
func (packet VerifiedPacket) GuestFiles(slot string) ([]GuestFile, error) {
	if packet.root == "" {
		return nil, errors.New("packet was not verified")
	}
	var prefix string
	for _, controller := range packet.manifest.Controllers {
		if controller.Slot == slot {
			prefix = controller.GuestRoot + "/"
		}
	}
	if prefix == "" {
		return nil, fmt.Errorf("unknown controller slot %q", slot)
	}
	var files []GuestFile
	for _, entry := range packet.manifest.Files {
		if rest, ok := strings.CutPrefix(entry.Path, prefix); ok {
			source := filepath.Join(packet.root, filepath.FromSlash(entry.Path))
			body, err := os.ReadFile(source)
			if err != nil {
				return nil, fmt.Errorf("read guest material %q: %w", entry.Path, err)
			}
			digest := sha256.Sum256(body)
			if int64(len(body)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
				return nil, fmt.Errorf("guest material changed after packet validation: %q", entry.Path)
			}
			files = append(files, GuestFile{SourcePath: source, GuestPath: "/" + rest, File: entry, Body: body})
		}
	}
	return files, nil
}

// SimulatorRoutes returns the exact response inventory for one instance.
// It rechecks body digests at read time, so later packet mutation cannot
// silently alter a response after manifest validation.
func (packet VerifiedPacket) SimulatorRoutes(slot string) ([]production.ReadResponse, []production.MissingRead, error) {
	if packet.root == "" {
		return nil, nil, errors.New("packet was not verified")
	}
	var instance string
	for _, controller := range packet.manifest.Controllers {
		if controller.Slot == slot {
			instance = controller.InstanceOCID
		}
	}
	if instance == "" {
		return nil, nil, fmt.Errorf("unknown simulator controller slot %q", slot)
	}
	files := make(map[string]FileEntry, len(packet.manifest.Files))
	for _, file := range packet.manifest.Files {
		files[file.Path] = file
	}
	var reads []production.ReadResponse
	var missing []production.MissingRead
	for _, route := range packet.manifest.Routes {
		if route.ControllerSlot != slot {
			continue
		}
		if route.InstanceOCID != instance {
			return nil, nil, errors.New("route instance differs from selected simulator")
		}
		if route.Status == 404 {
			missing = append(missing, production.MissingRead{Host: route.Host, RequestURI: route.RequestURI})
			continue
		}
		entry := files[route.BodyPath]
		body, err := os.ReadFile(filepath.Join(packet.root, filepath.FromSlash(route.BodyPath)))
		if err != nil {
			return nil, nil, fmt.Errorf("read simulator response %q: %w", route.BodyPath, err)
		}
		digest := sha256.Sum256(body)
		if int64(len(body)) != entry.Size || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return nil, nil, fmt.Errorf("simulator response changed after packet validation: %q", route.BodyPath)
		}
		reads = append(reads, production.ReadResponse{Host: route.Host, RequestURI: route.RequestURI,
			Body: body, ContentType: "application/json", ETag: route.ETag, LastModified: route.LastModified})
	}
	return reads, missing, nil
}

// ValidatePacket rejects undeclared files and symlinks as well as digest,
// mode, ownership-role, and route inventory mismatches. It is safe to call
// before the driver copies any packet bytes into a guest image.
func ValidatePacket(root string, roots trust.Keyring, runNow time.Time) (VerifiedPacket, error) {
	if runNow.IsZero() {
		return VerifiedPacket{}, errors.New("packet validation requires a trusted run clock")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return VerifiedPacket{}, errors.New("packet root must be a real directory")
	}
	manifestPath := filepath.Join(root, "manifest.json")
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return VerifiedPacket{}, fmt.Errorf("stat packet manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return VerifiedPacket{}, errors.New("packet manifest must be a bounded regular file")
	}
	wire, err := os.ReadFile(manifestPath)
	if err != nil {
		return VerifiedPacket{}, fmt.Errorf("read packet manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(wire, &manifest, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedPacket{}, fmt.Errorf("decode packet manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return VerifiedPacket{}, err
	}
	if runNow.Before(manifest.FixtureNow.Add(-5*time.Minute)) || runNow.After(manifest.FixtureNow.Add(5*time.Minute)) {
		return VerifiedPacket{}, errors.New("packet fixture clock differs from trusted run clock")
	}
	canonical, err := trust.EncodePayload(manifest)
	if err != nil || !bytes.Equal(canonical, wire) {
		return VerifiedPacket{}, errors.New("packet manifest is not canonical signed JSON")
	}
	sigInfo, err := os.Lstat(filepath.Join(root, "manifest.sig"))
	if err != nil || !sigInfo.Mode().IsRegular() || sigInfo.Size() > trust.MaxEnvelopeBytes {
		return VerifiedPacket{}, errors.New("packet signature must be a bounded regular file")
	}
	signature, err := os.ReadFile(filepath.Join(root, "manifest.sig"))
	if err != nil {
		return VerifiedPacket{}, fmt.Errorf("read packet signature: %w", err)
	}
	envelope, err := trust.DecodeEnvelope(signature)
	if err != nil {
		return VerifiedPacket{}, fmt.Errorf("decode packet signature: %w", err)
	}
	verified, err := trust.VerifyCurrent(envelope, manifest.scope(), roots, runNow,
		trust.Policy{MaxLifetime: 365 * 24 * time.Hour, ClockSkew: time.Minute})
	if err != nil || !bytes.Equal(verified, wire) {
		return VerifiedPacket{}, errors.New("packet manifest root signature is invalid")
	}
	listed := make(map[string]FileEntry, len(manifest.Files))
	for _, entry := range manifest.Files {
		listed[entry.Path] = entry
	}
	seen := make(map[string]bool, len(listed))
	err = filepath.WalkDir(root, func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if item.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("packet contains symlink %q", rel)
		}
		if item.IsDir() {
			return nil
		}
		if rel == "manifest.json" || rel == "manifest.sig" {
			return nil
		}
		entry, ok := listed[rel]
		if !ok || !item.Type().IsRegular() {
			return fmt.Errorf("packet contains unlisted or nonregular file %q", rel)
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if info.Size() != entry.Size || uint32(info.Mode().Perm()) != entry.Mode {
			return fmt.Errorf("packet size or mode mismatch for %q", rel)
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
			return fmt.Errorf("packet digest mismatch for %q", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return VerifiedPacket{}, err
	}
	for _, entry := range manifest.Files {
		if !seen[entry.Path] {
			return VerifiedPacket{}, fmt.Errorf("listed packet file is absent: %q", entry.Path)
		}
	}
	return VerifiedPacket{root: root, manifest: manifest}, nil
}

func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != ManifestVersion || manifest.FixtureNow.IsZero() ||
		manifest.DeploymentID == "" || manifest.Cell != "GRU" || manifest.Environment != "production" ||
		len(manifest.Controllers) != 3 || len(manifest.SourcePins) < len(requiredSourcePaths) || len(manifest.SourcePins) > maxSourcePins ||
		len(manifest.Files) == 0 || len(manifest.Files) > 2048 || len(manifest.Routes) > 512 {
		return errors.New("invalid packet version, clock, or inventory bound")
	}
	controllers := make(map[string]string, len(manifest.Controllers))
	instances := make(map[string]struct{}, len(manifest.Controllers))
	previous := ""
	for index, controller := range manifest.Controllers {
		if controller.Slot != []string{"controller-a", "controller-b", "seed-a"}[index] {
			return fmt.Errorf("packet controller %q is outside the fixed three-slot topology", controller.Slot)
		}
		if controller.Slot <= previous || controller.Slot == "" ||
			!strings.HasPrefix(controller.InstanceOCID, "ocid1.instance.oc1.sa-saopaulo-1.") ||
			strings.ContainsAny(controller.InstanceOCID, " /?&#\r\n") ||
			len(controller.InstanceOCID) <= len("ocid1.instance.oc1.sa-saopaulo-1.") ||
			controller.GuestRoot != "controllers/"+controller.Slot+"/guest-root" {
			return fmt.Errorf("invalid, duplicated, or unsorted controller %q", controller.Slot)
		}
		if _, exists := instances[controller.InstanceOCID]; exists {
			return fmt.Errorf("multiple controllers share OCI instance %q", controller.InstanceOCID)
		}
		instances[controller.InstanceOCID] = struct{}{}
		previous = controller.Slot
		controllers[controller.Slot] = controller.InstanceOCID
	}
	files := make(map[string]FileEntry, len(manifest.Files))
	var totalBytes int64
	previous = ""
	for _, entry := range manifest.Files {
		if !canonicalPath(entry.Path) || entry.Path <= previous {
			return fmt.Errorf("packet file path is invalid, duplicated, or unsorted: %q", entry.Path)
		}
		previous = entry.Path
		role, mode := expectedOwnership(entry.Path, controllers)
		maxSize := int64(4 << 20)
		if entry.Path == "input/orchestrator" {
			maxSize = 512 << 20
		}
		if entry.Size < 0 || entry.Size > maxSize || !validDigest(entry.SHA256) ||
			entry.Mode != mode || entry.OwnerRole != role || role == "" {
			return fmt.Errorf("packet file has invalid metadata: %q", entry.Path)
		}
		totalBytes += entry.Size
		if totalBytes > maxPacketBytes {
			return errors.New("packet aggregate file bytes exceed bound")
		}
		files[entry.Path] = entry
	}
	if binaryFile, ok := files[manifest.Binary.Path]; !ok || manifest.Binary.Path != "input/orchestrator" ||
		manifest.Binary.GuestPath != "/usr/local/bin/terrascale-orchestrator" ||
		binaryFile.SHA256 != manifest.Binary.SHA256 || binaryFile.Size != manifest.Binary.Size ||
		!slices.Contains([]string{"amd64", "arm64"}, manifest.Binary.Architecture) {
		return errors.New("packet binary input does not match listed exact executable")
	}
	if _, ok := files[guestDirectoryPlanPath]; !ok {
		return errors.New("packet lacks signed guest directory plan")
	}
	for _, required := range []string{"simulator/tls/oci.crt", "simulator/tls/oci.key"} {
		if _, ok := files[required]; !ok {
			return fmt.Errorf("packet lacks signed simulator HTTPS material %q", required)
		}
	}
	for _, controller := range manifest.Controllers {
		for _, name := range []string{"tenancy.txt", "leaf.pem", "leaf.key", "intermediate.pem"} {
			if _, ok := files["simulator/imds/"+controller.Slot+"/"+name]; !ok {
				return fmt.Errorf("controller %q lacks signed IMDS %s", controller.Slot, name)
			}
		}
		prefix := controller.GuestRoot + "/etc/terrascale-orchestrator/bootstrap/"
		for _, required := range []string{"identity.json", "anchor.json", "trust-roots/001.pem"} {
			if _, ok := files[prefix+required]; !ok {
				return fmt.Errorf("controller %q lacks baked %s", controller.Slot, required)
			}
		}
		for _, required := range []string{
			"etc/terrascale-orchestrator/controller.json",
			"usr/local/share/ca-certificates/ts-fixture-oci.crt",
			"etc/systemd/network/20-terrascale-production.network",
			"etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf",
			"etc/hosts",
			"etc/cloud/cloud-init.disabled",
			"etc/ssh/sshd_config.d/99-terrascale-production.conf",
		} {
			if _, ok := files[controller.GuestRoot+"/"+required]; !ok {
				return fmt.Errorf("controller %q lacks production guest file %s", controller.Slot, required)
			}
		}
		for _, required := range []string{
			"var/lib/terrascale-orchestrator-bootstrap/accepted-install.json",
		} {
			if _, ok := files[controller.GuestRoot+"/"+required]; !ok {
				return fmt.Errorf("controller %q lacks restart marker %s", controller.Slot, required)
			}
		}
		credentialPrefix := controller.GuestRoot + "/var/lib/terrascale-orchestrator-secrets/"
		if _, ok := files[credentialPrefix+"operator.jwt"]; !ok {
			return fmt.Errorf("controller %q lacks signed operator credential", controller.Slot)
		}
	}
	seedRoot := "controllers/seed-a/guest-root/var/lib/terrascale-orchestrator-controller/"
	for _, required := range []string{"founder-selection-floor.json", ".founder-selection-floor.lock"} {
		if _, ok := files[seedRoot+required]; !ok {
			return fmt.Errorf("seed lacks durable founder floor %s", required)
		}
	}
	previous = ""
	for _, pin := range manifest.SourcePins {
		if !canonicalPath(pin.Path) || pin.Path <= previous || !validDigest(pin.SHA256) {
			return fmt.Errorf("packet source pin is invalid, duplicated, or unsorted: %q", pin.Path)
		}
		previous = pin.Path
	}
	for _, required := range requiredSourcePaths {
		if !slices.ContainsFunc(manifest.SourcePins, func(pin SourcePin) bool { return pin.Path == required }) {
			return fmt.Errorf("packet source pins omit required code %q", required)
		}
	}
	previous = ""
	routeBytes := make(map[string]int64, len(manifest.Controllers))
	for _, route := range manifest.Routes {
		key := route.ControllerSlot + "\n" + route.InstanceOCID + "\n" + route.Host + "\n" + route.RequestURI
		if key <= previous || controllers[route.ControllerSlot] != route.InstanceOCID || !validRoute(route, files) {
			return fmt.Errorf("packet route is invalid, duplicated, or unsorted: %q", key)
		}
		if route.Status == 200 {
			routeBytes[route.ControllerSlot] += files[route.BodyPath].Size
			if routeBytes[route.ControllerSlot] > maxRouteBodies {
				return fmt.Errorf("simulator response bytes exceed controller %q bound", route.ControllerSlot)
			}
		}
		previous = key
	}
	return nil
}

func canonicalPath(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.ContainsRune(name, '\x00') &&
		!strings.HasPrefix(name, "/") && path.Clean(name) == name &&
		!slices.Contains(strings.Split(name, "/"), "..") && name != "manifest.json" && name != "manifest.sig"
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func expectedOwnership(name string, controllers map[string]string) (string, uint32) {
	for slot := range controllers {
		guest := "controllers/" + slot + "/guest-root/"
		if !strings.HasPrefix(name, guest) {
			continue
		}
		name = strings.TrimPrefix(name, guest)
		switch {
		case name == "etc/terrascale-orchestrator/controller.json":
			return "root:" + slot, 0o644
		case name == "etc/systemd/network/20-terrascale-production.network" ||
			name == "etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf" ||
			name == "etc/hosts" || name == "etc/cloud/cloud-init.disabled" ||
			name == "etc/ssh/sshd_config.d/99-terrascale-production.conf":
			return "root:" + slot, 0o644
		case name == "etc/terrascale-orchestrator/bootstrap/identity.json" ||
			name == "etc/terrascale-orchestrator/bootstrap/anchor.json" ||
			name == "etc/terrascale-orchestrator/bootstrap/trust-roots/001.pem":
			return "root:" + slot, 0o444
		case name == "usr/local/share/ca-certificates/ts-fixture-oci.crt":
			return "root:" + slot, 0o644
		case strings.HasPrefix(name, "var/lib/terrascale-orchestrator-bootstrap/"):
			return "root:" + slot, 0o644
		case strings.HasPrefix(name, "var/lib/terrascale-orchestrator-secrets/"):
			return "service:" + slot, 0o600
		case strings.HasPrefix(name, "var/lib/terrascale-orchestrator-controller/"):
			return "service:" + slot, 0o600
		}
		return "", 0
	}
	switch {
	case strings.HasPrefix(name, "simulator/"):
		return "simulator-host", 0o600
	case strings.HasPrefix(name, "signing/"):
		return "signing-host", 0o600
	case name == "input/orchestrator":
		return "binary-host", 0o600
	default:
		return "", 0
	}
}

func (manifest Manifest) scope() trust.Scope {
	return trust.Scope{Domain: "terrascale.production-fixture.packet", DeploymentID: manifest.DeploymentID,
		Cell: manifest.Cell, Environment: manifest.Environment, Role: "fixture", Slot: "packet"}
}

func validRoute(route Route, files map[string]FileEntry) bool {
	if !slices.Contains([]string{"iaas.sa-saopaulo-1.oraclecloud.com", "objectstorage.sa-saopaulo-1.oraclecloud.com"}, route.Host) ||
		!strings.HasPrefix(route.RequestURI, "/") || strings.ContainsAny(route.RequestURI, "#\r\n") ||
		len(route.RequestURI) > 4096 {
		return false
	}
	uri, err := url.ParseRequestURI(route.RequestURI)
	if err != nil || uri.IsAbs() || uri.Path == "" || strings.Contains(uri.Path, "..") ||
		strings.Contains(uri.Path, "//") || uri.RequestURI() != route.RequestURI {
		return false
	}
	if route.Host == "iaas.sa-saopaulo-1.oraclecloud.com" {
		switch {
		case uri.Path == "/20160918/instances/"+route.InstanceOCID:
			if uri.RawQuery != "" {
				return false
			}
		case uri.Path == "/20160918/vnicAttachments":
			query := uri.Query()
			if query.Get("instanceId") != route.InstanceOCID ||
				!strings.HasPrefix(query.Get("compartmentId"), "ocid1.compartment.") ||
				query.Get("limit") != "50" || len(query) < 3 || len(query) > 4 {
				return false
			}
			for key, values := range query {
				if !slices.Contains([]string{"compartmentId", "instanceId", "limit", "page"}, key) || len(values) != 1 {
					return false
				}
			}
		case strings.HasPrefix(uri.Path, "/20160918/vnics/ocid1.vnic."):
			if uri.RawQuery != "" || strings.Contains(strings.TrimPrefix(uri.Path, "/20160918/vnics/"), "/") {
				return false
			}
		case strings.HasPrefix(uri.Path, "/20160918/subnets/ocid1.subnet.oc1.sa-saopaulo-1."):
			if uri.RawQuery != "" || strings.Contains(strings.TrimPrefix(uri.Path, "/20160918/subnets/"), "/") {
				return false
			}
		default:
			return false
		}
	} else {
		parts := strings.SplitN(strings.TrimPrefix(uri.Path, "/"), "/", 6)
		if uri.RawQuery != "" || len(parts) != 6 || parts[0] != "n" || parts[1] == "" ||
			parts[2] != "b" || parts[3] == "" || parts[4] != "o" || parts[5] == "" {
			return false
		}
	}
	if route.Status == 404 {
		return route.Host == "objectstorage.sa-saopaulo-1.oraclecloud.com" &&
			route.BodyPath == "" && route.ETag == "" && route.LastModified.IsZero()
	}
	if route.Status != 200 || route.ETag == "" || route.LastModified.IsZero() ||
		!strings.HasPrefix(route.BodyPath, "simulator/responses/") {
		return false
	}
	_, ok := files[route.BodyPath]
	return ok && files[route.BodyPath].Size > 0
}
