// Package client installs the checksum-pinned NetBird client without executing archives.
package client

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
)

const MaxBinaryBytes = 128 << 20

var SHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Archive struct {
	URL          string `json:"url"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	BinarySHA256 string `json:"binary_sha256"`
}
type FilePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Pin struct {
	Version  string `json:"version"`
	Archives struct {
		Arm64 Archive `json:"arm64"`
		AMD64 Archive `json:"amd64"`
	} `json:"archives"`
	EnrollmentConfig FilePin `json:"enrollment_config"`
}

func (p Pin) Archive(architecture string) (Archive, error) {
	switch architecture {
	case "arm64":
		return p.Archives.Arm64, nil
	case "amd64":
		return p.Archives.AMD64, nil
	}
	return Archive{}, errors.New("unsupported architecture")
}
func SHA256(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func ValidatePin(p Pin) error {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(p.Version) {
		return errors.New("NetBird pin needs version, archives and enrollment_config")
	}
	for _, arch := range []string{"arm64", "amd64"} {
		a, _ := p.Archive(arch)
		expected := fmt.Sprintf("https://github.com/netbirdio/netbird/releases/download/v%s/netbird_%s_linux_%s.tar.gz", p.Version, p.Version, arch)
		if a.URL != expected {
			return fmt.Errorf("invalid NetBird %s archive source", arch)
		}
		if a.Bytes <= 0 || a.Bytes > MaxBinaryBytes {
			return fmt.Errorf("invalid NetBird %s archive size", arch)
		}
		if !SHA256Pattern.MatchString(a.SHA256) || !SHA256Pattern.MatchString(a.BinarySHA256) {
			return fmt.Errorf("invalid NetBird %s SHA-256", arch)
		}
	}
	return nil
}

type Config struct {
	ManagementURL    string            `json:"management_url"`
	ManagementIP     string            `json:"management_ip,omitempty"`
	Region           string            `json:"region"`
	SetupKeySecretID string            `json:"setup_key_secret_id"`
	PeerNames        map[string]string `json:"peer_names,omitempty"`
	AdminPATSecretID string            `json:"admin_pat_secret_id,omitempty"`
}

func ValidateConfig(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return c, e
	}
	if len(b) > 16384 {
		return c, errors.New("NetBird enrollment configuration is too large")
	}
	var fields map[string]any
	if e = json.Unmarshal(b, &fields); e != nil {
		return c, e
	}
	// RejectUnknownMembers below bounds the field set; only required fields
	// are checked here.
	if fields["management_url"] == nil || fields["region"] == nil || fields["setup_key_secret_id"] == nil {
		return c, errors.New("NetBird enrollment configuration has unexpected or missing fields")
	}
	if e = json.Unmarshal(b, &c, json.RejectUnknownMembers(true)); e != nil {
		return c, errors.New("NetBird enrollment configuration has unexpected or missing fields")
	}
	u, e := url.Parse(c.ManagementURL)
	if e != nil || u.Scheme != "https" || u.User != nil || (u.Host != "netbird.terrascale.tech" && u.Host != "netbird.terrascale.tech:443") || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.Opaque != "" || strings.ContainsAny(c.ManagementURL, "?#") {
		return c, errors.New("NetBird management_url must be https://netbird.terrascale.tech")
	}
	if !regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]*$`).MatchString(c.Region) {
		return c, errors.New("NetBird region must be an OCI region name")
	}
	if !netbird.ValidSecretID(c.Region, c.SetupKeySecretID) {
		return c, errors.New("NetBird setup_key_secret_id must identify an OCI Vault secret in the configured region")
	}
	// An empty or null admin_pat_secret_id means absent, as in the
	// controller's netbird.Config.
	if c.AdminPATSecretID != "" && !netbird.ValidSecretID(c.Region, c.AdminPATSecretID) {
		return c, errors.New("NetBird admin_pat_secret_id must identify an OCI Vault secret in the configured region")
	}
	if _, ok := fields["management_ip"]; ok {
		ip, e := netip.ParseAddr(c.ManagementIP)
		if e != nil || !ip.IsPrivate() || ip.Is4In6() || ip.Zone() != "" {
			return c, errors.New("NetBird management_ip must be a private IPv4 or IPv6 address")
		}
	}
	if e = netbird.ValidatePeerNames(c.PeerNames); e != nil {
		return c, e
	}
	return c, nil
}
func VerifyBinary(path, expected, architecture string) error {
	if !SHA256Pattern.MatchString(expected) {
		return errors.New("NetBird binary SHA-256 must be 64 lowercase hex characters")
	}
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() || s.Size() < 64 || s.Size() > MaxBinaryBytes {
		return errors.New("NetBird binary must be a regular executable between 64 bytes and 128 MiB")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	var header [64]byte
	if _, e = io.ReadFull(f, header[:]); e != nil {
		return e
	}
	machine := uint16(183)
	if architecture == "amd64" {
		machine = 62
	} else if architecture != "arm64" {
		return errors.New("unsupported architecture")
	}
	if string(header[:7]) != "\x7fELF\x02\x01\x01" || (binary.LittleEndian.Uint16(header[16:]) != 2 && binary.LittleEndian.Uint16(header[16:]) != 3) || binary.LittleEndian.Uint16(header[18:]) != machine || binary.LittleEndian.Uint32(header[20:]) != 1 || binary.LittleEndian.Uint16(header[52:]) != 64 {
		return fmt.Errorf("NetBird binary must be an ELF64 little-endian %s executable", architecture)
	}
	digest, e := SHA256(path)
	if e != nil {
		return e
	}
	if digest != expected {
		return errors.New("NetBird binary bytes differ from the pinned SHA-256")
	}
	return nil
}
func ArchiveMatches(path string, p Archive) bool {
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() || s.Size() != p.Bytes {
		return false
	}
	digest, e := SHA256(path)
	return e == nil && digest == p.SHA256
}
func Download(ctx context.Context, p Archive, path string, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if e != nil {
		return e
	}
	request.Header.Set("User-Agent", "TerraScale-image-builder")
	response, e := client.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("NetBird download HTTP status %d", response.StatusCode)
	}
	out, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(out, io.LimitReader(response.Body, p.Bytes+1))
	e = errors.Join(e, out.Close())
	if e != nil {
		return e
	}
	if n > p.Bytes {
		return errors.New("NetBird archive exceeds its pinned size")
	}
	if !ArchiveMatches(path, p) {
		return errors.New("NetBird archive bytes differ from the pinned SHA-256 or size")
	}
	return nil
}
func Extract(archive, destination string, p Archive, architecture string) error {
	file, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer file.Close()
	gz, e := gzip.NewReader(file)
	if e != nil {
		return e
	}
	defer gz.Close()
	source := tar.NewReader(gz)
	var contents []byte
	count := 0
	for {
		h, e := source.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		if h.Name != "netbird" {
			continue
		}
		count++
		if count != 1 || !h.FileInfo().Mode().IsRegular() || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA || h.Size < 64 || h.Size > MaxBinaryBytes {
			return errors.New("NetBird archive must contain one regular root-level netbird executable")
		}
		contents, e = io.ReadAll(io.LimitReader(source, MaxBinaryBytes+1))
		if e != nil {
			return e
		}
		if int64(len(contents)) != h.Size {
			return errors.New("NetBird archive truncated binary")
		}
	}
	if count != 1 {
		return errors.New("NetBird archive must contain one regular root-level netbird executable")
	}
	out, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = out.Write(contents)
	e = errors.Join(e, out.Close())
	if e != nil {
		return e
	}
	if e = VerifyBinary(destination, p.BinarySHA256, architecture); e != nil {
		return e
	}
	return os.Chmod(destination, 0755)
}
func Fetch(ctx context.Context, p Pin, architecture, output, cache string, client *http.Client) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e := ValidatePin(p); e != nil {
		return e
	}
	a, e := p.Archive(architecture)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(output), 0755); e != nil {
		return e
	}
	work, e := os.MkdirTemp(filepath.Dir(output), ".netbird-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	archive := filepath.Join(work, "netbird.tar.gz")
	cached := ""
	if cache != "" {
		cached = filepath.Join(cache, a.SHA256)
	}
	if cached != "" && ArchiveMatches(cached, a) {
		if e = copyFile(cached, archive, 0600); e != nil {
			return e
		}
	} else {
		if e = Download(ctx, a, archive, client); e != nil {
			return e
		}
		if cached != "" {
			if e = os.MkdirAll(cache, 0755); e != nil {
				return e
			}
			f, e := os.CreateTemp(cache, ".netbird-cache-")
			if e != nil {
				return e
			}
			tmp := f.Name()
			f.Close()
			defer os.Remove(tmp)
			if e = copyFile(archive, tmp, 0600); e != nil {
				return e
			}
			if e = os.Rename(tmp, cached); e != nil {
				return e
			}
		}
	}
	if !ArchiveMatches(archive, a) {
		return errors.New("NetBird archive bytes differ from the pinned SHA-256 or size")
	}
	binary := filepath.Join(work, "netbird")
	if e = Extract(archive, binary, a, architecture); e != nil {
		return e
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(binary, output)
}
func copyFile(source, destination string, mode os.FileMode) error {
	f, e := os.Open(source)
	if e != nil {
		return e
	}
	defer f.Close()
	out, e := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, f)
	return errors.Join(e, out.Close(), os.Chmod(destination, mode))
}
func orderedKeys(raw []byte) ([]string, error) {
	decoder := jsontext.NewDecoder(strings.NewReader(string(raw)))
	first, err := decoder.ReadToken()
	if err != nil || first.Kind() != '{' {
		return nil, errors.New("expected JSON object")
	}
	keys := []string{}
	for decoder.PeekKind() != '}' {
		key, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		keys = append(keys, key.String())
		if _, err = decoder.ReadValue(); err != nil {
			return nil, err
		}
	}
	_, err = decoder.ReadToken()
	return keys, err
}
func ValidatePinJSON(raw []byte) (Pin, error) {
	var pin Pin
	keys, err := orderedKeys(raw)
	if err != nil {
		return pin, err
	}
	if !slices.Equal(keys, []string{"version", "archives", "enrollment_config"}) {
		return pin, errors.New("NetBird pin needs version, archives and enrollment_config")
	}
	if err = json.Unmarshal(raw, &pin, json.RejectUnknownMembers(true)); err != nil {
		return pin, err
	}
	var fields map[string]jsontext.Value
	if err = json.Unmarshal(raw, &fields); err != nil {
		return pin, err
	}
	keys, err = orderedKeys(fields["archives"])
	if err != nil {
		return pin, err
	}
	if !slices.Equal(keys, []string{"arm64", "amd64"}) {
		return pin, errors.New("NetBird archives must pin arm64 and amd64")
	}
	var archives map[string]jsontext.Value
	if err = json.Unmarshal(fields["archives"], &archives); err != nil {
		return pin, err
	}
	for _, arch := range []string{"arm64", "amd64"} {
		keys, err = orderedKeys(archives[arch])
		if err != nil {
			return pin, err
		}
		if !slices.Equal(keys, []string{"url", "bytes", "sha256", "binary_sha256"}) {
			return pin, fmt.Errorf("invalid NetBird %s archive source", arch)
		}
	}
	return pin, ValidatePin(pin)
}
func LoadPin(path string) (Pin, error) {
	var inputs map[string]jsontext.Value
	b, err := os.ReadFile(path)
	if err != nil {
		return Pin{}, err
	}
	if err = json.Unmarshal(b, &inputs); err != nil {
		return Pin{}, err
	}
	raw, ok := inputs["netbird"]
	if !ok {
		return Pin{}, errors.New("missing NetBird input pin")
	}
	return ValidatePinJSON(raw)
}

func directDirectory(root, path string, mode os.FileMode, enforce bool) (string, error) {
	destination := root
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		destination = filepath.Join(destination, part)
		s, e := os.Lstat(destination)
		if e == nil && !s.IsDir() {
			return "", fmt.Errorf("installation parent must be a direct directory: %s", destination)
		}
		if e != nil && !os.IsNotExist(e) {
			return "", e
		}
		if os.IsNotExist(e) {
			m := os.FileMode(0755)
			if i == len(parts)-1 {
				m = mode
			}
			if e = os.Mkdir(destination, m); e != nil {
				return "", e
			}
		}
	}
	if enforce {
		if e := os.Chmod(destination, mode); e != nil {
			return "", e
		}
	}
	return destination, nil
}
func installFile(source, destination string, mode os.FileMode) error {
	s, e := os.Lstat(destination)
	if e == nil && !s.Mode().IsRegular() {
		return fmt.Errorf("installation destination must be a direct file: %s", destination)
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	out, e := os.CreateTemp(filepath.Dir(destination), ".netbird-install-")
	if e != nil {
		return e
	}
	tmp := out.Name()
	out.Close()
	defer os.Remove(tmp)
	if e = copyFile(source, tmp, mode); e != nil {
		return e
	}
	return os.Rename(tmp, destination)
}

type InstallOptions struct{ Config, EnrollBinary, EnrollSHA256, ClientBinary, Architecture, Inputs, Cache, Root string }

func Install(ctx context.Context, repo string, o InstallOptions, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.Architecture == "" {
		return errors.New("unsupported host architecture")
	}
	root, e := filepath.EvalSymlinks(o.Root)
	if e != nil {
		return e
	}
	root, e = filepath.Abs(root)
	if e != nil {
		return e
	}
	live := root == "/"
	if live && os.Geteuid() != 0 {
		return errors.New("live NetBird installation must run as root")
	}
	if _, e = ValidateConfig(o.Config); e != nil {
		return e
	}
	pin, e := LoadPin(o.Inputs)
	if e != nil {
		return e
	}
	if e = VerifyBinary(o.EnrollBinary, o.EnrollSHA256, o.Architecture); e != nil {
		return e
	}
	work, e := os.MkdirTemp("", "ts-netbird-install-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	binary := o.ClientBinary
	if binary == "" {
		binary = filepath.Join(work, "netbird")
		if e = Fetch(ctx, pin, o.Architecture, binary, o.Cache, nil); e != nil {
			return e
		}
	}
	a, e := pin.Archive(o.Architecture)
	if e != nil {
		return e
	}
	if e = VerifyBinary(binary, a.BinarySHA256, o.Architecture); e != nil {
		return e
	}
	systemctl := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "systemctl", args...)
		b, e := cmd.CombinedOutput()
		if e != nil {
			return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(b)))
		}
		return nil
	}
	active := false
	if live {
		active = systemctl("is-active", "--quiet", "netbird.service") == nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, path := range []string{"/usr/local/bin", "/usr/local/lib/terrascale-orchestrator", "/etc/terrascale-orchestrator", "/etc/systemd/system"} {
		if _, e = directDirectory(root, path, 0755, false); e != nil {
			return e
		}
	}
	if _, e = directDirectory(root, "/var/lib/netbird", 0700, true); e != nil {
		return e
	}
	for _, f := range []struct {
		src, dst string
		mode     os.FileMode
	}{{binary, "usr/local/bin/netbird", 0755}, {o.EnrollBinary, "usr/local/lib/terrascale-orchestrator/netbird-enroll", 0755}, {o.Config, "etc/terrascale-orchestrator/netbird.json", 0644}, {filepath.Join(repo, "deploy/systemd/netbird.service"), "etc/systemd/system/netbird.service", 0644}, {filepath.Join(repo, "deploy/systemd/terrascale-netbird-enroll.service"), "etc/systemd/system/terrascale-netbird-enroll.service", 0644}} {
		if e = installFile(f.src, filepath.Join(root, f.dst), f.mode); e != nil {
			return e
		}
	}
	dropin, e := directDirectory(root, "/etc/systemd/system/terrascale-netbird-enroll.service.d", 0755, false)
	if e != nil {
		return e
	}
	override := filepath.Join(work, "command.conf")
	if e = os.WriteFile(override, []byte("[Service]\nExecStart=\nExecStart=/usr/local/lib/terrascale-orchestrator/netbird-enroll netbird-enroll --config /etc/terrascale-orchestrator/netbird.json\n"), 0644); e != nil {
		return e
	}
	if e = installFile(override, filepath.Join(dropin, "command.conf"), 0644); e != nil {
		return e
	}
	units := []string{"netbird.service", "terrascale-netbird-enroll.service"}
	if live {
		if e = systemctl("daemon-reload"); e != nil {
			return e
		}
		if e = systemctl(append([]string{"enable"}, units...)...); e != nil {
			return e
		}
		action := "start"
		if active {
			action = "restart"
		}
		if e = systemctl(action, units[0]); e != nil {
			return e
		}
		if e = systemctl("--no-block", "restart", units[1]); e != nil {
			return e
		}
	} else {
		wants, e := directDirectory(root, "/etc/systemd/system/multi-user.target.wants", 0755, false)
		if e != nil {
			return e
		}
		for _, name := range units {
			link := filepath.Join(wants, name)
			target := "../" + name
			if existing, e := os.Readlink(link); e == nil && existing == target {
				continue
			}
			if _, e = os.Lstat(link); e == nil {
				return fmt.Errorf("service enablement destination already exists: %s", link)
			} else if !os.IsNotExist(e) {
				return e
			}
			if e = os.Symlink(target, link); e != nil {
				return e
			}
		}
	}
	status := "enabled in offline root"
	if live {
		status = "started"
	}
	_, e = fmt.Fprintf(out, "NetBird %s installed; enrollment %s\n", pin.Version, status)
	return e
}
func Run(ctx context.Context, root string, args []string, stdout, stderr io.Writer) (code int) {
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	output := commandio.NewWriter(stdout)
	stdout = output
	defer func() {
		if err := errors.Join(ctx.Err(), output.Err()); err != nil {
			fmt.Fprintln(stderr, err)
			code = 1
		}
	}()
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "usage: ts-orch netbird client fetch|verify-binary|check-config; ts-orch netbird install [flags]; ts-orch netbird sync|prune-peers|inventory [flags]")
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: ts-orch netbird client|install|sync|prune-peers|inventory")
		return 2
	}
	name := args[0]
	args = args[1:]
	fs := flag.NewFlagSet("netbird-"+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	inputs := fs.String("inputs", filepath.Join(root, "deploy/image/image-inputs.json"), "pinned inputs")
	arch := fs.String("architecture", runtime.GOARCH, "architecture")
	cache := fs.String("cache", os.Getenv("TS_NETBIRD_CLIENT_CACHE"), "verified archive cache")
	var e error
	switch name {
	case "install":
		config := fs.String("config", "", "public config")
		enroll := fs.String("enroll-binary", "", "enrollment executable")
		sha := fs.String("enroll-sha256", "", "enrollment digest")
		binary := fs.String("client-binary", "", "pinned client")
		stage := fs.String("root", "/", "offline root")
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if *config == "" || *enroll == "" || *sha == "" || fs.NArg() != 0 {
			return 2
		}
		e = Install(ctx, root, InstallOptions{*config, *enroll, *sha, *binary, *arch, *inputs, *cache, *stage}, stdout)
	case "client": // Global inputs flags may precede the client command.
		command := ""
		for i, a := range args {
			if a == "fetch" || a == "verify-binary" || a == "check-config" {
				command = a
				args = append(append([]string{}, args[:i]...), args[i+1:]...)
				break
			}
		}
		output := fs.String("out", "", "output")
		binary := fs.String("binary", "", "binary")
		expected := fs.String("sha256", "", "digest")
		config := fs.String("config", "", "config")
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if fs.NArg() != 0 {
			return 2
		}
		switch command {
		case "fetch":
			if *output == "" {
				return 2
			}
			var p Pin
			p, e = LoadPin(*inputs)
			if e == nil {
				e = Fetch(ctx, p, *arch, *output, *cache, nil)
			}
			if e == nil {
				digest, _ := SHA256(*output)
				_, e = fmt.Fprintf(stdout, "NetBird client version=%s architecture=%s sha256=%s\n", p.Version, *arch, digest)
			}
		case "verify-binary":
			e = VerifyBinary(*binary, *expected, *arch)
		case "check-config":
			_, e = ValidateConfig(*config)
		default:
			fmt.Fprintln(stderr, "usage: ts-orch netbird client fetch|verify-binary|check-config")
			return 2
		}
	default:
		return 2
	}
	if e != nil {
		fmt.Fprintf(stderr, "netbird-%s: %v\n", name, e)
		return 1
	}
	return 0
}
