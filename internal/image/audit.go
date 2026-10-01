package image

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

func requireDirectParents(g *Guest, p string) error {
	for _, parent := range []string{"/", "/usr", "/usr/local", "/usr/local/lib", AppLib} {
		kind, e := g.Kind(parent)
		if e != nil {
			return e
		}
		if kind == "" && parent == AppLib {
			continue
		}
		if kind != "dir" {
			if kind == "" {
				kind = "absent"
			}
			return fmt.Errorf("native verifier parent must be a root-owned nonwritable directory: %s (kind=%s)", parent, kind)
		}
		meta, e := g.Metadata(parent)
		if e != nil {
			return e
		}
		if meta["st_uid"] != 0 || meta["st_mode"]&022 != 0 {
			return fmt.Errorf("native verifier parent must be a root-owned nonwritable directory: %s (uid=%d gid=%d mode=0%o)", parent, meta["st_uid"], meta["st_gid"], meta["st_mode"]&07777)
		}
	}
	return g.AssertAbsent(p, "managed-material verifier directory")
}
func auditKernel(g *Guest, release, work, output string, out io.Writer) error {
	names, e := g.List("/boot")
	if e != nil {
		return e
	}
	var kernels []string
	for _, name := range names {
		if strings.HasPrefix(name, "vmlinuz-") {
			kernels = append(kernels, name)
		}
	}
	kernelPath := "/boot/vmlinuz-" + release
	kind, e := g.Kind(kernelPath)
	if e != nil {
		return e
	}
	if !slices.Equal(kernels, []string{"vmlinuz-" + release}) || kind != "file" {
		return fmt.Errorf("base image must contain exactly one regular /boot/vmlinuz-%s (found %v)", release, kernels)
	}
	kind, e = g.Kind("/lib/modules/" + release)
	if e != nil {
		return e
	}
	if kind != "dir" {
		return fmt.Errorf("selected guest kernel has no /lib/modules/%s directory", release)
	}
	kernel := filepath.Join(work, "guest-kernel-base")
	data, e := g.Read(kernelPath, kernel)
	if e != nil {
		return e
	}
	size := len(data)
	if size == 0 || size > 128<<20 {
		return errors.New("base guest kernel must be between 1 byte and 128 MiB")
	}
	header := data
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		gzipReader, e := gzip.NewReader(bytes.NewReader(data))
		if e != nil {
			return e
		}
		defer gzipReader.Close()
		header = make([]byte, 64)
		if _, e = io.ReadFull(gzipReader, header); e != nil {
			return errors.New("base guest kernel is not an AArch64 Linux boot Image")
		}
	}
	if len(header) < 64 || string(header[56:60]) != "ARM\x64" {
		return errors.New("base guest kernel is not an AArch64 Linux boot Image")
	}
	if e = copyFile(kernel, output, 0644); e != nil {
		return e
	}
	digest, e := fileHash(output)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(out, "base guest kernel release=%s bytes=%d sha256=%s\n", release, size, digest)
	return e
}
func packages(data []byte) []map[string]string {
	var result []map[string]string
	for block := range strings.SplitSeq(string(data), "\n\n") {
		p := map[string]string{}
		for line := range strings.SplitSeq(block, "\n") {
			if key, value, ok := strings.Cut(line, ": "); ok {
				p[key] = value
			}
		}
		result = append(result, p)
	}
	return result
}
func auditSystemd(g *Guest, work string, out io.Writer) error {
	status, e := g.Read("/var/lib/dpkg/status", filepath.Join(work, "base-dpkg-status"))
	if e != nil {
		return e
	}
	var versions []string
	for _, p := range packages(status) {
		if p["Package"] == "systemd" {
			versions = append(versions, p["Version"])
		}
	}
	if len(versions) != 1 || !strings.HasPrefix(versions[0], "255.") {
		return errors.New("base image must contain the audited Noble systemd 255 package")
	}
	host, e := g.exec(g.ctx, "", g.Env, "systemctl", "--version")
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(out, "offline unit enablement: guest systemd=%s host tool=%s\n", versions[0], strings.Split(host, "\n")[0])
	return e
}
func auditSSHServer(g *Guest, work string, out io.Writer) error {
	status, err := g.Read("/var/lib/dpkg/status", filepath.Join(work, "ssh-dpkg-status"))
	if err != nil {
		return err
	}
	installed := false
	for _, p := range packages(status) {
		installed = installed || p["Package"] == "openssh-server" && p["Status"] == "install ok installed"
	}
	if !installed {
		return errors.New("base image must contain the installed openssh-server package")
	}
	if err := g.AssertAbsent("/etc/ssh/sshd_not_to_be_run", "OpenSSH disable marker"); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "offline OpenSSH server verified package=openssh-server unit=%s\n", SSHUnit)
	return err
}

func auditVolumeTools(g *Guest, work string, out io.Writer) error {
	status, e := g.Read("/var/lib/dpkg/status", filepath.Join(work, "volume-tools-dpkg-status"))
	if e != nil {
		return e
	}
	for name, version := range map[string]string{"e2fsprogs": "1.47.0-2.4~exp1ubuntu4.1", "util-linux": "2.39.3-9ubuntu6.6"} {
		var installed []map[string]string
		for _, p := range packages(status) {
			if p["Package"] == name && p["Status"] == "install ok installed" {
				installed = append(installed, p)
			}
		}
		if len(installed) != 1 || installed[0]["Version"] != version {
			observed := []string{}
			for _, p := range installed {
				observed = append(observed, p["Version"])
			}
			if len(observed) == 0 {
				observed = []string{"absent"}
			}
			return fmt.Errorf("host base image must contain pinned %s %s (observed %s)", name, version, strings.Join(observed, ", "))
		}
	}
	for _, p := range VolumeTools {
		current := p
		visited := map[string]bool{}
		resolved := false
		for range 40 {
			if visited[current] {
				return fmt.Errorf("host base image volume tool has a symlink loop: %s", p)
			}
			visited[current] = true
			kind, e := g.Kind(current)
			if e != nil {
				return e
			}
			if kind == "file" {
				meta, e := g.Metadata(current)
				if e != nil {
					return e
				}
				if meta["st_mode"]&0111 == 0 {
					return fmt.Errorf("host base image volume tool is not executable: %s", p)
				}
				resolved = true
				break
			}
			if kind != "symlink" {
				return fmt.Errorf("host base image is missing required volume tool: %s", p)
			}
			target, e := g.Call("readlink", current)
			if e != nil {
				return e
			}
			if target == "" || strings.ContainsRune(target, 0) {
				return fmt.Errorf("host base image volume tool has an invalid symlink: %s", p)
			}
			if !strings.HasPrefix(target, "/") {
				target = path.Join(path.Dir(current), target)
			}
			current = path.Clean(target)
			if !strings.HasPrefix(current, "/") || current == "/" || strings.HasPrefix(current, "/../") {
				return fmt.Errorf("host base image volume tool escapes its root: %s", p)
			}
		}
		if !resolved {
			return fmt.Errorf("host base image volume tool has too many symlinks: %s", p)
		}
	}
	_, e = fmt.Fprintf(out, "offline host volume tools verified packages=e2fsprogs,util-linux tools=%s\n", strings.Join(VolumeTools, ","))
	return e
}
func activeTimeSetting(data []byte) (bool, error) {
	if !utf8.Valid(data) {
		return false, errors.New("could not inspect systemd timesyncd config: invalid UTF-8")
	}
	section := ""
	pattern := regexp.MustCompile(`^(NTP|FallbackNTP|PollIntervalMinSec|PollIntervalMaxSec)\s*=`)
	for raw := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section, _, _ = strings.Cut(strings.TrimPrefix(line, "["), "]")
			section = strings.TrimSpace(section)
		} else if section == "Time" && pattern.MatchString(line) {
			return true, nil
		}
	}
	return false, nil
}
func auditTimeConfig(g *Guest, work string) error {
	main := "/etc/systemd/timesyncd.conf"
	kind, e := g.Kind(main)
	if e != nil {
		return e
	}
	if kind == "" {
		main = "/usr/lib/systemd/timesyncd.conf"
		kind, e = g.Kind(main)
		if e != nil {
			return e
		}
	}
	candidates := []string{}
	if kind != "" {
		candidates = append(candidates, main)
	}
	seen := map[string]bool{}
	for _, directory := range []string{"/etc/systemd/timesyncd.conf.d", "/run/systemd/timesyncd.conf.d", "/usr/local/lib/systemd/timesyncd.conf.d", "/usr/lib/systemd/timesyncd.conf.d"} {
		names, e := g.List(directory)
		if e != nil {
			return e
		}
		slices.Sort(names)
		for _, name := range names {
			if !strings.HasSuffix(name, ".conf") || seen[name] {
				continue
			}
			seen[name] = true
			candidates = append(candidates, directory+"/"+name)
		}
	}
	for i, p := range candidates {
		kind, e := g.Kind(p)
		if e != nil {
			return e
		}
		if kind == "symlink" {
			target, e := g.Call("readlink", p)
			if e != nil {
				return e
			}
			if target == "/dev/null" {
				continue
			}
		}
		data, e := g.Read(p, filepath.Join(work, fmt.Sprintf("timesyncd-base-%d.conf", i)))
		if e != nil {
			return fmt.Errorf("unresolvable systemd timesyncd config symlink: %s: %w", p, e)
		}
		active, e := activeTimeSetting(data)
		if e != nil {
			return e
		}
		if active {
			return fmt.Errorf("base image has active NTP/FallbackNTP or poll interval configuration: %s", p)
		}
	}
	return g.AssertAbsent(TimeConfig, "timesyncd config")
}

type upload struct {
	source, destination string
	mode                int
}

func parseAccounts(data string, kind string) (map[string]int, error) {
	result := map[string]int{}
	for line := range strings.SplitSeq(strings.TrimSuffix(data, "\n"), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid base /etc/%s record", kind)
		}
		n, e := strconv.Atoi(fields[2])
		if e != nil {
			return nil, e
		}
		if _, exists := result[fields[0]]; exists {
			return nil, fmt.Errorf("duplicate base /etc/%s record", kind)
		}
		result[fields[0]] = n
	}
	return result, nil
}
func accounts(g *Guest, work, config string, out io.Writer) (int, int, []upload, error) {
	root := filepath.Join(work, "account-root")
	etc := filepath.Join(root, "etc")
	if e := os.MkdirAll(filepath.Join(etc, "sysusers.d"), 0755); e != nil {
		return 0, 0, nil, e
	}
	var files []upload
	for _, name := range []string{"passwd", "group", "shadow", "gshadow"} {
		p := "/etc/" + name
		kind, e := g.Kind(p)
		if e != nil {
			return 0, 0, nil, e
		}
		if kind != "file" {
			return 0, 0, nil, fmt.Errorf("base image lacks regular %s", p)
		}
		meta, e := g.Metadata(p)
		if e != nil {
			return 0, 0, nil, e
		}
		source := filepath.Join(etc, name)
		if _, e = g.Read(p, source); e != nil {
			return 0, 0, nil, e
		}
		files = append(files, upload{source, p, meta["st_mode"] & 07777})
	}
	load := func(kind string) (map[string]int, error) {
		b, e := os.ReadFile(filepath.Join(etc, kind))
		if e != nil {
			return nil, e
		}
		return parseAccounts(string(b), kind)
	}
	passwd, e := load("passwd")
	if e != nil {
		return 0, 0, nil, e
	}
	groups, e := load("group")
	if e != nil {
		return 0, 0, nil, e
	}
	for _, m := range []map[string]int{passwd, groups} {
		for name, n := range m {
			if name == "terrascale-workload" || name == "2000" || n == 2000 {
				return 0, 0, nil, errors.New("base image already uses the reserved managed workload UID, GID, or name")
			}
		}
	}
	stagedConfig := filepath.Join(etc, "sysusers.d/terrascale-orchestrator.conf")
	if e = copyFile(config, stagedConfig, 0644); e != nil {
		return 0, 0, nil, e
	}
	if _, e = g.exec(g.ctx, "", g.Env, "systemd-sysusers", "--root="+root, stagedConfig); e != nil {
		return 0, 0, nil, e
	}
	passwd, e = load("passwd")
	if e != nil {
		return 0, 0, nil, e
	}
	groups, e = load("group")
	if e != nil {
		return 0, 0, nil, e
	}
	if passwd["terrascale-workload"] != 2000 || groups["terrascale-workload"] != 2000 {
		return 0, 0, nil, errors.New("managed workload identity was not created as UID/GID 2000:2000")
	}
	data, e := os.ReadFile(filepath.Join(etc, "passwd"))
	if e != nil {
		return 0, 0, nil, e
	}
	uid, gid := -1, -1
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "terrascale-workload" && fields[3] != "2000" {
			return 0, 0, nil, errors.New("orchestrator or managed workload account was not created")
		}
		if fields[0] == "terrascale-orchestrator" {
			uid, _ = strconv.Atoi(fields[2])
			gid, _ = strconv.Atoi(fields[3])
		}
	}
	if uid <= 0 || gid <= 0 || uid == 2000 || gid == 2000 || groups["terrascale-orchestrator"] != gid {
		return 0, 0, nil, errors.New("orchestrator account has an invalid UID/GID or primary group")
	}
	_, e = fmt.Fprintf(out, "offline accounts: workload=2000:2000 orchestrator=%d:%d\n", uid, gid)
	return uid, gid, files, e
}
func expectedInstallLinks(stage string, names []string) (map[string]string, error) {
	expected := map[string]string{}
	for _, name := range names {
		unit := filepath.Join(stage, "etc/systemd/system", name)
		source := "/etc/systemd/system/" + name
		if _, e := os.Stat(unit); os.IsNotExist(e) {
			unit = filepath.Join(stage, "usr/lib/systemd/system", name)
			source = "/usr/lib/systemd/system/" + name
		}
		s, e := os.Lstat(unit)
		if e != nil || !s.Mode().IsRegular() {
			return nil, fmt.Errorf("required systemd unit is not a direct regular file: %s", name)
		}
		b, e := os.ReadFile(unit)
		if e != nil {
			return nil, e
		}
		section := ""
		found := false
		for raw := range strings.SplitSeq(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = line[1 : len(line)-1]
				continue
			}
			if section != "Install" {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok || !slices.Contains([]string{"WantedBy", "RequiredBy", "Alias", "Also"}, key) {
				return nil, fmt.Errorf("unsupported systemd [Install] entry in %s: %s", name, line)
			}
			if key == "Also" {
				for _, other := range strings.Fields(value) {
					if !slices.Contains(names, other) {
						return nil, fmt.Errorf("unsupported systemd Also unit in %s", name)
					}
				}
				continue
			}
			for _, item := range strings.Fields(value) {
				if !regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`).MatchString(item) {
					return nil, fmt.Errorf("invalid systemd [Install] name in %s: %s", name, item)
				}
				link := item
				if key != "Alias" {
					relationship := "wants"
					if key == "RequiredBy" {
						relationship = "requires"
					}
					link = item + "." + relationship + "/" + name
				}
				if existing, ok := expected[link]; ok && existing != source {
					return nil, fmt.Errorf("conflicting systemd enablement link: %s", link)
				}
				expected[link] = source
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("required systemd unit has no enablement links: %s", name)
		}
	}
	return expected, nil
}
func resolveLink(link, target string) string {
	if !strings.HasPrefix(target, "/") {
		target = path.Join("/etc/systemd/system", path.Dir(link), target)
	}
	target = path.Clean(target)
	if strings.HasPrefix(target, "/lib/systemd/system/") {
		target = "/usr" + target
	}
	return target
}
func collectLinks(root string) (map[string]string, error) {
	links := map[string]string{}
	e := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			target, e := os.Readlink(p)
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(root, p)
			if e != nil {
				return e
			}
			links[rel] = target
		}
		return nil
	})
	return links, e
}
func installLinks(g *Guest, work, repo string, out io.Writer) error {
	stage := filepath.Join(work, "systemd-root")
	for _, dir := range []string{"etc/systemd", "usr/lib/systemd"} {
		if e := os.MkdirAll(filepath.Join(stage, dir), 0755); e != nil {
			return e
		}
	}
	if e := os.Symlink("usr/lib", filepath.Join(stage, "lib")); e != nil {
		return e
	}
	if _, e := g.Call("copy-out", "/etc/systemd/system", filepath.Join(stage, "etc/systemd")); e != nil {
		return e
	}
	if _, e := g.Call("copy-out", "/usr/lib/systemd/system", filepath.Join(stage, "usr/lib/systemd")); e != nil {
		return e
	}
	etc := filepath.Join(stage, "etc/systemd/system")
	for _, name := range append(append([]string{"terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"}, NetBirdUnits...), HostUnitFiles...) {
		if e := copyFile(filepath.Join(repo, "deploy/systemd", name), filepath.Join(etc, name), 0644); e != nil {
			return e
		}
	}
	names := append(append([]string{}, Units...), HostUnits...)
	files := append(append([]string{}, names...), "terrascale-orchestrator-host-volume-init.service")
	for _, name := range files {
		for _, dir := range []string{"/run/systemd/system", "/usr/local/lib/systemd/system"} {
			if e := g.AssertAbsent(dir+"/"+name, "systemd unit override"); e != nil {
				return e
			}
		}
		unit := filepath.Join(etc, name)
		if target, e := os.Readlink(unit); e == nil && target == "/dev/null" {
			return fmt.Errorf("required systemd unit is masked: %s", name)
		}
		if _, e := os.Stat(unit); e != nil {
			if _, e = os.Stat(filepath.Join(stage, "usr/lib/systemd/system", name)); e != nil {
				return fmt.Errorf("missing a required systemd unit: %s", name)
			}
		}
	}
	expected, e := expectedInstallLinks(stage, names)
	if e != nil {
		return e
	}
	before, e := collectLinks(etc)
	if e != nil {
		return e
	}
	env := append(append([]string{}, g.Env...), "SYSTEMD_OFFLINE=1")
	if _, e = g.exec(g.ctx, "", env, append([]string{"systemctl", "--root=" + stage, "enable"}, names...)...); e != nil {
		return e
	}
	for _, name := range names {
		state, e := g.exec(g.ctx, "", env, "systemctl", "--root="+stage, "is-enabled", name)
		if e != nil {
			return e
		}
		if state != "enabled" {
			return fmt.Errorf("required systemd unit is not enabled: %s (%s)", name, state)
		}
	}
	after, e := collectLinks(etc)
	if e != nil {
		return e
	}
	for link := range after {
		if _, exists := before[link]; !exists {
			if _, exists = expected[link]; !exists {
				return errors.New("host systemctl generated a different set of enablement links than guest unit [Install] metadata")
			}
		}
	}
	for link, unit := range expected {
		target, exists := after[link]
		if !exists || resolveLink(link, target) != unit {
			return fmt.Errorf("systemd enablement link does not point to its required unit: %s", link)
		}
	}
	for link, target := range after {
		if old, exists := before[link]; exists {
			if old != target {
				return fmt.Errorf("systemctl changed a preexisting unit link: %s", link)
			}
			continue
		}
		guestPath := "/etc/systemd/system/" + link
		if e = g.AssertAbsent(guestPath, "systemd enablement link"); e != nil {
			return e
		}
		if e = g.Directory(path.Dir(guestPath), 0, 0, 0755); e != nil {
			return e
		}
		if _, e = g.Call("ln-s", target, guestPath); e != nil {
			return e
		}
	}
	for link, target := range after {
		if _, exists := expected[link]; !exists {
			continue
		}
		guestPath := "/etc/systemd/system/" + link
		kind, e := g.Kind(guestPath)
		if e != nil {
			return e
		}
		observed, e := g.Call("readlink", guestPath)
		if e != nil {
			return e
		}
		if kind != "symlink" || observed != target {
			return fmt.Errorf("systemd enablement link readback differs: %s", guestPath)
		}
	}
	_, e = fmt.Fprintf(out, "offline systemd enablement links verified=%d\n", len(expected))
	return e
}
