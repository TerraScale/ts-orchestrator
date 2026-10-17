package firecracker

import (
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ProductionSlots = []string{"controller-a", "controller-b", "controller-c"}
var ProductionAddresses = map[string]string{"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", "controller-c": "10.44.0.10"}
var IMDSPaths = []string{"/opc/v2/instance/id", "/opc/v2/instance/metadata/terrascale-bootstrap", "/opc/v2/instance/region", "/opc/v2/identity/cert.pem", "/opc/v2/identity/key.pem", "/opc/v2/identity/intermediate.pem"}

// OptionalIMDSPaths are answered by the simulator but not required in every
// run: NetBird enrollment reads the primary VNIC only when its daemon reports
// that a login is needed, which the isolated qualification does not force.
var OptionalIMDSPaths = []string{"/opc/v2/vnics/"}
var ProductionUnits = []string{"systemd-networkd.service", "systemd-timesyncd.service", "systemd-time-wait-sync.service", "terrascale-orchestrator-controller.service", "ssh.service"}

func RequirePinnedFile(path, expected string) (string, error) {
	path, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", e
	}
	path, e = filepath.Abs(path)
	if e != nil {
		return "", e
	}
	s, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !s.Mode().IsRegular() || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(expected) {
		return "", fmt.Errorf("invalid pinned regular input %s", path)
	}
	h, e := Digest(path)
	if e != nil {
		return "", e
	}
	if h != expected {
		return "", fmt.Errorf("input hash mismatch for %s: %s", path, h)
	}
	return path, nil
}
func CheckNetworkCollision(ctx context.Context, command CommandFunc, subnet netip.Prefix, imds bool) error {
	r, e := command(ctx, []string{"ip", "-j", "route", "show", "table", "all"}, CommandOptions{})
	if e != nil {
		return e
	}
	v, e := decode(r.Stdout)
	if e != nil {
		return e
	}
	for _, row := range array(v) {
		destination := str(object(row)["dst"])
		if destination == "" || destination == "default" {
			continue
		}
		p, e := netip.ParsePrefix(destination)
		if e != nil {
			if addr, e := netip.ParseAddr(destination); e == nil {
				p = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				continue
			}
		}
		if p.Overlaps(subnet) {
			return fmt.Errorf("host route collides with isolated fixture subnet: %s", destination)
		}
	}
	r, e = command(ctx, []string{"ip", "-j", "address", "show"}, CommandOptions{})
	if e != nil {
		return e
	}
	v, e = decode(r.Stdout)
	if e != nil {
		return e
	}
	for _, link := range array(v) {
		for _, address := range array(object(link)["addr_info"]) {
			a := object(address)
			if a["family"] != "inet" {
				continue
			}
			local, e := netip.ParseAddr(str(a["local"]))
			if e != nil {
				return e
			}
			if subnet.Contains(local) || (imds && local.String() == "169.254.169.254") {
				return fmt.Errorf("host address collides with isolated fixture: %s", local)
			}
		}
	}
	return nil
}
func SameHostNetworkNamespace() (bool, error) {
	a, e := os.Stat("/proc/self/ns/net")
	if e != nil {
		return false, e
	}
	b, e := os.Stat("/proc/1/ns/net")
	if e != nil {
		return false, e
	}
	return os.SameFile(a, b), nil
}

// EnsureProductionNetworkNamespace reexecutes the single Go binary inside a private namespace.
func EnsureProductionNetworkNamespace(ctx context.Context, run bool, argv []string) error {
	return ensureProductionNetworkNamespace(ctx, run, argv, namespaceDependencies{
		same: SameHostNetworkNamespace, uid: os.Geteuid, command: Execute,
		lookPath: exec.LookPath, executable: os.Executable, reexec: syscall.Exec,
	})
}

type namespaceDependencies struct {
	same       func() (bool, error)
	uid        func() int
	command    CommandFunc
	lookPath   func(string) (string, error)
	executable func() (string, error)
	reexec     func(string, []string, []string) error
}

func ensureProductionNetworkNamespace(ctx context.Context, run bool, argv []string, dependencies namespaceDependencies) error {
	if !run {
		return nil
	}
	same, e := dependencies.same()
	if e != nil || !same {
		return e
	}
	if dependencies.uid() != 0 {
		return errors.New("production Firecracker qualification requires root")
	}
	if e = CheckNetworkCollision(ctx, dependencies.command, netip.MustParsePrefix("10.44.0.0/24"), true); e != nil {
		return e
	}
	r, e := dependencies.command(ctx, []string{"timedatectl", "show", "-p", "NTPSynchronized", "--value"}, CommandOptions{})
	if e != nil {
		return e
	}
	if strings.TrimSpace(r.Stdout) != "yes" {
		return errors.New("host clock is not NTP synchronized")
	}
	unshare, e := dependencies.lookPath("unshare")
	if e != nil {
		return errors.New("unshare is required for isolated production qualification")
	}
	executable, e := dependencies.executable()
	if e != nil {
		return e
	}
	return dependencies.reexec(unshare, append([]string{unshare, "--net", "--", executable}, argv...), os.Environ())
}
func NTPTimestamp(moment float64) []byte {
	seconds := moment + 2208988800
	whole := math.Floor(seconds)
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(uint64(whole)))
	binary.BigEndian.PutUint32(b[4:], uint32((seconds-whole)*(1<<32)))
	return b
}
func NTPResponse(request []byte, moment, transmit float64) ([]byte, error) {
	if len(request) < 48 || request[0]&7 != 3 {
		return nil, errors.New("not an NTP client request")
	}
	answer := make([]byte, 48)
	answer[0] = 0x24
	answer[1] = 2
	answer[2] = request[2]
	answer[3] = 0xec
	copy(answer[12:16], "TSFC")
	copy(answer[16:24], NTPTimestamp(moment-1))
	copy(answer[24:32], request[40:48])
	copy(answer[32:40], NTPTimestamp(moment))
	copy(answer[40:48], NTPTimestamp(transmit))
	return answer, nil
}

type NTPServer struct {
	Socket                        *net.UDPConn
	mu                            sync.Mutex
	Requests, Replies, SendErrors map[string]int
	Unknown                       int
	Done                          chan struct{}
}

func StartNTPServer() (*NTPServer, error) {
	socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.44.0.1"), Port: 123})
	if e != nil {
		return nil, e
	}
	s := &NTPServer{Socket: socket, Requests: map[string]int{}, Replies: map[string]int{}, SendErrors: map[string]int{}, Done: make(chan struct{})}
	for _, slot := range ProductionSlots {
		s.Requests[slot] = 0
		s.Replies[slot] = 0
		s.SendErrors[slot] = 0
	}
	go s.serve()
	return s, nil
}
func (s *NTPServer) serve() {
	defer close(s.Done)
	byAddress := map[string]string{}
	for slot, address := range ProductionAddresses {
		byAddress[address] = slot
	}
	b := make([]byte, 512)
	for {
		n, peer, e := s.Socket.ReadFromUDP(b)
		if e != nil {
			return
		}
		slot := byAddress[peer.IP.String()]
		s.mu.Lock()
		if slot == "" {
			s.Unknown++
			s.mu.Unlock()
			continue
		}
		s.Requests[slot]++
		s.mu.Unlock()
		now := float64(time.Now().UnixNano()) / 1e9
		answer, e := NTPResponse(b[:n], now, float64(time.Now().UnixNano())/1e9)
		if e != nil {
			s.mu.Lock()
			s.Unknown++
			s.mu.Unlock()
			continue
		}
		_, e = s.Socket.WriteToUDP(answer, peer)
		s.mu.Lock()
		if e != nil {
			s.SendErrors[slot]++
		} else {
			s.Replies[slot]++
		}
		s.mu.Unlock()
	}
}
func (s *NTPServer) Close() { _ = s.Socket.Close(); <-s.Done }
func (s *NTPServer) Snapshot() Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, p, e := map[string]int{}, map[string]int{}, map[string]int{}
	for _, slot := range ProductionSlots {
		r[slot] = s.Requests[slot]
		p[slot] = s.Replies[slot]
		e[slot] = s.SendErrors[slot]
	}
	return Object{"ntpRequests": r, "ntpReplies": p, "ntpSendErrors": e, "ntpUnknownRequests": s.Unknown}
}
func CheckProductionAudit(audit Object) (map[string]int, error) {
	slots := object(audit["slots"])
	if integer(audit["unknownSources"]) != 0 || len(slots) != len(ProductionSlots) {
		return nil, errors.New("OCI simulator saw unknown sources or incomplete slots")
	}
	counts := map[string]int{}
	for _, slot := range ProductionSlots {
		entry := object(slots[slot])
		requests := array(entry["requests"])
		if integer(entry["overflow"]) != 0 || len(requests) == 0 {
			return nil, fmt.Errorf("%s OCI audit is empty or overflowed", slot)
		}
		imds, compute := map[string]bool{}, map[string]bool{}
		auth, storage := 0, 0
		for _, raw := range requests {
			r := object(raw)
			method, status, host := str(r["method"]), integer(r["status"]), str(r["host"])
			if r["listed"] != true || !slices.Contains([]string{"GET", "POST"}, method) || (status != 200 && status != 404) {
				return nil, fmt.Errorf("%s made a failed, write, or unlisted OCI request: %v", slot, r)
			}
			if status == 404 && host != "objectstorage.sa-saopaulo-1.oraclecloud.com" {
				return nil, fmt.Errorf("%s received an unexpected non-ledger 404: %v", slot, r)
			}
			switch host {
			case "169.254.169.254":
				uri := str(r["requestUri"])
				if !slices.Contains(IMDSPaths, uri) && !slices.Contains(OptionalIMDSPaths, uri) {
					return nil, fmt.Errorf("%s made an unexpected IMDS request: %v", slot, r)
				}
				imds[uri] = true
			case "auth.sa-saopaulo-1.oraclecloud.com":
				auth++
			case "iaas.sa-saopaulo-1.oraclecloud.com":
				compute[str(r["requestUri"])] = true
			case "objectstorage.sa-saopaulo-1.oraclecloud.com":
				storage++
			}
		}
		for _, p := range IMDSPaths {
			if !imds[p] {
				return nil, fmt.Errorf("%s did not exercise IMDS, federation, Compute, and ledger reads", slot)
			}
		}
		if auth < 1 || len(compute) < 3 || storage < 1 {
			return nil, fmt.Errorf("%s did not exercise IMDS, federation, Compute, and ledger reads", slot)
		}
		counts[slot] = len(requests)
	}
	return counts, nil
}

type ProductionOptions struct {
	Paths, Hashes                 map[string]string
	Packet, SourceRoot, ImageOCID string
	Run                           bool
}
type ProductionQualification struct {
	Ctx                            context.Context
	Options                        ProductionOptions
	Command                        CommandFunc
	Root, Bridge, Table, AuditPath string
	Taps                           map[string]string
	CreatedLinks, Mounted          []string
	CreatedTables                  [][2]string
	VMs                            map[string]*ProductionVM
	Simulator                      *Process
	PendingCommands                []*Process
	NativeExecutable               NativeProvenance
	NTP                            *NTPServer
	Report                         Object
	sameNamespace                  func() (bool, error)
	bootVM                         func(*ProductionVM) error
	now                            func() time.Time
	sleep                          func(time.Duration) error
}

func (q *ProductionQualification) clockNow() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}
func (q *ProductionQualification) pause(duration time.Duration) error {
	if q.sleep != nil {
		return q.sleep(duration)
	}
	select {
	case <-q.Ctx.Done():
		return q.Ctx.Err()
	case <-time.After(duration):
		return nil
	}
}

func NewProductionQualification(ctx context.Context, o ProductionOptions) (*ProductionQualification, error) {
	root, e := os.MkdirTemp("/tmp", "tspr-")
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(root, 0o700); e != nil {
		return nil, e
	}
	suffix := tail(filepath.Base(root), 4)
	q := &ProductionQualification{Ctx: ctx, Options: o, Command: Execute, Root: root, Bridge: "tspr" + suffix, Table: "tspr_" + suffix, Taps: map[string]string{}, VMs: map[string]*ProductionVM{}, AuditPath: filepath.Join(root, "oci-audit.json"), Report: Object{"result": "incomplete", "artifacts": Object{}}}
	for i, slot := range ProductionSlots {
		q.Taps[slot] = fmt.Sprintf("tsp%s%d", suffix, i+1)
	}
	return q, nil
}
func (q *ProductionQualification) command(args []string, o CommandOptions) (CommandResult, error) {
	r, e := q.Command(q.Ctx, args, o)
	if pending, ok := errors.AsType[*PendingCommandError](e); ok && !slices.Contains(q.PendingCommands, pending.Process) {
		q.PendingCommands = append(q.PendingCommands, pending.Process)
	}
	return r, e
}
func (q *ProductionQualification) Fixturegen(extra ...string) (CommandResult, error) {
	for _, name := range []string{"fixturegen", "root-cert"} {
		h, e := Digest(q.Options.Paths[name])
		if e != nil || h != q.Options.Hashes[name] {
			return CommandResult{}, errors.New("packet verifier or trusted root changed after pinning")
		}
	}
	argv := append([]string{q.Options.Paths["fixturegen"]}, extra...)
	argv = append(argv, "-packet", q.Options.Packet, "-root-cert", q.Options.Paths["root-cert"], "-source-root", q.Options.SourceRoot, "-image-ocid", q.Options.ImageOCID)
	return q.command(argv, CommandOptions{Timeout: 120 * time.Second})
}
func (q *ProductionQualification) Preflight() (Object, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("production Firecracker qualification requires root")
	}
	moduleDigests := Object{}
	for _, name := range []string{"go.mod", "go.sum"} {
		h, e := Digest(filepath.Join(q.Options.SourceRoot, name))
		if e != nil {
			return nil, e
		}
		moduleDigests[name] = h
	}
	q.Report["goModuleInputs"] = moduleDigests
	for _, name := range []string{"rootfs", "kernel", "firecracker", "fixturegen", "ssh-key", "known-hosts", "root-cert"} {
		path, e := RequirePinnedFile(q.Options.Paths[name], q.Options.Hashes[name])
		if e != nil {
			return nil, e
		}
		q.Options.Paths[name] = path
		object(q.Report["artifacts"])[name] = q.Options.Hashes[name]
	}
	if _, e := q.Fixturegen("production-preflight"); e != nil {
		return nil, e
	}
	manifest, e := readObject(filepath.Join(q.Options.Packet, "manifest.json"))
	if e != nil {
		return nil, e
	}
	rows := array(manifest["controllers"])
	if len(rows) != 3 {
		return nil, errors.New("packet controller slots differ from fixed topology")
	}
	for i, slot := range ProductionSlots {
		if object(rows[i])["slot"] != slot {
			return nil, errors.New("packet controller slots differ from fixed topology")
		}
	}
	if e = CheckNetworkCollision(q.Ctx, q.Command, netip.MustParsePrefix("10.44.0.0/24"), true); e != nil {
		return nil, e
	}
	if q.Options.Run {
		r, e := q.command([]string{"timedatectl", "show", "-p", "NTPSynchronized", "--value"}, CommandOptions{})
		if e != nil {
			return nil, e
		}
		if strings.TrimSpace(r.Stdout) != "yes" {
			return nil, errors.New("host clock is not NTP synchronized")
		}
	}
	return manifest, nil
}
func (q *ProductionQualification) PrepareImages() error {
	b, e := os.ReadFile(filepath.Join(q.Options.Packet, "simulator/guest-directories.json"))
	if e != nil {
		return e
	}
	v, e := decode(string(b))
	if e != nil {
		return e
	}
	plan := array(v)
	if len(plan) != 6 {
		return errors.New("signed service directory plan is incomplete")
	}
	identities := Object{}
	for _, slot := range ProductionSlots {
		owner := []Object{}
		for _, row := range plan {
			r := object(row)
			if r["controllerSlot"] == slot {
				owner = append(owner, r)
			}
		}
		if len(owner) != 2 || owner[0]["uid"] != owner[1]["uid"] || owner[0]["gid"] != owner[1]["gid"] {
			return fmt.Errorf("%s has incomplete service ownership", slot)
		}
		identities[slot] = Object{"uid": owner[0]["uid"], "gid": owner[0]["gid"]}
		image := filepath.Join(q.Root, slot+".ext4")
		if _, e = q.command([]string{"cp", "--reflink=never", "--sparse=always", q.Options.Paths["rootfs"], image}, CommandOptions{Timeout: 240 * time.Second}); e != nil {
			return e
		}
		h, e := Digest(image)
		if e != nil {
			return e
		}
		a, e := os.Stat(image)
		if e != nil {
			return e
		}
		base, e := os.Stat(q.Options.Paths["rootfs"])
		if e != nil {
			return e
		}
		if h != q.Options.Hashes["rootfs"] || os.SameFile(a, base) {
			return errors.New("disposable image copy differs from pinned base")
		}
		if e = os.Truncate(image, max(a.Size(), 8<<30)); e != nil {
			return e
		}
		r, e := q.command([]string{"e2fsck", "-f", "-y", image}, CommandOptions{Timeout: 240 * time.Second, AllowFailure: true})
		if e != nil {
			return e
		}
		if r.Code != 0 && r.Code != 1 {
			return fmt.Errorf("disposable image check failed: %s", tail(r.Stderr, 500))
		}
		if _, e = q.command([]string{"resize2fs", image}, CommandOptions{Timeout: 240 * time.Second}); e != nil {
			return e
		}
		mount := filepath.Join(q.Root, "mount-"+slot)
		if e = os.Mkdir(mount, 0o700); e != nil {
			return e
		}
		q.Mounted = append(q.Mounted, mount)
		if _, e = q.command([]string{"mount", "-o", "loop", image, mount}, CommandOptions{}); e != nil {
			return e
		}
		stageErr := func() error {
			if _, e := q.Fixturegen("stage", "-guest-root", mount, "-slot", slot); e != nil {
				return e
			}
			for _, unit := range ProductionUnits {
				r, e := q.command([]string{"systemctl", "--root=" + mount, "is-enabled", unit}, CommandOptions{})
				if e != nil {
					return e
				}
				if strings.TrimSpace(r.Stdout) != "enabled" {
					return fmt.Errorf("%s image has disabled %s: %s", slot, unit, r.Stdout)
				}
			}
			return nil
		}()
		if pendingErrors := quiescePendingCommands(&q.PendingCommands); len(pendingErrors) > 0 {
			return errors.Join(stageErr, fmt.Errorf("preserve guest image and mount %s: %s", mount, strings.Join(pendingErrors, "; ")))
		}
		_, unmountErr := q.command([]string{"umount", mount}, CommandOptions{})
		if unmountErr == nil {
			q.Mounted = slices.DeleteFunc(q.Mounted, func(p string) bool { return p == mount })
		}
		if e = errors.Join(stageErr, unmountErr); e != nil {
			return e
		}
		socket, e := SocketPath(q.Root, slot)
		if e != nil {
			return e
		}
		q.VMs[slot] = &ProductionVM{Q: q, Slot: slot, Tap: q.Taps[slot], Image: image, Socket: socket}
	}
	q.Report["serviceIdentity"] = identities
	return nil
}
func (q *ProductionQualification) Network() error {
	sameNamespace := q.sameNamespace
	if sameNamespace == nil {
		sameNamespace = SameHostNetworkNamespace
	}
	same, e := sameNamespace()
	if e != nil {
		return e
	}
	if same {
		return errors.New("production fixture network requires a private namespace")
	}
	for _, args := range [][]string{{"ip", "link", "set", "lo", "up"}, {"ip", "link", "add", q.Bridge, "type", "bridge"}} {
		if _, e = q.command(args, CommandOptions{}); e != nil {
			if args[2] == "add" && (len(q.PendingCommands) > 0 || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded)) {
				q.CreatedLinks = append(q.CreatedLinks, q.Bridge)
			}
			return e
		}
	}
	q.CreatedLinks = append(q.CreatedLinks, q.Bridge)
	for _, args := range [][]string{{"ip", "address", "add", "10.44.0.1/24", "dev", q.Bridge}, {"ip", "address", "add", "169.254.169.254/32", "dev", q.Bridge}, {"ip", "link", "set", q.Bridge, "up"}} {
		if _, e = q.command(args, CommandOptions{}); e != nil {
			return e
		}
	}
	for _, slot := range ProductionSlots {
		tap := q.Taps[slot]
		if _, e = q.command([]string{"ip", "tuntap", "add", "dev", tap, "mode", "tap"}, CommandOptions{}); e != nil {
			if len(q.PendingCommands) > 0 || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				q.CreatedLinks = append(q.CreatedLinks, tap)
			}
			return e
		}
		q.CreatedLinks = append(q.CreatedLinks, tap)
		for _, args := range [][]string{{"ip", "link", "set", tap, "master", q.Bridge}, {"ip", "link", "set", tap, "up"}} {
			if _, e = q.command(args, CommandOptions{}); e != nil {
				return e
			}
		}
	}
	return q.Firewall()
}
func (q *ProductionQualification) FirewallPrograms() map[string]string {
	taps := []string{}
	for _, slot := range ProductionSlots {
		taps = append(taps, strconv.Quote(q.Taps[slot]))
	}
	tapset := strings.Join(taps, ", ")
	out := map[string]string{}
	for _, family := range []string{"inet", "bridge"} {
		priority := "-100"
		if family == "bridge" {
			priority = "0"
		}
		lines := []string{"table " + family + " " + q.Table + " {"}
		for _, chain := range []string{"input", "forward"} {
			lines = append(lines, "chain vm_"+chain+" { type filter hook "+chain+" priority "+priority+"; policy accept;")
			if family == "bridge" {
				lines = append(lines, "iifname { "+tapset+" } ether type arp accept", "iifname { "+tapset+" } ether type ip6 drop")
			}
			for _, slot := range ProductionSlots {
				lines = append(lines, fmt.Sprintf("iifname %q ip saddr != %s counter drop", q.Taps[slot], ProductionAddresses[slot]))
			}
			scope := tapset
			if family == "inet" && chain == "forward" {
				scope += ", " + strconv.Quote(q.Bridge)
			}
			lines = append(lines, "iifname { "+scope+" } ct state established,related accept")
			if chain == "input" {
				lines = append(lines, "iifname { "+tapset+" } ip daddr 10.44.0.1 tcp dport 443 counter accept", "iifname { "+tapset+" } ip daddr 10.44.0.1 udp dport 123 counter accept", "iifname { "+tapset+" } ip daddr 169.254.169.254 tcp dport 80 counter accept")
			} else {
				for _, source := range ProductionSlots {
					for _, target := range ProductionSlots {
						if source == target {
							continue
						}
						prefix := "iifname { " + scope + " }"
						if family == "bridge" {
							prefix = fmt.Sprintf("iifname %q oifname %q", q.Taps[source], q.Taps[target])
						}
						lines = append(lines, prefix+" ip saddr "+ProductionAddresses[source]+" ip daddr "+ProductionAddresses[target]+" tcp dport { 4222, 6222 } accept")
					}
				}
			}
			lines = append(lines, "iifname { "+scope+" } counter drop", "}")
		}
		lines = append(lines, "}")
		out[family] = strings.Join(lines, "\n")
	}
	return out
}
func (q *ProductionQualification) Firewall() error {
	for _, family := range []string{"inet", "bridge"} {
		r, e := q.command([]string{"nft", "list", "table", family, q.Table}, CommandOptions{AllowFailure: true})
		if e != nil {
			return e
		}
		if r.Code == 0 {
			return fmt.Errorf("refusing to replace existing %s firewall table", family)
		}
	}
	programs := q.FirewallPrograms()
	for _, family := range []string{"inet", "bridge"} {
		q.CreatedTables = append(q.CreatedTables, [2]string{family, q.Table})
		if _, e := q.command([]string{"nft", "-f", "-"}, CommandOptions{Input: programs[family]}); e != nil {
			return e
		}
	}
	return nil
}
func (q *ProductionQualification) StartServices() error {
	for _, name := range []string{"fixturegen", "root-cert"} {
		h, e := Digest(q.Options.Paths[name])
		if e != nil || h != q.Options.Hashes[name] {
			return errors.New("packet verifier or trusted root changed before simulator launch")
		}
	}
	var e error
	q.NTP, e = StartNTPServer()
	if e != nil {
		return e
	}
	log, e := os.OpenFile(filepath.Join(q.Root, "simulator.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if e != nil {
		return e
	}
	q.Simulator, e = Start([]string{q.Options.Paths["fixturegen"], "serve", "-packet", q.Options.Packet, "-root-cert", q.Options.Paths["root-cert"], "-source-root", q.Options.SourceRoot, "-image-ocid", q.Options.ImageOCID, "-audit", q.AuditPath}, "", log)
	if e != nil {
		log.Close()
		return e
	}
	q.Simulator.Output = log
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		done, e := q.Simulator.Exited()
		if e != nil {
			return e
		}
		if done {
			return errors.New("OCI simulator exited before VM boot")
		}
		b, _ := os.ReadFile(filepath.Join(q.Root, "simulator.log"))
		if strings.Contains(string(b), "simulators ready") {
			return nil
		}
		select {
		case <-q.Ctx.Done():
			return q.Ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("OCI simulator did not become ready")
}

type ProductionVM struct {
	Q                        *ProductionQualification
	Slot, Tap, Image, Socket string
	Process                  *Process
}

func (v *ProductionVM) Boot() error {
	if v.Process != nil {
		return errors.New("Firecracker guest is already running")
	}
	serial, e := os.OpenFile(filepath.Join(v.Q.Root, v.Slot+"-serial.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	v.Process, e = Start([]string{v.Q.Options.Paths["firecracker"], "--api-sock", v.Socket}, "", serial)
	if e != nil {
		serial.Close()
		return e
	}
	v.Process.Output = serial
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, e = os.Stat(v.Socket); e == nil {
			break
		}
		done, e := v.Process.Exited()
		if e != nil {
			return e
		}
		if done {
			return fmt.Errorf("Firecracker %s exited before API socket", v.Slot)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Firecracker %s API socket did not appear", v.Slot)
		}
		select {
		case <-v.Q.Ctx.Done():
			return v.Q.Ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	for _, r := range []struct {
		path    string
		payload Object
	}{{"/machine-config", Object{"vcpu_count": 2, "mem_size_mib": 4096, "smt": false}}, {"/boot-source", Object{"kernel_image_path": v.Q.Options.Paths["kernel"], "boot_args": "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw"}}, {"/drives/rootfs", Object{"drive_id": "rootfs", "path_on_host": v.Image, "is_root_device": true, "is_read_only": false}}, {"/network-interfaces/eth0", Object{"iface_id": "eth0", "host_dev_name": v.Tap, "guest_mac": fmt.Sprintf("02:fc:44:00:00:%02x", slices.Index(ProductionSlots, v.Slot)+1)}}, {"/actions", Object{"action_type": "InstanceStart"}}} {
		if e = UnixAPI(v.Q.Ctx, v.Socket, r.path, r.payload); e != nil {
			return e
		}
	}
	return nil
}
func (v *ProductionVM) SSH(script string, timeout time.Duration, check bool) (CommandResult, error) {
	return v.Q.command([]string{"ssh", "-i", v.Q.Options.Paths["ssh-key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + v.Q.Options.Paths["known-hosts"], "-o", "ConnectTimeout=3", "root@" + ProductionAddresses[v.Slot], "sh", "-lc", quote(script)}, CommandOptions{Timeout: timeout, AllowFailure: !check})
}
func (v *ProductionVM) WaitSSH(previous string, timeout time.Duration) (string, error) {
	deadline := v.Q.clockNow().Add(timeout)
	for v.Q.clockNow().Before(deadline) {
		if v.Process == nil {
			return "", fmt.Errorf("Firecracker %s stopped while waiting for SSH", v.Slot)
		}
		done, e := v.Process.Exited()
		if e != nil {
			return "", e
		}
		if done {
			return "", fmt.Errorf("Firecracker %s stopped while waiting for SSH", v.Slot)
		}
		r, e := v.SSH("cat /proc/sys/kernel/random/boot_id", 8*time.Second, false)
		if e != nil && !errors.Is(e, context.DeadlineExceeded) {
			return "", e
		}
		id := strings.TrimSpace(r.Stdout)
		if e == nil && r.Code == 0 && id != "" && id != previous {
			return id, nil
		}
		if e = v.Q.pause(2 * time.Second); e != nil {
			return "", e
		}
	}
	return "", fmt.Errorf("%s SSH did not reach a new boot", v.Slot)
}

const productionHealthScript = `set -eu; fail() { printf 'failed-stage=%s\n' "$1" >&2; exit 1; }; test "$(timedatectl show -p NTPSynchronized --value)" = yes || fail ntp-synchronized; timedatectl timesync-status --no-pager | grep -F '10.44.0.1' || fail ntp-server; test "$(systemctl show -p Result --value terrascale-orchestrator-bootstrap.service)" = success || fail bootstrap-result; test "$(systemctl show -p ExecMainStatus --value terrascale-orchestrator-bootstrap.service)" = 0 || fail bootstrap-exit; test "$(systemctl show -p ActiveState --value terrascale-orchestrator-controller.service)" = active || fail controller-active; pid=$(systemctl show -p MainPID --value terrascale-orchestrator-controller.service); test "$pid" -gt 1 || fail controller-pid; awk '/^Uid:|^Gid:/ {print $1, $2, $3, $4, $5}' /proc/$pid/status; systemctl show -p InvocationID --value terrascale-orchestrator-controller.service; cat /proc/sys/kernel/random/boot_id`
const productionHealthDiagnosticScript = `printf '%s\n' '[clock]'; timedatectl show -p NTPSynchronized --value 2>&1 || true; timedatectl timesync-status --no-pager 2>&1 || true; printf '%s\n' '[network]'; networkctl status eth0 --no-pager 2>&1 || true; printf '%s\n' '[units]'; for unit in systemd-timesyncd.service systemd-time-wait-sync.service terrascale-orchestrator-bootstrap.service terrascale-orchestrator-controller.service; do printf '%s\n' "$unit"; systemctl show "$unit" -p ActiveState -p SubState -p Result -p ExecMainStatus --no-pager 2>&1 || true; done; printf '%s\n' '[systemd unit journal]'; journalctl -b -n 40 --no-pager -o cat SYSLOG_IDENTIFIER=systemd -u systemd-timesyncd.service -u systemd-time-wait-sync.service -u terrascale-orchestrator-bootstrap.service -u terrascale-orchestrator-controller.service 2>&1 || true`

func ProductionHealthEvidence(output string, uid, gid int64) (Object, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	uids, gids := [][]string{}, [][]string{}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) > 0 {
			if f[0] == "Uid:" {
				uids = append(uids, f[1:])
			}
			if f[0] == "Gid:" {
				gids = append(gids, f[1:])
			}
		}
	}
	u, g := strconv.FormatInt(uid, 10), strconv.FormatInt(gid, 10)
	if len(lines) < 2 || len(uids) != 1 || len(gids) != 1 || !slices.Equal(uids[0], []string{u, u, u, u}) || !slices.Equal(gids[0], []string{g, g, g, g}) {
		return nil, errors.New("failed-stage=service-identity")
	}
	return Object{"bootId": lines[len(lines)-1], "controllerInvocation": lines[len(lines)-2], "uid": uid, "gid": gid, "ntp": "synchronized", "bootstrap": "success", "controller": "active"}, nil
}
func (v *ProductionVM) Health(uid, gid int64) (Object, error) {
	deadline := v.Q.clockNow().Add(300 * time.Second)
	last := ""
	for v.Q.clockNow().Before(deadline) {
		r, e := v.SSH(productionHealthScript, 15*time.Second, false)
		if e != nil && !errors.Is(e, context.DeadlineExceeded) {
			return nil, e
		}
		if e == nil && r.Code == 0 {
			evidence, parseErr := ProductionHealthEvidence(r.Stdout, uid, gid)
			if parseErr == nil {
				return evidence, nil
			}
			last = tail(parseErr.Error()+"\n"+r.Stdout, 500)
		} else {
			last = tail(r.Stderr, 500) + tail(r.Stdout, 500)
		}
		if e = v.Q.pause(3 * time.Second); e != nil {
			return nil, e
		}
	}
	r, e := v.SSH(productionHealthDiagnosticScript, 20*time.Second, false)
	diagnostic := tail(r.Stdout+r.Stderr, 8000)
	if e != nil {
		diagnostic = "diagnostic SSH timed out"
	}
	return nil, fmt.Errorf("%s did not reach production health: %s\nguest diagnostics:\n%s", v.Slot, last, diagnostic)
}
func (v *ProductionVM) Stop() error {
	if v.Process == nil {
		return nil
	}
	if e := v.Process.Stop(10*time.Second, false); e != nil {
		return e
	}
	v.Process = nil
	return removeMissing(v.Socket)
}
func CheckProductionRestart(first, restart Object) error {
	if restart["bootId"] == first["bootId"] || restart["controllerInvocation"] == first["controllerInvocation"] {
		return errors.New("did not complete a new production controller invocation")
	}
	return nil
}
func (q *ProductionQualification) RunVMs() error {
	for _, slot := range ProductionSlots {
		boot := q.bootVM
		if boot == nil {
			boot = (*ProductionVM).Boot
		}
		if e := boot(q.VMs[slot]); e != nil {
			return e
		}
	}
	evidence := Object{}
	for _, slot := range ProductionSlots {
		vm := q.VMs[slot]
		boot, e := vm.WaitSSH("", 240*time.Second)
		if e != nil {
			return e
		}
		identity := object(object(q.Report["serviceIdentity"])[slot])
		first, e := vm.Health(integer(identity["uid"]), integer(identity["gid"]))
		if e != nil {
			return e
		}
		if first["bootId"] != boot {
			return fmt.Errorf("%s boot identity changed during health check", slot)
		}
		evidence[slot] = Object{"first": first}
	}
	for _, slot := range ProductionSlots {
		vm := q.VMs[slot]
		first := object(object(evidence[slot])["first"])
		previous := str(first["bootId"])
		if _, e := vm.SSH("systemctl reboot", 10*time.Second, false); e != nil && !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		if _, e := vm.WaitSSH(previous, 240*time.Second); e != nil {
			return e
		}
		identity := object(object(q.Report["serviceIdentity"])[slot])
		restart, e := vm.Health(integer(identity["uid"]), integer(identity["gid"]))
		if e != nil {
			return e
		}
		if e = CheckProductionRestart(first, restart); e != nil {
			return fmt.Errorf("%s %w", slot, e)
		}
		object(evidence[slot])["restart"] = restart
	}
	q.Report["guests"] = evidence
	return nil
}
func droppedPackets(output string) int64 {
	var count int64
	for _, match := range regexp.MustCompile(`counter packets (\d+) bytes \d+ drop`).FindAllStringSubmatch(output, -1) {
		n, _ := strconv.ParseInt(match[1], 10, 64)
		count += n
	}
	return count
}
func (q *ProductionQualification) FinishAudit() error {
	for _, slot := range ProductionSlots {
		if e := q.VMs[slot].Stop(); e != nil {
			return e
		}
	}
	if q.Simulator == nil {
		return errors.New("OCI simulator did not start")
	}
	done, e := q.Simulator.Exited()
	if e != nil {
		return e
	}
	if done {
		return errors.New("OCI simulator exited before audit collection")
	}
	if e = q.Simulator.Stop(20*time.Second, false); e != nil {
		return e
	}
	if q.Simulator.ExitCode != 0 {
		return errors.New("OCI simulator did not exit cleanly")
	}
	q.Simulator = nil
	audit, e := readObject(q.AuditPath)
	if e != nil {
		return e
	}
	counts, e := CheckProductionAudit(audit)
	if e != nil {
		return e
	}
	q.Report["ociRequests"] = counts
	if q.NTP == nil {
		return errors.New("NTP server did not serve only the three expected guests")
	}
	snapshot := q.NTP.Snapshot()
	if integer(snapshot["ntpUnknownRequests"]) != 0 {
		return errors.New("NTP server did not serve only the three expected guests")
	}
	for _, slot := range ProductionSlots {
		if snapshot["ntpReplies"].(map[string]int)[slot] == 0 || snapshot["ntpSendErrors"].(map[string]int)[slot] != 0 {
			return errors.New("NTP server did not serve only the three expected guests")
		}
	}
	for k, v := range snapshot {
		q.Report[k] = v
	}
	var drops int64
	for _, table := range q.CreatedTables {
		r, e := q.command([]string{"nft", "list", "table", table[0], table[1]}, CommandOptions{})
		if e != nil {
			return e
		}
		drops += droppedPackets(r.Stdout)
	}
	if drops > 0 {
		return fmt.Errorf("isolated bridge dropped %d unexpected packets", drops)
	}
	q.Report["firewallDrops"] = drops
	return nil
}
func (q *ProductionQualification) Cleanup() []string {
	originalContext := q.Ctx
	q.Ctx = context.WithoutCancel(originalContext)
	defer func() { q.Ctx = originalContext }()
	failures := []string{}
	if pendingErrors := quiescePendingCommands(&q.PendingCommands); len(pendingErrors) > 0 {
		return pendingErrors
	}
	for _, slot := range ProductionSlots {
		if vm := q.VMs[slot]; vm != nil {
			if e := vm.Stop(); e != nil {
				failures = append(failures, fmt.Sprintf("stop %s: %v", slot, e))
			}
		}
	}
	if q.Simulator != nil {
		done, e := q.Simulator.Exited()
		if e == nil && !done {
			_, e = q.Simulator.WaitUnreaped(0)
			id, groupErr := q.Simulator.Group()
			if groupErr != nil {
				e = groupErr
			} else {
				e = q.Simulator.signalGroup(id, syscall.SIGTERM)
			}
			if e != nil && !errors.Is(e, syscall.ESRCH) {
				failures = append(failures, "signal simulator: "+e.Error())
			}
			done, e = q.Simulator.WaitUnreaped(20 * time.Second)
			if e == nil && !done {
				failures = append(failures, "simulator required SIGKILL during cleanup")
			}
		}
		if e == nil {
			e = q.Simulator.Stop(10*time.Second, true)
		}
		if e != nil {
			failures = append(failures, "stop simulator: "+e.Error())
		} else {
			q.Simulator = nil
		}
	}
	if q.NTP != nil {
		q.NTP.Close()
		for k, v := range q.NTP.Snapshot() {
			q.Report[k] = v
		}
		q.NTP = nil
	}
	for i := len(q.Mounted) - 1; i >= 0; i-- {
		mount := q.Mounted[i]
		if _, e := q.command([]string{"umount", mount}, CommandOptions{}); e != nil {
			failures = append(failures, "unmount "+mount+": "+e.Error())
		} else {
			q.Mounted = slices.Delete(q.Mounted, i, i+1)
		}
		if len(q.PendingCommands) > 0 {
			return failures
		}
	}
	for i := len(q.CreatedTables) - 1; i >= 0; i-- {
		family, name := q.CreatedTables[i][0], q.CreatedTables[i][1]
		r, e := q.command([]string{"nft", "list", "table", family, name}, CommandOptions{})
		if len(q.PendingCommands) > 0 {
			return append(failures, fmt.Sprintf("firewall counter capture is not confirmed stopped: %v", e))
		}
		if e != nil {
			failures = append(failures, "capture "+family+" firewall counters: "+e.Error())
		} else {
			filename := "firewall-" + family + ".txt"
			if e = os.WriteFile(filepath.Join(q.Root, filename), []byte(r.Stdout), 0o600); e != nil {
				failures = append(failures, e.Error())
			}
			if q.Report["firewallCounterFiles"] == nil {
				q.Report["firewallCounterFiles"] = Object{}
			}
			object(q.Report["firewallCounterFiles"])[family] = filename
			q.Report["firewallDrops"] = integer(q.Report["firewallDrops"]) + droppedPackets(r.Stdout)
		}
		if _, e = q.command([]string{"nft", "delete", "table", family, name}, CommandOptions{}); e != nil {
			failures = append(failures, "delete "+family+" "+name+": "+e.Error())
		} else {
			q.CreatedTables = slices.Delete(q.CreatedTables, i, i+1)
		}
		if len(q.PendingCommands) > 0 {
			return failures
		}
	}
	for i := len(q.CreatedLinks) - 1; i >= 0; i-- {
		link := q.CreatedLinks[i]
		if _, e := q.command([]string{"ip", "link", "delete", link}, CommandOptions{}); e != nil {
			failures = append(failures, "delete "+link+": "+e.Error())
		} else {
			q.CreatedLinks = slices.Delete(q.CreatedLinks, i, i+1)
		}
		if len(q.PendingCommands) > 0 {
			return failures
		}
	}
	stopped := true
	for _, vm := range q.VMs {
		if vm.Process != nil {
			stopped = false
		}
	}
	if q.Options.Run && stopped && len(q.Mounted) == 0 {
		for _, slot := range ProductionSlots {
			if e := removeMissing(filepath.Join(q.Root, slot+".ext4")); e != nil {
				failures = append(failures, e.Error())
			}
		}
	}
	return failures
}
func RunProduction(ctx context.Context, args []string, out, errout io.Writer) error {
	f := flag.NewFlagSet("qualification firecracker production", flag.ContinueOnError)
	f.SetOutput(errout)
	o := ProductionOptions{Paths: map[string]string{}, Hashes: map[string]string{}}
	for _, name := range []string{"rootfs", "kernel", "firecracker", "fixturegen", "ssh-key", "known-hosts", "root-cert"} {
		f.Func(name, "pinned input file", func(value string) error { o.Paths[name] = value; return nil })
		f.Func(name+"-sha256", "reviewed lowercase SHA-256", func(value string) error { o.Hashes[name] = value; return nil })
	}
	f.StringVar(&o.Packet, "packet", "", "immutable restart packet")
	f.StringVar(&o.SourceRoot, "source-root", "", "source tree")
	f.StringVar(&o.ImageOCID, "image-ocid", "", "custom image OCID")
	f.BoolVar(&o.Run, "run", false, "launch three VMs after preparation")
	if e := f.Parse(args); e != nil {
		return e
	}
	for _, name := range []string{"rootfs", "kernel", "firecracker", "fixturegen", "ssh-key", "known-hosts", "root-cert"} {
		if o.Paths[name] == "" || o.Hashes[name] == "" {
			return fmt.Errorf("--%s and --%s-sha256 are required", name, name)
		}
	}
	if o.Packet == "" || o.SourceRoot == "" || o.ImageOCID == "" {
		return errors.New("--packet, --source-root and --image-ocid are required")
	}
	for _, p := range []*string{&o.Packet, &o.SourceRoot} {
		absolute, e := filepath.EvalSymlinks(*p)
		if e != nil {
			return e
		}
		*p, e = filepath.Abs(absolute)
		if e != nil {
			return e
		}
	}
	if e := EnsureProductionNetworkNamespace(ctx, o.Run, os.Args[1:]); e != nil {
		return e
	}
	provenance, e := CaptureNativeProvenance()
	if e != nil {
		return e
	}
	q, e := NewProductionQualification(ctx, o)
	if e != nil {
		return e
	}
	q.NativeExecutable = provenance
	q.Report["nativeQualification"] = provenance
	_, e = q.Preflight()
	if e == nil {
		e = q.PrepareImages()
	}
	if e == nil && o.Run {
		for _, step := range []func() error{q.Network, q.StartServices, q.RunVMs, q.FinishAudit} {
			if e = step(); e != nil {
				break
			}
		}
	}
	e = errors.Join(e, q.NativeExecutable.VerifyExecutable())
	for name, expected := range object(q.Report["goModuleInputs"]) {
		actual, hashErr := Digest(filepath.Join(o.SourceRoot, name))
		if hashErr != nil {
			e = errors.Join(e, hashErr)
		} else if actual != expected {
			e = errors.Join(e, fmt.Errorf("qualification module input %s changed", name))
		}
	}
	if e != nil {
		q.Report["result"] = "failed"
		q.Report["error"] = e.Error()
	} else if o.Run {
		q.Report["result"] = "passed"
	} else {
		q.Report["result"] = "prepared-only"
	}
	cleanup := q.Cleanup()
	q.Report["cleanupErrors"] = cleanup
	if len(cleanup) > 0 {
		q.Report["result"] = "failed"
		e = errors.Join(e, fmt.Errorf("cleanup: %v", cleanup))
	}
	writeErr := writeJSON(filepath.Join(q.Root, "report.json"), q.Report)
	fmt.Fprintf(out, "qualification artifacts: %s\n", q.Root)
	return errors.Join(e, writeErr)
}

var _ = json.Deterministic
