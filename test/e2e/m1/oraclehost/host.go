package oraclehost

import (
	"bufio"
	"crypto/rand"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	hostCommand    = "oraclehost-host"
	serviceCommand = "oraclehost-service"
	notifySocket   = "/run/systemd/notify"
	stateDir       = "/var/lib/ts-orch"
	installedPath  = "/usr/local/bin/terrascale-orchestrator"
)

type hostConfig struct {
	Name       string
	Dir        string
	InstanceID string
	CABundle   string
	Containerd string
}

type Event struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Run      int       `json:"run"`
	Revision string    `json:"revision,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

func Main() bool {
	if name := filepath.Base(os.Args[0]); name == systemctlCommand || name == analyzeCommand {
		os.Exit(serviceManager(name, os.Args[1:]))
	}
	if len(os.Args) < 3 {
		return false
	}
	var err error
	switch os.Args[1] {
	case hostCommand:
		err = runHost(os.Args[2])
	case serviceCommand:
		err = runService(os.Args[2])
	default:
		return false
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "oraclehost:", err)
		os.Exit(1)
	}
	os.Exit(0)
	return true
}

func readHostConfig(path string) (hostConfig, error) {
	var cfg hostConfig
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &cfg)
	}
	return cfg, err
}

func mount(source, target, kind string, flags uintptr, data string) error {
	if err := unix.Mount(source, target, kind, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", source, target, err)
	}
	return nil
}

func bind(source, target string) error { return mount(source, target, "", unix.MS_BIND, "") }

func prepareHostMounts(cfg hostConfig) error {
	if err := unix.Sethostname([]byte(cfg.Name)); err != nil {
		return err
	}
	if err := mount("none", "/sys/fs/cgroup", "cgroup2", 0, ""); err != nil {
		return err
	}
	firmware, err := filepath.EvalSymlinks("/sys/class/dmi/id")
	if err != nil {
		return fmt.Errorf("the runner exposes no DMI directory to stand in for: %w", err)
	}
	if err := mount("tmpfs", firmware, "tmpfs", 0, "mode=0755"); err != nil {
		return err
	}
	for name, value := range map[string]string{"chassis_asset_tag": "OracleCloud.com", "board_asset_tag": cfg.InstanceID} {
		if err := os.WriteFile(filepath.Join(firmware, name), []byte(value+"\n"), 0o444); err != nil {
			return err
		}
	}
	carried := map[string][]byte{}
	for _, name := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"} {
		target, err := filepath.EvalSymlinks(name)
		if err != nil {
			return err
		}
		if strings.HasPrefix(target, "/run/") {
			if carried[target], err = os.ReadFile(name); err != nil {
				return err
			}
		}
	}
	for _, dir := range []string{"/run", "/var/lib", "/etc/systemd"} {
		if err := mount("tmpfs", dir, "tmpfs", 0, "mode=0755"); err != nil {
			return err
		}
	}
	for target, data := range carried {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/run/containerd", "/run/systemd", stateDir, "/var/lib/containerd", "/etc/systemd/journald.conf.d"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for source, target := range map[string]string{
		filepath.Join(cfg.Dir, "state"):      stateDir,
		filepath.Join(cfg.Dir, "containerd"): "/var/lib/containerd",
		filepath.Join(cfg.Dir, "bin"):        "/usr/local/bin",
		cfg.CABundle:                         "/etc/ssl/certs/ca-certificates.crt",
	} {
		if err := bind(source, target); err != nil {
			return err
		}
	}
	return nil
}

type supervisor struct {
	cfg     hostConfig
	unit    unit
	out     *json.Encoder
	outMu   sync.Mutex
	journal *os.File
	mu      sync.Mutex
	child   *exec.Cmd
	run     int
}

func (s *supervisor) emit(kind, revision, detail string) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	s.mu.Lock()
	run := s.run
	s.mu.Unlock()
	_ = s.out.Encode(Event{At: time.Now(), Kind: kind, Run: run, Revision: revision, Detail: detail})
}

func runHost(path string) error {
	unix.Umask(0o022)
	cfg, err := readHostConfig(path)
	if err != nil {
		return err
	}
	u, err := productionUnit()
	if err != nil {
		return err
	}
	if err := prepareHostMounts(cfg); err != nil {
		return err
	}
	journal, err := os.OpenFile(filepath.Join(cfg.Dir, "journal.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer journal.Close()
	s := &supervisor{cfg: cfg, unit: u, out: json.NewEncoder(os.Stdout), journal: journal}
	containerd, err := s.startContainerd()
	if err != nil {
		return err
	}
	defer func() {
		_ = containerd.Process.Signal(syscall.SIGTERM)
		_ = containerd.Wait()
	}()
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifySocket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer notify.Close()
	go s.readNotify(notify)
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	for {
		exited, err := s.start()
		if err != nil {
			return err
		}
		failed := false
		select {
		case code := <-exited:
			s.emit("exited", "", code)
			failed = true
		case sig := <-signals:
			if sig == syscall.SIGINT {
				s.kill(exited)
				return nil
			}
			s.stop(exited)
			if sig != syscall.SIGHUP {
				s.emit("stopped", "", sig.String())
				return nil
			}
		}
		if failed {
			select {
			case <-time.After(s.unit.RestartSec):
			case sig := <-signals:
				if sig != syscall.SIGHUP {
					return nil
				}
			}
		}
	}
}

func (s *supervisor) startContainerd() (*exec.Cmd, error) {
	logFile, err := os.Create(filepath.Join(s.cfg.Dir, "containerd.log"))
	if err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(s.cfg.Containerd, "--address", "/run/containerd/containerd.sock", "--root", "/var/lib/containerd", "--state", "/run/containerd/state")
	cmd.Stdout, cmd.Stderr = writer, writer
	err = cmd.Start()
	_ = writer.Close()
	if err != nil {
		return nil, err
	}
	booted := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		once := sync.Once{}
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = fmt.Fprintln(logFile, line)
			if strings.Contains(line, "containerd successfully booted") {
				once.Do(func() { close(booted) })
			}
		}
		_ = logFile.Close()
	}()
	died := make(chan error, 1)
	go func() { died <- cmd.Wait() }()
	select {
	case <-booted:
		s.emit("containerd", "", "")
		return cmd, nil
	case err := <-died:
		return nil, fmt.Errorf("containerd exited before it booted: %w", err)
	}
}

func revisionOf(path string) string {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return ""
}

func (s *supervisor) start() (<-chan string, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	invocation := make([]byte, 16)
	if _, err := rand.Read(invocation); err != nil {
		return nil, err
	}
	cmd := exec.Command(self, serviceCommand, hex.EncodeToString(invocation))
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = s.journal, s.journal
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, Setpgid: true}
	revision := revisionOf(filepath.Join(s.cfg.Dir, "bin", filepath.Base(installedPath)))
	s.mu.Lock()
	s.run++
	s.child = cmd
	s.mu.Unlock()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := s.recordStart(cmd.Process.Pid, hex.EncodeToString(invocation)); err != nil {
		return nil, err
	}
	s.emit("started", revision, fmt.Sprint(cmd.Process.Pid))
	exited := make(chan string, 1)
	go func() {
		err := cmd.Wait()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		code := "0"
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.String()
		} else if err != nil {
			code = err.Error()
		}
		exited <- code
	}()
	return exited, nil
}

func (s *supervisor) stop(exited <-chan string) {
	s.mu.Lock()
	child := s.child
	s.mu.Unlock()
	_ = child.Process.Signal(syscall.SIGTERM)
	select {
	case code := <-exited:
		s.emit("exited", "", code)
	case <-time.After(s.unit.TimeoutStopSec):
		_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		s.emit("exited", "", "killed after TimeoutStopSec "+<-exited)
	}
}

func (s *supervisor) kill(exited <-chan string) {
	s.mu.Lock()
	child := s.child
	s.mu.Unlock()
	_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	s.emit("killed", "", <-exited)
}

func (s *supervisor) readNotify(conn *net.UnixConn) {
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			s.emit("notify-closed", "", err.Error())
			return
		}
		for _, line := range strings.Split(string(buffer[:n]), "\n") {
			switch {
			case line == "READY=1":
				s.emit("ready", revisionOf(filepath.Join(s.cfg.Dir, "bin", filepath.Base(installedPath))), "")
			case line == "STOPPING=1":
				s.emit("stopping", "", "")
			case strings.HasPrefix(line, "STATUS="):
				s.emit("status", "", strings.TrimPrefix(line, "STATUS="))
			}
		}
	}
}

func runService(invocation string) error {
	u, err := productionUnit()
	if err != nil {
		return err
	}
	if u.PrivateTmp {
		for _, dir := range []string{"/tmp", "/var/tmp"} {
			if err := mount("tmpfs", dir, "tmpfs", 0, "mode=1777"); err != nil {
				return err
			}
		}
	}
	if u.ProtectHome {
		for _, dir := range []string{"/home", "/root", "/run/user"} {
			if _, err := os.Stat(dir); err != nil {
				continue
			}
			if err := mount("tmpfs", dir, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0000"); err != nil {
				return err
			}
		}
	}
	if u.ProtectSystem == "full" {
		writable := map[string]string{}
		for _, path := range u.ReadWritePaths {
			writable[path] = path
		}
		for _, dir := range u.ConfigurationDirectory {
			writable[filepath.Join("/etc", dir)] = filepath.Join("/etc", dir)
		}
		for _, dir := range []string{"/usr", "/boot", "/efi", "/etc"} {
			if _, err := os.Stat(dir); err != nil {
				continue
			}
			if err := mount(dir, dir, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
				return err
			}
			if err := mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
				return err
			}
		}
		for path := range writable {
			if err := mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
				return err
			}
		}
	}
	if u.LimitNOFILE > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: u.LimitNOFILE, Max: u.LimitNOFILE}); err != nil {
			return err
		}
	}
	unix.Umask(u.UMask)
	if u.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"NOTIFY_SOCKET=" + notifySocket,
		"INVOCATION_ID=" + invocation,
		"SYSTEMD_EXEC_PID=" + fmt.Sprint(os.Getpid()),
	}
	return unix.Exec(u.ExecStart[0], u.ExecStart, env)
}
