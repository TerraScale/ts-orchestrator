package workloadspec

import (
	"errors"
	"strings"
	"testing"
)

// The three sample workloads of TS-572: a stateless HTTP service, a stateful
// service with a volume and a quorum, and a third-party container.
var (
	statelessHTTP = MachineSpec{
		Files:     []File{{Path: "/etc/dashboard/config.toml", Content: "listen = \":8080\"\n"}},
		Lifecycle: Lifecycle{DrainSeconds: 30},
	}
	statefulStore = MachineSpec{
		Artifact:  ArtifactTarball,
		Command:   []string{"bin/store", "--data", "/var/lib/store"},
		Mounts:    []Mount{{Volume: "data", Path: "/var/lib/store"}},
		Lifecycle: Lifecycle{PreStop: []string{"bin/store", "drain"}, DrainSeconds: 45},
	}
	container = MachineSpec{
		Artifact:  ArtifactImage,
		Image:     "ghcr.io/acme/hello-http",
		Command:   []string{"hello-http", "--listen", ":8080"},
		Lifecycle: Lifecycle{PostStart: []string{"/bin/sh", "-c", "test -s /etc/hello/index.html"}},
		Files:     []File{{Path: "/etc/hello/index.html", Content: "hello\n"}},
	}
)

func TestSampleWorkloadsAreValid(t *testing.T) {
	for name, spec := range map[string]MachineSpec{"stateless": statelessHTTP, "stateful": statefulStore, "container": container} {
		if err := spec.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (AppSpec{Placement: Placement{MaxPerFailureDomain: 1}}).Validate("dashboard"); err != nil {
		t.Fatal(err)
	}
	stateful := AppSpec{Stateful: &Stateful{Quorum: 2}, DependsOn: []string{"ts-auth"}}
	if err := stateful.Validate("store"); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactSelectsDriver(t *testing.T) {
	for artifact, want := range map[Artifact]Driver{"": DriverNative, ArtifactBinary: DriverNative,
		ArtifactTarball: DriverNative, ArtifactImage: DriverOCI} {
		if got := artifact.Driver(); got != want {
			t.Errorf("%q runs on %q, want %q", artifact, got, want)
		}
	}
}

func TestStrategyDefaults(t *testing.T) {
	for _, tc := range []struct {
		spec AppSpec
		want Strategy
	}{
		{AppSpec{}, AllAtOnce},
		{AppSpec{Stateful: &Stateful{Quorum: 2}}, Rolling},
		{AppSpec{Update: Update{Strategy: Rolling}}, Rolling},
	} {
		if got := tc.spec.Strategy(); got != tc.want {
			t.Errorf("%+v: strategy %q, want %q", tc.spec, got, tc.want)
		}
	}
}

func TestMachineSpecRefusals(t *testing.T) {
	long := strings.Repeat("a", maxArgBytes)
	image := func(m *MachineSpec, repository string, command ...string) {
		m.Artifact, m.Image, m.Command = ArtifactImage, repository, command
	}
	tarball := func(m *MachineSpec, command ...string) { m.Artifact, m.Command = ArtifactTarball, command }
	for name, mutate := range map[string]func(*MachineSpec){
		"unknown artifact":       func(m *MachineSpec) { m.Artifact = "jar" },
		"binary with image":      func(m *MachineSpec) { m.Image = "ghcr.io/acme/web" },
		"binary with command":    func(m *MachineSpec) { m.Command = []string{"/bin/sh"} },
		"tarball without entry":  func(m *MachineSpec) { tarball(m) },
		"tarball absolute entry": func(m *MachineSpec) { tarball(m, "/usr/bin/env") },
		"tarball escaping entry": func(m *MachineSpec) { tarball(m, "../../bin/sh") },
		"tarball unclean entry":  func(m *MachineSpec) { tarball(m, "bin/../../sh") },
		"tarball entry newline":  func(m *MachineSpec) { tarball(m, "bin/app\nExecStart=/bin/sh") },
		"tarball with image": func(m *MachineSpec) {
			tarball(m, "bin/app")
			m.Image = "ghcr.io/acme/web"
		},
		"tarball hook escaping": func(m *MachineSpec) {
			tarball(m, "bin/app")
			m.Lifecycle.PreStop = []string{"../../usr/bin/curl"}
		},
		"image without repo":     func(m *MachineSpec) { image(m, "") },
		"image short name":       func(m *MachineSpec) { image(m, "nginx") },
		"image docker hub short": func(m *MachineSpec) { image(m, "library/nginx") },
		"image with tag":         func(m *MachineSpec) { image(m, "ghcr.io/acme/web:latest") },
		"image with digest":      func(m *MachineSpec) { image(m, "ghcr.io/acme/web@sha256:"+strings.Repeat("a", 64)) },
		"image upper case":       func(m *MachineSpec) { image(m, "ghcr.io/Acme/web") },
		"image too long":         func(m *MachineSpec) { image(m, "ghcr.io/"+strings.Repeat("a", 250)) },
		// Neither podman's local store nor an address such as the instance
		// metadata service is a registry.
		"image localhost":        func(m *MachineSpec) { image(m, "localhost/acme/web") },
		"image ip literal":       func(m *MachineSpec) { image(m, "169.254.169.254/opc/v2") },
		"image ip and port":      func(m *MachineSpec) { image(m, "10.0.0.1:5000/acme/web") },
		"image empty command":    func(m *MachineSpec) { image(m, "ghcr.io/acme/web", "") },
		"image relative command": func(m *MachineSpec) { image(m, "ghcr.io/acme/web", "../sh") },
		"image path command":     func(m *MachineSpec) { image(m, "ghcr.io/acme/web", "bin/sh") },
		"empty hook entry":       func(m *MachineSpec) { m.Lifecycle.PostStart = []string{""} },
		"relative binary hook":   func(m *MachineSpec) { m.Lifecycle.PreStop = []string{"bin/drain"} },
		"bare binary hook":       func(m *MachineSpec) { m.Lifecycle.PreStop = []string{"sh"} },
		"hook with nul":          func(m *MachineSpec) { m.Lifecycle.PostStart = []string{"/bin/true", "a\x00b"} },
		"hook not utf-8":         func(m *MachineSpec) { m.Lifecycle.PostStart = []string{"/bin/true", "\xff"} },
		"argument too long":      func(m *MachineSpec) { m.Lifecycle.PreStop = []string{"/bin/true", long + "a"} },
		"too many arguments": func(m *MachineSpec) {
			m.Lifecycle.PostStart = append([]string{"/bin/true"}, make([]string, maxListed)...)
		},
		"negative drain": func(m *MachineSpec) { m.Lifecycle.DrainSeconds = -1 },
		// The host agent unit stops after 90 s.
		"drain too long":    func(m *MachineSpec) { m.Lifecycle.DrainSeconds = 61 },
		"relative file":     func(m *MachineSpec) { m.Files = []File{{Path: "etc/app.conf"}} },
		"root file":         func(m *MachineSpec) { m.Files = []File{{Path: "/"}} },
		"unclean file":      func(m *MachineSpec) { m.Files = []File{{Path: "/etc/app/../passwd"}} },
		"double slash file": func(m *MachineSpec) { m.Files = []File{{Path: "/etc//passwd"}} },
		"duplicate file":    func(m *MachineSpec) { m.Files = []File{{Path: "/etc/a"}, {Path: "/etc/a"}} },
		"file inside file":  func(m *MachineSpec) { m.Files = []File{{Path: "/etc/a"}, {Path: "/etc/a/b"}} },
		"file holding file": func(m *MachineSpec) { m.Files = []File{{Path: "/etc/a/b"}, {Path: "/etc/a"}} },
		"binary file":       func(m *MachineSpec) { m.Files = []File{{Path: "/etc/a", Content: "\xff\xfe"}} },
		"too many files":    func(m *MachineSpec) { m.Files = make([]File, maxListed+1) },
		// A newline would add a directive to a systemd unit, a comma or
		// colon an option to a podman mount.
		"file path newline": func(m *MachineSpec) { m.Files = []File{{Path: "/etc/a\nExecStartPre=+/bin/sh -c id"}} },
		"file path space":   func(m *MachineSpec) { m.Files = []File{{Path: "/etc/a b"}} },
		"mount path comma":  func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "data", Path: "/data,rw=true"}} },
		"mount path colon":  func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "data", Path: "/data:/etc"}} },
		"mount over proc":   func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "data", Path: "/proc"}} },
		"mount in sys":      func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "data", Path: "/sys/fs"}} },
		"mount over dev":    func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "data", Path: "/dev"}} },
		"file in cgroupfs":  func(m *MachineSpec) { m.Files = []File{{Path: "/sys/fs/cgroup/cgroup.procs"}} },
		"file in dev":       func(m *MachineSpec) { m.Files = []File{{Path: "/dev/sda"}} },
		"unnamed volume":    func(m *MachineSpec) { m.Mounts = []Mount{{Path: "/data"}} },
		"bad volume name":   func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "Data", Path: "/data"}} },
		"relative mount":    func(m *MachineSpec) { m.Mounts = []Mount{{Volume: "data", Path: "data"}} },
		"duplicate volume": func(m *MachineSpec) {
			m.Mounts = []Mount{{Volume: "data", Path: "/a"}, {Volume: "data", Path: "/b"}}
		},
		"nested mounts": func(m *MachineSpec) {
			m.Mounts = []Mount{{Volume: "a", Path: "/data"}, {Volume: "b", Path: "/data/b"}}
		},
		"file on a mount": func(m *MachineSpec) {
			m.Files = []File{{Path: "/data/app.conf"}}
			m.Mounts = []Mount{{Volume: "data", Path: "/data"}}
		},
		// A machine record carries its config and must fit a NATS message.
		"file too large": func(m *MachineSpec) {
			m.Files = []File{{Path: "/etc/a", Content: strings.Repeat("x", maxEncodedBytes)}}
		},
		"hooks too large": func(m *MachineSpec) {
			m.Lifecycle.PreStop = []string{"/bin/true"}
			for range maxListed - 1 {
				m.Lifecycle.PreStop = append(m.Lifecycle.PreStop, long)
			}
		},
	} {
		spec := statelessHTTP
		mutate(&spec)
		if err := spec.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestAppSpecRefusals(t *testing.T) {
	for name, spec := range map[string]AppSpec{
		"negative spread":         {Placement: Placement{MaxPerFailureDomain: -1}},
		"spread too high":         {Placement: Placement{MaxPerFailureDomain: maxMachines + 1}},
		"unknown strategy":        {Update: Update{Strategy: "canary"}},
		"unavailable all at once": {Update: Update{MaxUnavailable: 1}},
		"negative unavailable":    {Update: Update{Strategy: Rolling, MaxUnavailable: -1}},
		"stateful all at once":    {Stateful: &Stateful{Quorum: 2}, Update: Update{Strategy: AllAtOnce}},
		"stateful without quorum": {Stateful: &Stateful{}},
		"quorum too high":         {Stateful: &Stateful{Quorum: maxMachines + 1}},
		"self dependency":         {DependsOn: []string{"web"}},
		"repeated dependency":     {DependsOn: []string{"ts-auth", "ts-auth"}},
		"invalid dependency":      {DependsOn: []string{"TS_AUTH"}},
		"too many dependencies":   {DependsOn: make([]string, maxListed+1)},
	} {
		if err := spec.Validate("web"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}
