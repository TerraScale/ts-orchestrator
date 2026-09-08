package tsnodebootstrap

import (
	"strings"
	"testing"
)

func TestProductionSystemdUnitPinsExactPrivilegeContract(t *testing.T) {
	rendered, err := RenderSystemdUnit(ProductionConfig())
	if err != nil {
		t.Fatalf("render production unit: %v", err)
	}
	want := `[Unit]
Description=TerraScale ts-node host agent
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=root
Group=root
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/terrascale/ts-node/current/ts-node
Restart=on-failure
RestartSec=2s
LimitCORE=0
LimitMEMLOCK=16777216
UMask=0022
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_LINUX_IMMUTABLE
AmbientCapabilities=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_LINUX_IMMUTABLE
SecureBits=noroot-locked
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/opt/terrascale
ReadWritePaths=/var/lib/terrascale
ReadWritePaths=/etc
ReadOnlyPaths=/etc/terrascale
CPUWeight=100
MemoryMax=536870912
IOWeight=100

[Install]
WantedBy=multi-user.target
`
	if rendered != want {
		t.Fatalf("production unit privilege contract drifted:\n%s", rendered)
	}
}

func TestRenderSystemdUnitRejectsUnsafeIdentities(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"unprivileged user": func(config *Config) { config.User = "terrascale-node" },
		"numeric user":      func(config *Config) { config.User = "0" },
		"injected user":     func(config *Config) { config.User = "root\nAmbientCapabilities=CAP_SYS_ADMIN" },
		"unprivileged group": func(config *Config) {
			config.Group = "terrascale-node"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := ProductionConfig()
			mutate(&config)
			if _, err := RenderSystemdUnit(config); err == nil {
				t.Fatal("unsafe identity accepted")
			}
		})
	}
}

func TestRenderSystemdUnitRejectsUnsafePaths(t *testing.T) {
	longPath := "/" + strings.Repeat("a", maximumPathBytes)
	for name, mutate := range map[string]func(*Config){
		"relative executable": func(config *Config) { config.ExecutablePath = "ts-node" },
		"directive injection": func(config *Config) {
			config.DataVolumeRoot = "/var/lib/terrascale\nCapabilityBoundingSet=CAP_SYS_ADMIN"
		},
		"systemd specifier": func(config *Config) { config.InstallRoot = "/opt/%n" },
		"unclean path":      func(config *Config) { config.DataVolumeRoot = "/var/lib/../lib/terrascale" },
		"filesystem root":   func(config *Config) { config.InstallRoot = "/" },
		"long path":         func(config *Config) { config.DataVolumeRoot = longPath },
		"executable escape": func(config *Config) {
			config.ExecutablePath = "/opt/other/ts-node"
		},
		"wrong unit directory": func(config *Config) { config.UnitDirectory = "/tmp" },
		"alternate install root": func(config *Config) {
			config.InstallRoot = "/srv/terrascale"
			config.ExecutablePath = "/srv/terrascale/ts-node/current/ts-node"
		},
		"alternate data root": func(config *Config) { config.DataVolumeRoot = "/srv/terrascale-data" },
		"overlapping roots": func(config *Config) {
			config.DataVolumeRoot = "/opt/terrascale/data"
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := ProductionConfig()
			mutate(&config)
			if _, err := RenderSystemdUnit(config); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
}

func TestRendererReturnsRawUnitWithoutShellOrCloudInit(t *testing.T) {
	rendered, err := RenderSystemdUnit(ProductionConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"#cloud-config", "/bin/sh", "sh -c", "ExecStartPre="} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("renderer emitted forbidden wrapper %q", forbidden)
		}
	}
	if strings.Count(rendered, "ExecStart=") != 1 {
		t.Fatalf("unit must carry exactly one direct ExecStart:\n%s", rendered)
	}
}

func TestPrivilegeExceptionsStayNarrowAndOrdered(t *testing.T) {
	rendered, err := RenderSystemdUnit(ProductionConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{
		"CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_LINUX_IMMUTABLE\n",
		"AmbientCapabilities=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_LINUX_IMMUTABLE\n",
		"SecureBits=noroot-locked\n",
		"SystemCallFilter=@system-service\n",
		"ProtectProc=invisible\n",
		"PrivateDevices=yes\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
	} {
		if strings.Count(rendered, exact) != 1 {
			t.Fatalf("privilege directive %q is missing or duplicated", strings.TrimSpace(exact))
		}
	}
	for _, forbidden := range []string{
		"CAP_DAC_OVERRIDE", "CAP_KILL", "CAP_NET_ADMIN", "CAP_SETGID", "CAP_SETUID", "CAP_SYS_ADMIN", "AF_NETLINK", "AF_PACKET",
	} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("unit gained unneeded privilege %q", forbidden)
		}
	}
	writableEtc := strings.Index(rendered, "ReadWritePaths=/etc\n")
	readonlyConfig := strings.Index(rendered, "ReadOnlyPaths=/etc/terrascale\n")
	if writableEtc < 0 || readonlyConfig <= writableEtc {
		t.Fatal("the specific read-only config overlay must follow the useradd /etc write exception")
	}
	var writable []string
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, "ReadWritePaths=") {
			writable = append(writable, line)
		}
	}
	wantWritable := []string{
		"ReadWritePaths=/opt/terrascale",
		"ReadWritePaths=/var/lib/terrascale",
		"ReadWritePaths=/etc",
	}
	if strings.Join(writable, "\n") != strings.Join(wantWritable, "\n") {
		t.Fatalf("writable host paths drifted: %v", writable)
	}
}

func TestProductionConfigReturnsAnIndependentValue(t *testing.T) {
	first := ProductionConfig()
	first.User = "changed"
	if second := ProductionConfig(); second.User != "root" {
		t.Fatalf("production config was mutated: %+v", second)
	}
}
