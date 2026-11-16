package selfupdate

// HostSetupUnit enrolls a host before its host agent starts.
const HostSetupUnit = "terrascale-orchestrator-host-setup.service"

// MemoryPrepareMarker is written by every prepare that mounts the host's
// runtime secret directories, before it tries: its absence is the evidence
// that the prepare before a host start predates the mounts (TS-745).
const MemoryPrepareMarker = "/run/terrascale-orchestrator-memory-prepare"

// HostSetupDropin makes host-setup run the current release, the one the host
// agent runs, so an enrollment change ships with a rollout (TS-632); the
// image-baked binary runs it until prepare seeds a current release. It is
// deploy/systemd/selfupdate's copy byte for byte.
const HostSetupDropin = `# Binary-only A/B self-update (docs/continuous-delivery.md), installed by the
# image and by selfupdate prepare on a host whose image predates it.
[Service]
# First enrollment shares the private NetBird transaction lock with the worker.
StateDirectory=terrascale-orchestrator/netbird-managed
StateDirectoryMode=0700
# host-setup runs the current release, the one the host agent runs, so an
# enrollment change ships with a rollout; the image-baked binary runs it
# until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" host-setup --public-config /etc/terrascale-orchestrator/host-enrollment-public.json --output-root /etc/terrascale-orchestrator'
# The enrollment identity and credentials live in memory and outlive this
# oneshot for the host agent; host-setup restores the identity from Vault
# after a reboot (TS-745).
RuntimeDirectory=terrascale-orchestrator-host-credentials
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
`

// BootstrapUnit admits a controller install before the controller starts.
const BootstrapUnit = "terrascale-orchestrator-bootstrap.service"

// BootstrapDropin makes bootstrap admission run the current release, the one
// the controller runs, so a controller.json a newer release installed (a
// material generation, TS-668) is admitted at boot: the image-baked binary may
// refuse its members. The baked binary runs it until prepare seeds a current
// release. Only prepare installs it; the image does not carry it.
const BootstrapDropin = `# Binary-only A/B self-update (docs/continuous-delivery.md), installed by
# selfupdate prepare.
[Service]
# Bootstrap admission runs the current release, the one the controller runs,
# so a config a newer release installed is admitted at boot; the image-baked
# binary runs it until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" bootstrap-controller --config /etc/terrascale-orchestrator/controller.json'
# The credential directory is memory only: the same release rebuilds it from
# Vault first (TS-745), and admission waits until it can. Only a rolled-back
# release that lacks the command skips it.
ExecStartPre=
ExecStartPre=+/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; "$$b" --help 2>/dev/null | grep -q restore-controller-material || exit 0; exec "$$b" restore-controller-material'
`

// ControllerInstallUnit installs the root-signed controller configuration before admission.
const ControllerInstallUnit = "terrascale-orchestrator-controller-install.service"

// ControllerInstallDropin makes controller config installation run the current
// release, the one the controller runs, so an identity or config a newer
// release installed survives a reboot: the image-baked binary may refuse it.
// The baked binary runs it until prepare seeds a current release. Only prepare
// installs it; the image does not carry it.
const ControllerInstallDropin = `# Binary-only A/B self-update (docs/continuous-delivery.md), installed by
# selfupdate prepare.
[Service]
# Config installation runs the current release, the one the controller runs,
# so an identity or config a newer release installed survives a reboot; the
# image-baked binary runs it until prepare seeds a current release.
ExecStart=
ExecStart=/bin/sh -c 'b=/var/lib/terrascale-orchestrator/current/terrascale-orchestrator; [ -x "$$b" ] || b=/usr/local/bin/terrascale-orchestrator; exec "$$b" install-controller-config'
`
