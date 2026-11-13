package m1

const ReleaseGuardService = `[Unit]
Description=Recover an unconfirmed orchestrator release

[Service]
Type=oneshot
ExecStart=/usr/local/bin/terrascale-orchestrator release guard
TimeoutStartSec=45s
`

const ReleaseGuardTimer = `[Unit]
Description=Check orchestrator release recovery deadline

[Timer]
OnBootSec=15s
OnUnitActiveSec=1min
AccuracySec=1s
Unit=ts-orch-release-guard.service

[Install]
WantedBy=timers.target
`
