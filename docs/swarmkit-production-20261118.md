# SwarmKit production review, 2026-11-18

Read-only review of gru, sjc and fra from an operator host (C2). No production
state was changed.

## Access that works today

- Managers: OpenSSH on the NetBird address (`ssh ts-<region>-1`, user `ubuntu`),
  then `sudo -n ts-orch status`, `member ls`, `service ls`, `events`.
- Dashboard API of every region: `ts-orch observe cluster --url
  http://<ts-<region>-1 NetBird IP>:9463 --token-file FILE`, with FILE (mode
  0600) holding `<region>-1-orch-dashboard-token` from the shared gru Vault.
  The default `ts-orch observe` access reads a signed foundation anchor from
  bucket `gru-1-head`, which the `ts-orch node` runtime never creates, so it
  stays "access pending". Only `cluster`, `events`, `snapshot`, `history` and
  `metrics` are served by the node dashboard.
- Workers: none. OpenSSH accepts no operator key and the NetBird SSH server
  was off on every server since C4 deleted the enrollment settings, so
  `ts-orch netbird ssh` and `ts-orch log-scan` failed on every node.

## Causes found

| Symptom | Cause | Fix |
|---|---|---|
| `netbird-server.service` failing with `invalid arguments`, ~700 restarts per 2 h on every manager | C16e changed the unit's arguments; pull releases replace only the binary | Release preflight stores each binary's `netbird-server.service` under `/var/lib/ts-orch/units/<sha>.netbird-server.service`; the privileged `ExecStartPre=+` of `ts-orch.service` installs it, reloads and restarts the companion |
| `log-scan`, `netbird ssh`: no node readable | NetBird enrollment no longer passes `--allow-server-ssh` and its siblings | `netbird server` re-applies the server SSH settings |
| `ts-orch observe` pending everywhere | foundation discovery reads `gru-1-head`, absent in production | open: needs a decision on the observe access path |
| fra stalls, gru waits for fra | ts-fra-2 runs d360f05de, which cannot decode the current pull request (`unknown object member name "seq"`) and cannot reach the channel release | open: no operator path reaches ts-fra-2 |
| gru TerraBase 0/2 on the new digest | writer handoff loop (C49), gru runs 90c536aa3 without C50 | C50/C51; gru gets C50 once fra unblocks the release |
