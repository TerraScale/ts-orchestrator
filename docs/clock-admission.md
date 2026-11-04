# Clock discipline and TerraBase admission (PIVOT R12 / D21)

Every host installation runs `deploy/m1/host-runtime.sh`, including new hosts
created by `ts-orch region add`. It installs chrony, uses OCI's link-local NTP
server at `169.254.169.254`, enables RTC synchronization and waits for at most
30 seconds for the correction to fall below 10 ms. Setup fails if it cannot
synchronize. A step is permitted only during chrony's first three updates.

TerraBase reads the host kernel's NTP discipline state from its container and
compares wall time with peers over the mesh. Its routing fact refuses local
writes if the conservative error estimate exceeds 50 ms or becomes stale.
Existing host metrics include `ts_orch_host_clock_synchronized`,
`ts_orch_host_clock_offset_seconds` and `ts_orch_host_clock_max_error_seconds`.

TerraBase sends a bounded JSON request on `terrabase.clock.report`, inside its
existing scoped account permissions. A founder stores it in the `tb-clock-skew`
JetStream KV bucket through its existing fabric connection. TerraBase receives
`{"stored":true}` only after the KV write is acknowledged. No new permissions
or credentials are needed. Before the three-region JetStream quorum exists,
reports return `{"stored":false}` and TerraBase keeps measuring mesh peers.

The bucket keeps one report per node, expires reports after 15 seconds, caps
values at 4 KiB and total storage at 1 MiB, and has three replicas in distinct
regions. Consumers use the KV entry's server creation time for freshness, since
the reporting node's wall clock might be wrong. A missing or expired report
never grants local write permission.
