# PostgreSQL cancellation ownership

Raw CancelRequest is routed to its unique live backend-key owner across retained
admitted mesh regions. This supersedes the older runbook description of local
backend broadcasting. Lookup uses a digest; only the selected owner receives the
complete PID/secret pair, over mesh mTLS, with the live connection generation.

Missing, ambiguous, unavailable, stale or changed membership fails closed. Public
HTTP callers cannot access the control paths. Outgoing relays and incoming control
requests each have 32 slots, three-second deadlines and bounded bodies; the largest
dispatch body is 84 bytes. Discovery supports at most 32 admitted regions.

Legacy raw cancellation exposes its secret on the client-to-edge connection.
TLS cancellation classification and capacity reserved independently of normal
sessions are subsequent changes. These bounds establish neither a TerraBase
retained-memory envelope nor production cancellation qualification.
