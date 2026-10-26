# PostgreSQL edge connection capacity

Each edge listener admits at most 1,024 normal sessions, including backend dials,
and 32 connections being classified or completing handshakes. Excess accepts close
immediately; classified excess normal sessions receive `53300` when possible.
Raw and TLS CancelRequest use classification capacity independently of normal
sessions. A full classification pool can still reject cancellation.

Handshake/classification has a ten-second deadline. Refusal cleanup drains at most
64 KiB within that deadline. Established edge sessions have no idle timeout here.
These are count and refusal bounds; they do not establish a total memory envelope
or TerraBase active/idle limits. Public cancellation still requires live qualification.
