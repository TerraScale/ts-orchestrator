# Independent remote plan-pin reads

`transitionreceipts.ReadPlanPins` and the operator command
`check-storage-plan-pins` now collect signed host acknowledgements through OCI
Object Storage reads without NATS. Exact object keys, regional bucket identity,
projected ownership-observation digests, metadata, bytes and host signatures are
verified before returning the complete live-plan proof.

The test starts a real local HTTP server and sends requests through the existing
OCI HTTP transport, request signer and bounded Object Storage reader. Only the
test transport remaps fixed OCI endpoints to that server. The fixture records
methods and request hosts and checks the OCI signature header. ECDSA host
receipt signatures are verified by the production plan verifier.

Coverage includes shared source/GRU and separate GRU destination inventories,
ordered receipt digests, the complete command composition and JSON summary,
strict command arguments/input, missing receipts, ownership changes before and
after reads, wrong-host receipts, altered receipt bytes, mismatching metadata,
oversized and truncated bodies, future receipts, redirects, cancellation,
incorrect regional transports, and incomplete output writes. Invalid collections
return no verified proof; missing remote evidence emits no command success
summary. Invalid scope/input checks make no HTTP requests.

The fixtures use synthetic plans and signed receipt claims. They do not prove
actual host journal persistence, live OCI behavior, automatic upload, provider
IAM, current destination health, a complete preparation barrier, or R3 promotion.
The independent reader is implemented; host publication and transition-executor
composition remain unfinished. Focused race and portable check logs accompany
this record.
