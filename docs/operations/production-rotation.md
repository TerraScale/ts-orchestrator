# Production rotation composition

The production runtime's `global.rotation` declaration contains `issuer`,
`vault`, `members`, `reloaders`, `edge`, and `regions`. It is admitted before
provider clients open and constructed only inside the current GRU global lease.

`issuer` names an OCI region, compartment, certificate authority, and distinct
principals (`id`, `spiffe_id`, `control`). `vault` names an OCI region,
compartment, vault, and encryption key. Constructors use OCI instance principals;
these sections contain resource references, not credentials.

`members` and `reloaders` each contain endpoint declarations (`id`, `region`,
`url`) and absolute `certificate_file`, `private_key_file`, and
`trust_bundle_file` references. Every issuer principal must have exactly one
consumer of the correct class. Every declared region needs both classes. Region
codes are lowercase and the root declaration checks them against the estate.
The private key must be an owned private regular file. File reads are bounded
and reject symlink traversal.

`edge` contains exact `account_id`, `zone_id`, `token_file`, `template_file`,
`template_service` (`ts-proxy`), `snippet_name` (`ts-gate`), the typed Cloudflare
`zone`, `probe_urls`, `journal_bucket`, and `journal_key`. The token file is
private; the template is a bounded unbound artifact containing exactly one
capability deployment marker. The journal must already exist as a nonexpiring,
file-backed R3 NATS KV bucket. Construction does not create it.

Member requests carry the current authority epoch and lease ID. Cloudflare
requests recheck authority at every transport dispatch, including client
retries. The same Snippet capability store is returned to global release
promotion so template changes preserve the current and previous capability
ring. Mirrored artifacts and journal records contain no substituted keys.

These constructors and admission tests do not establish provider rollout or
worldwide propagation. Runtime verification requires actual provider readback
and authenticated generation responses from the declared probe ingresses.
