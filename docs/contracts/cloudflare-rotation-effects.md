# Cloudflare capability rotation effects

`cloudflare.NewSnippetCapabilityStore` implements `security.SecretsStore` with
Cloudflare's supported Snippet source upload and content-read APIs. It does not
use Secrets Store CRUD as an activation protocol: Secrets Store has no numbered
version or activation endpoint, and no documented Snippet binding.

Build `ts-proxy` with `npm run build:snippet` to obtain the executable, unbound
`dist/snippet.template.js`. The production configuration supplies that file,
Cloudflare credentials, zone/account and Snippet name, the capability Vault,
fixed-owner `CheckEffectAuthority`, an existing R3 file-backed nonexpiring NATS
KV journal, and explicit HTTPS probe URLs plus their trusted HTTP transport.
Delivery supplies an artifact resolver and template service. `PromoteTemplate`
keeps the live ring while journaling the new verified template digest;
`ObserveTemplate` checks the rendered source, probes and enabled rule. Restarts
resolve the journaled template digest instead of restoring an older startup
file. Ordinary unbound Snippet uploads must not bypass this path.
No keys are written into the template artifact. The adapter resolves Vault
references and inserts the current/previous hex key ring into the template in
memory immediately before upload. Cloudflare necessarily stores the deployed
source; access to Snippet source is access to these keys.

Distribution publishes a staged ring: only the previous key serves reads, while
the new key answers authenticated generation probes. Activation publishes the
active ring, accepting current and bounded previous keys. Retirement publishes
only the current key after overlap expires. Rollback restores the previous key
only inside its lifetime, otherwise fences. A fenced ring denies reactive reads.
Expired or unbound deployments deny reads. No Worker runs on the reactive path.

The journal commits secret-free generation/key references, phase, source digest
and operation intent before mutation. After an uncertain upload, a retry reads
provider source identity before issuing another PUT. Every mutation requires a
fresh authority check. Verification checks provider source identity and a fresh
HMAC challenge at every configured ingress. The response binds nonce,
generation, phase and expiry to the current Vault key. Redirects are rejected;
responses and probes are not cached. Gate routing includes the probe path.

These are ingress observations, not proof that every Cloudflare point of
presence has converged. Cloudflare PUT has no global-lease precondition: an
already accepted request can complete after ownership changes. Local authority
checks and durable intent cannot provide atomic multi-region activation or
eliminate that provider race. Production qualification must retain this limit;
these effects do not satisfy an atomic publication proof by themselves.

Tests exercise the real supported provider HTTP shape, journal CAS/recovery,
probe authentication, and execution of the generated Snippet module with an
in-memory binding. They do not claim live Cloudflare propagation qualification.
