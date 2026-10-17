# Root OCI reader qualification

Obtain the shared QA lease before executing this scenario. No production key,
credential installation, cloud endpoint or host configuration is needed.

`TestRootReleaseChannelThroughSignedSDK` runs the real typed root backend,
current foundation discovery, root/grant signature verification, durable trust
floor and generated OCI SDK. A confined HTTPS service verifies each request's
RSA signature. The independent test ceremony signs actual foundation documents;
the test never constructs a sealed foundation or spending proof.

The three cases cover a current channel observation, a signed grant successor
arriving during the channel read, and cancellation after the channel request.
The latter two must return no observation. Channel data remains unsealed and
does not admit a binary release. Fleet, image, costs and ordinary
Unix peer authorization require their own scenarios.

`TestRootInventoryIncludesProtectedOriginalLiabilities` adds four serial cases:
an original protected financial commitment, missing protected history, a grant
successor during the read, and cancellation. It uses the same cryptographic
fixture and exact regional Identity, Compute and Search host allowlist. Search
requests have their body digest and signature checked; each query and family
list must name one of the five signed compartments. Missing history stays
pending; the result retains unbounded compartments and never gains a purchase
snapshot seal. The fixture does not qualify actual pool birth or retirement.

The test binary needs the public test genesis embedded in place of production's
public genesis. Go's overlay changes only the test build input; it does not edit
the production PEM or add a runtime trust override. The deterministic signing
seed is test-only and cannot sign anything accepted by a production binary.

After identity's typed Client/transport is integrated, prepare the overlay from
the repository root:

```bash
python3 - <<'PY'
import json
import pathlib
root = pathlib.Path.cwd()
overlay = {"Replace": {
    str(root / "internal/trust/bootstrap-root-002.pem"):
    str(root / "internal/rootociread/testdata/genesis.pem")
}}
pathlib.Path("/tmp/ts-rootociread-overlay.json").write_text(json.dumps(overlay))
PY
```

QA's bounded local invocation (the test process needs root, the compiler does
not; `sudo -n` must already be authorized):

```bash
nice -n 19 env GOMAXPROCS=2 GOFLAGS=-p=2 go test \
  -overlay=/tmp/ts-rootociread-overlay.json \
  -exec='sudo -n -- env GOMAXPROCS=2' \
  ./internal/rootociread \
  -run '^TestRootReleaseChannelThroughSignedSDK$' \
  -count=1 -parallel=1 -timeout=90s -v
```

Run only the selected root-reader scenarios in the overlay binary. The channel
scenario creates one loopback TLS server
per serial case, at most 32 signed requests per case and one temporary trust
floor. Each operation has a 20-second context. Runtime and memory envelopes
remain unmeasured until QA executes it.

For the inventory scenario, use selector
`^TestRootInventoryIncludesProtectedOriginalLiabilities$` and package timeout
`150s`. Its four serial cases each use one loopback TLS server, one temporary
trust floor, a 30-second operation context and at most 256 signed requests.
No broker, subprocess worker, production credentials or cloud endpoint is used.
