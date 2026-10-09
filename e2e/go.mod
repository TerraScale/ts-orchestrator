module terrascale.tech/ts-orchestrator/e2e

go 1.27.1

require terrascale.tech/sdk v0.0.0-20261009173424-f8f51d8a46c6

require github.com/oklog/ulid/v2 v2.1.2 // indirect

// Vanity discovery is not published yet; fetch the same pinned SDK from Forgejo.
replace terrascale.tech/sdk => git.terrascale.tech/TerraScale/ts-go v0.0.0-20261009173424-f8f51d8a46c6
