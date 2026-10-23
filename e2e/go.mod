module terrascale.tech/ts-orchestrator/e2e

go 1.27.3

require terrascale.tech/sdk v0.0.0-20261013114332-6a9d69c9c2aa

require github.com/oklog/ulid/v2 v2.1.2 // indirect

// Vanity discovery is not published yet; fetch the same pinned SDK from GitHub.
replace terrascale.tech/sdk => github.com/TerraScale/ts-go v0.0.0-20261013114332-6a9d69c9c2aa
