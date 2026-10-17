# Isolated OCI SDK qualification snapshot

This isolated source closure replaces `github.com/oracle/oci-go-sdk/v65` with
`./third_party/oci-go-sdk`. It is prepared for independent compile and local
protocol qualification; it is not canonical dependency adoption or deployment.

The snapshot contains exactly 2,316 runtime files and 13,636,266 bytes copied
from the independently reviewed candidate. `patched-runtime-files.json` records
every path, byte count and SHA256; `upstream-runtime-files.json` records the
corresponding original bytes. `copy-files.txt` enumerates the copied paths and
`omitted-upstream-tests-assets.json` records excluded upstream test sources and
assets. The six upstream root licenses/manifests are preserved unchanged.

Runtime bytes match SDK review commit
`ac33f551c7cda13cf756f0bcb298c4249e0e1599`, tree
`a09744b5cdc6f9fb251f7a0e28dc77309b45fd46`, and production predecessor
`d300a4c2b00164c09d0b8eea37895b8bf2567157`. The project API/protocol donor is
`41e07d59e43c37ab3f3bb2a4a67488fbe652b9af`, tree
`7fb69b30927c6bf6b581df23cef23c356654b1ff`. Both runtime and separate upstream
fixture patches remain in the parent directory; its provenance retains their
original source-only status. This document describes the later isolated staging
step and does not replace that provenance.

Project `internal/ociclient/instance_principal_test.go` exercises production SDK
methods across controlled local IMDS HTTP and federation/Secrets TLS. Upstream
SDK tests remain outside the production snapshot, with their reviewed patch
retained separately. No Go CLI, compiler, test, runtime or cloud operation was
executed during source staging. Independent QA must authorize exact compilation
and later protocol execution separately.
