# TerraScale seccomp profile

`terrascale-default-v1.json` is based on the Podman default profile from
`containers/common` v0.64.2. The upstream file is Apache-2.0 licensed.

TerraScale removes `getppid` from the allow list. The syscall is a harmless
sentinel used by the live test to prove the kernel loaded this exact profile.
The runtime verifies the file's SHA-256 digest before preflight and before
every container create. The expected digest is
`52f89c2c6abbd08f091c1ec332b29f4d0ab28cf580e9d229bc516741f07025a1`.

The runtime also checks every path component with `lstat`. It rejects symbolic
links, a non-regular or oversized profile, group or other write permissions,
and ownership outside root or the node account. Do not replace this file with
a permissive development profile. A different byte sequence fails admission.
