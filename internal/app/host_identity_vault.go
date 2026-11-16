package app

// HostCredentialDirectory holds a host's enrollment identity and its
// credentials in memory (TS-745). host-setup's RuntimeDirectory outlives the
// oneshot, so the host agent reads the credentials host.json names. A reboot
// empties it: host-setup restores the identity from its Vault record and the
// credentials from the kept response. A pending renewal request is public
// (signed, public keys only) and stays beside host.json, so after a reboot
// host-setup replays exactly the request the controller may have committed.
const HostCredentialDirectory = "/run/terrascale-orchestrator-host-credentials"
