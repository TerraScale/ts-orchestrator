# GRU operational worker connection

The root derives operational worker connections from the admitted GRU global
NATS URL, NKey seed file and mTLS file references. It validates those files and
copies the resolved references before any listener starts. The provider factory
cannot supply or replace the connection. Binding to the global runtime checks
that its actual URL, identity and file references still match that admission.

Each ownership attempt captures bounded regular credential files through Unix
directory descriptors, rejecting symlinks and nonprivate seed/key permissions.
It parses the captured bytes once, requiring TLS 1.3, nonce signing by the admitted NKey,
verified server trust and a client certificate. Reconnect, initial retry and
publication buffering are disabled. DNS uses the context dialer. A cancellation callback closes setup sockets during
INFO and TLS waits, sharing the original absolute deadline with dialing. Its
callback is stopped or joined before transferring a successful connection; the
session supervisor then owns closing it.
The current file contents are loaded for each connection, but changing the
admitted NKey identity requires new static admission.

JWT credential-file mode remains supported by other NATS clients, but is not
supported for these operational sessions: all three journal adapters currently
require explicit NKey nonce-signing options. The root rejects that mode before
listeners, without dropping the JWT or falling back to another identity.
