package messaging

// NatsProtocolPackageBytes mirrors NatsProtocolPackage.Bytes: the immutable
// canonical protocol package the controller compares against the object-store
// copy.
var NatsProtocolPackageBytes = []byte(`{"name":"terrascale-orchestrator","protocol":2}`)
