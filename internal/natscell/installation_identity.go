package natscell

// InstallationIdentity is measured from signed broker claims and existing disk
// pins. Configuration declarations alone cannot authorize opening an old store.
type InstallationIdentity struct {
	Operator, SystemAccount, CellAccount, HostSigner, RoleSigner, AccountSigner, InterRegionAccount string
	Directory, ServerName, RaftNodeID, ServerNameSHA256, NodeIdentitySHA256                         string
}
