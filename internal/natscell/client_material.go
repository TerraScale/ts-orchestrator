package natscell

// ClientMaterial names the credential files a client presents when it dials.
type ClientMaterial struct {
	CredentialsFile string
	TLS             TLSFiles
}
