package netbird

// LocalStatus is the non-secret subset of the running daemon's status.
type LocalStatus struct {
	Version    string `json:"daemonVersion"`
	State      string `json:"daemonStatus"`
	IP         string `json:"netbirdIp"`
	FQDN       string `json:"fqdn"`
	Management struct {
		URL       string `json:"url"`
		Connected bool   `json:"connected"`
	} `json:"management"`
	Signal struct {
		Connected bool `json:"connected"`
	} `json:"signal"`
}
