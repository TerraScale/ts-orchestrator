package netbird

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
)

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

// Status queries the daemon, rather than the installed CLI version. Raw daemon
// output and subprocess errors are discarded because they may contain secrets.
func Status(ctx context.Context) (LocalStatus, error) {
	e := enroller{run: runCommand}
	wire, err := e.command(ctx, "status", "--json", "--config", netbirdConfig)
	defer clear(wire)
	if err != nil {
		return LocalStatus{}, errors.New("cannot query running NetBird status")
	}
	var status LocalStatus
	if len(wire) > 1<<20 || json.Unmarshal(wire, &status) != nil {
		return LocalStatus{}, errors.New("NetBird daemon returned invalid status JSON")
	}
	status.Version = strings.TrimPrefix(strings.TrimSpace(status.Version), "v")
	status.Management.URL, _ = normalizeManagerURL(status.Management.URL)
	return status, nil
}
