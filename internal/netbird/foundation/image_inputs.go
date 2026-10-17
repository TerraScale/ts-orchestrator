package foundation

import "errors"

// PinnedComponentImages returns the qualified server, dashboard, and ingress images, in that order.
func PinnedComponentImages(architecture string) ([]string, error) {
	var server, dashboard, ingress string
	switch architecture {
	case "arm64":
		server = "4ef9ce41c29a62b864805c948a1bcb173d4b909d72a581853ffb29743ac6f9ee"
		dashboard = "44a250c04d91b46aa666de4b2b25602f0580b64dee0682fedfb9d012cb020ff7"
		ingress = "8dbca3525dd8dce671e495665a0eb297a83ec87ee30f373947d0ea93115949db"
	case "amd64":
		server = "8eb63a41f572bd11a160c8444d9dbd7178dd1de71965f848cf788991a58a6c16"
		dashboard = "86f5fbb16c5bae1918dc2f09da6182144c30e45ecf75d7902038743094e7bdcd"
		ingress = "d8c17a862962def15cde69863a3a463f25a2664942eafd7bdbf050e9c3116b83"
	default:
		return nil, errors.New("NetBird foundation requires qualified arm64 or amd64 upstream components")
	}
	return []string{"docker.io/netbirdio/netbird-server@sha256:" + server, "docker.io/netbirdio/dashboard@sha256:" + dashboard, "docker.io/library/caddy@sha256:" + ingress}, nil
}
