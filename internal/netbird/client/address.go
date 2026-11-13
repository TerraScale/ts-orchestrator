package client

import (
	"errors"
	"net"
)

func Address() (string, error) {
	iface, err := net.InterfaceByName("wt0")
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.To4().String(), nil
		}
	}
	return "", errors.New("wt0 has no IPv4 address")
}
