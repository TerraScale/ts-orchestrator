package bootstrap

import (
	"crypto/tls"
)

type countingTLSConfigProvider struct {
	calls   int
	changed bool
}

func (provider *countingTLSConfigProvider) NewOrDefault() (*tls.Config, error) {
	provider.calls++
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

func (provider *countingTLSConfigProvider) WatchedFilesModified() bool {
	return provider.changed
}
