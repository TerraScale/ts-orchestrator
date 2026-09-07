package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
)

type productionMembershipRevocationsFile struct {
	Endpoint       string `json:"endpoint"`
	Audience       string `json:"audience"`
	ServiceKeyFile string `json:"service_key_file"`
}

func (f productionMembershipRevocationsFile) Construct(store *cloudflare.SnippetCapabilityStore, authorize func(context.Context) error) (*cloudflare.MembershipRevocationPublisher, error) {
	key, err := bootstrapcredentials.ReadFile(f.ServiceKeyFile, true, 4096)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return cloudflare.NewMembershipRevocationPublisher(cloudflare.MembershipRevocationPublisherConfig{Endpoint: f.Endpoint, Audience: f.Audience, ServiceKey: strings.TrimSpace(string(key)), Store: store, Authorize: authorize, HTTPClient: &http.Client{Timeout: 20 * time.Second}})
}
