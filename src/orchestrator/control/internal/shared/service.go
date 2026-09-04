package shared

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/nats-io/nats.go"
)

// The service adapter maps the NATS micro-service protocol onto nats.go
// subscriptions. Endpoints are queue-grouped request handlers, and the $SRV
// discovery subjects return the standard micro-service wire shape.

type NatsSvcConfig struct {
	Name        string
	Version     string
	Description string
	Metadata    map[string]string
	QueueGroup  string
}

type NatsSvcEndpointConfig struct {
	Name       string
	Subject    string
	QueueGroup string
	Metadata   map[string]string
	Handler    func(context.Context, *nats.Msg) error
}

type NatsSvcServer struct {
	client        *nats.Conn
	config        NatsSvcConfig
	endpoints     []NatsSvcEndpointConfig
	subscriptions []*nats.Subscription
	started       bool
	mu            sync.Mutex
}

func NewNatsSvcServer(client *nats.Conn, config NatsSvcConfig) *NatsSvcServer {
	return &NatsSvcServer{client: client, config: config}
}

func (s *NatsSvcServer) AddEndpoint(config NatsSvcEndpointConfig) error {
	if s == nil {
		return errors.New("NATS service is unavailable.")
	}
	if config.Handler == nil {
		return errors.New("NATS service endpoint handler is required.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if config.QueueGroup == "" {
		config.QueueGroup = s.config.QueueGroup
	}

	s.endpoints = append(s.endpoints, config)
	return nil
}

func (s *NatsSvcServer) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("NATS service is unavailable.")
	}
	if ctx == nil {
		return errors.New("(Parameter 'ctx')")
	}
	if s.client == nil {
		return errors.New("NATS service client is unavailable.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return nil
	}

	for _, endpoint := range s.endpoints {
		endpoint := endpoint
		handler := func(message *nats.Msg) {
			if err := endpoint.Handler(ctx, message); err != nil {
				// The instrumentation wrapper at the call site records errors;
				// the service itself keeps serving.
				_ = err
			}
		}

		var subscription *nats.Subscription
		var err error
		if endpoint.QueueGroup != "" {
			subscription, err = s.client.QueueSubscribe(endpoint.Subject, endpoint.QueueGroup, handler)
		} else {
			subscription, err = s.client.Subscribe(endpoint.Subject, handler)
		}

		if err != nil {
			s.stopLocked()
			return err
		}

		s.subscriptions = append(s.subscriptions, subscription)
	}

	s.subscriptions = append(s.subscriptions, s.subscribeDiscovery("$SRV.PING")...)
	s.started = true
	return s.client.Flush()
}

func (s *NatsSvcServer) subscribeDiscovery(subject string) []*nats.Subscription {
	subscription, err := s.client.Subscribe(subject, func(message *nats.Msg) {
		_ = message.Respond(s.discoveryDocument())
	})
	if err != nil {
		return nil
	}

	return []*nats.Subscription{subscription}
}

type natsSvcEndpointInfo struct {
	Name       string            `json:"name"`
	Subject    string            `json:"subject"`
	QueueGroup string            `json:"queue_group"`
	Metadata   map[string]string `json:"metadata"`
}

type natsSvcDiscoveryDocument struct {
	Type        string                `json:"type"`
	Id          string                `json:"id"`
	Name        string                `json:"name"`
	Version     string                `json:"version"`
	Description string                `json:"description"`
	Endpoints   []natsSvcEndpointInfo `json:"endpoints"`
}

func (s *NatsSvcServer) discoveryDocument() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoints := make([]natsSvcEndpointInfo, 0, len(s.endpoints))
	for _, endpoint := range s.endpoints {
		endpoints = append(endpoints, natsSvcEndpointInfo{
			Name:       endpoint.Name,
			Subject:    endpoint.Subject,
			QueueGroup: endpoint.QueueGroup,
			Metadata:   endpoint.Metadata,
		})
	}

	document := natsSvcDiscoveryDocument{
		Type:        "io.nats.micro.v1.info_response",
		Id:          s.config.Name,
		Name:        s.config.Name,
		Version:     s.config.Version,
		Description: s.config.Description,
		Endpoints:   endpoints,
	}

	encoded, err := json.Marshal(document)
	if err != nil {
		return []byte("{}")
	}

	return encoded
}

// DiscoveryDocument returns the micro-service discovery document.
func (s *NatsSvcServer) DiscoveryDocument() []byte { return s.discoveryDocument() }

func (s *NatsSvcServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stopLocked()
}

func (s *NatsSvcServer) stopLocked() {
	for _, subscription := range s.subscriptions {
		_ = subscription.Drain()
	}

	s.subscriptions = nil
	s.started = false
}
