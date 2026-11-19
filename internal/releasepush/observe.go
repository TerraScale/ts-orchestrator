package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/datamount"
	"github.com/nats-io/nats.go"
)

const ObservationPath = "/orchestrator/observation"

type Observation struct {
	Hosts          []HostVersion     `json:"hosts"`
	Running        map[string]string `json:"running"`
	Host           string            `json:"host"`
	DataMount      *datamount.Report `json:"data_mount,omitempty"`
	DataMountError string            `json:"data_mount_error,omitempty"`
	Version        string            `json:"version"`
	Health         string            `json:"health"`
	Ping           json.RawMessage   `json:"ping"`
	Images         map[string]string `json:"images"`
	Error          string            `json:"error,omitempty"`
}

func (o Observation) CheckImages() error {
	for service, desired := range o.Images {
		if !appregistry.SameDigest(o.Running[service], desired) {
			return fmt.Errorf("%s is not serving the desired digest: running %q, desired %q", service, o.Running[service], desired)
		}
	}
	return nil
}

func (h *Handler) Observe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := h.Verifier.VerifyMesh(r.Context(), token)
	if err != nil {
		claims, err = h.Verifier.Verify(r.Context(), token)
	}
	deployments := r.URL.Query().Get("view") == "deployments"
	if err != nil || deployments && claims.JobWorkflowRef != deployLagWorkflow {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	budget := 20 * time.Second
	if deployments {
		budget = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()
	if deployments {
		h.observeDeployments(ctx, w)
		return
	}
	if h.Mesh == nil || h.Health == nil {
		http.Error(w, "mesh unavailable", http.StatusServiceUnavailable)
		return
	}
	healthReply := h.health(ctx, nil)
	var health error
	if healthReply.Health != "ok" {
		health = errors.New(healthReply.Health)
	}
	ping, pingErr := h.Mesh(ctx, "ping", nil)
	data, stateErr := h.Mesh(ctx, "state", nil)
	running, readyErr := h.Mesh(ctx, "ready", nil)
	host, _ := os.Hostname()
	observation := Observation{Version: h.Revision, Host: host, DataMount: healthReply.DataMount, DataMountError: healthReply.DataMountError, Health: "ok", Ping: ping}
	if err := errors.Join(health, pingErr, stateErr, readyErr, json.Unmarshal(running, &observation.Running), json.Unmarshal(data, &observation.Images)); err != nil {
		observation.Health = "unhealthy"
		observation.Error = err.Error()
	}
	if h.Hosts != nil {
		hosts, err := h.Hosts(ctx)
		observation.Hosts = hosts
		if err != nil {
			observation.Health, observation.Error = "unhealthy", err.Error()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if observation.Health != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(observation)
}

func ReadObservation(ctx context.Context, region Region, token string) (Observation, error) {
	observation, status, err := fetchObservation(ctx, region, "", token)
	if err != nil {
		return observation, err
	}
	if status != http.StatusOK || observation.Health != "ok" || observation.Images == nil || observation.Running == nil {
		return observation, fmt.Errorf("%s: HTTP %d, health %s: %s", region.Region, status, observation.Health, observation.Error)
	}
	return observation, nil
}

func ReadHostObservation(ctx context.Context, region Region, address, token string) (Observation, error) {
	if net.ParseIP(address) == nil {
		return Observation{}, errors.New("host observation needs an IP address")
	}
	observation, _, err := fetchObservation(ctx, region, address, token)
	return observation, err
}

func meshURL(region, path string) string {
	return "https://" + region + ".mesh.terrascale.tech" + path
}

func fetchObservation(ctx context.Context, region Region, address, token string) (Observation, int, error) {
	endpoint := meshURL(region.Region, ObservationPath)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Observation{}, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if address != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(address, "443"))
		}
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	response, err := client.Do(request)
	if err != nil {
		return Observation{}, 0, err
	}
	defer response.Body.Close()
	var observation Observation
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&observation); err != nil {
		return Observation{}, response.StatusCode, fmt.Errorf("%s: HTTP %s: %w", region.Region, response.Status, err)
	}
	return observation, response.StatusCode, nil
}

type hostInventory struct {
	Hosts []HostVersion
	Error string
}

func inventorySubject(region string) string { return "ts.release.inventory." + region }

func (h *Handler) ServeInventory(conn *nats.Conn, region string) error {
	_, err := conn.QueueSubscribe(inventorySubject(region), "inventory", func(message *nats.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hosts, err := h.Hosts(ctx)
		reply := hostInventory{Hosts: hosts}
		if err != nil {
			reply.Error = err.Error()
		}
		data, err := json.Marshal(reply)
		if err == nil {
			_ = message.Respond(data)
		}
	})
	return err
}

func ReadInventory(ctx context.Context, conn *nats.Conn, region string) ([]HostVersion, error) {
	message, err := conn.RequestWithContext(ctx, inventorySubject(region), nil)
	if err != nil {
		return nil, err
	}
	var reply hostInventory
	if err := json.Unmarshal(message.Data, &reply); err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	return reply.Hosts, nil
}
