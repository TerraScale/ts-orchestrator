package releasepush

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	AnnouncePath   = "/orchestrator/release"
	announceBudget = 20 * time.Second
)

type Discovery struct {
	Region     string    `json:"region"`
	Owner      string    `json:"owner,omitempty"`
	Release    string    `json:"release,omitempty"`
	Seq        uint64    `json:"seq,omitempty"`
	Discovered time.Time `json:"discovered,omitzero"`
	Error      string    `json:"error,omitempty"`
}

func (h *Handler) Announce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := h.Verifier.Verify(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || claims.JobWorkflowRef != orchWorkflow {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.Discover == nil {
		http.Error(w, "release discovery unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), announceBudget)
	defer cancel()
	discovery, err := h.Discover(ctx)
	if err != nil {
		http.Error(w, "release discovery: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(discovery)
}

func Announce(ctx context.Context, client *http.Client, endpoint, token string) (Discovery, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return Discovery{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return Discovery{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return Discovery{}, err
	}
	if response.StatusCode != http.StatusOK {
		return Discovery{}, fmt.Errorf("%s: HTTP %s: %s", endpoint, response.Status, strings.TrimSpace(string(body)))
	}
	var discovery Discovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return Discovery{}, fmt.Errorf("%s: %w", endpoint, err)
	}
	if discovery.Error != "" {
		return discovery, fmt.Errorf("%s: the owner %s could not read the channel: %s", discovery.Region, discovery.Owner, discovery.Error)
	}
	return discovery, nil
}

func AnnounceChannel(ctx context.Context, region string, seq uint64, moved time.Time, output io.Writer) error {
	token, err := MintToken(ctx)
	if err != nil {
		return err
	}
	endpoint := meshURL(region, AnnouncePath)
	discovery, err := Announce(ctx, &http.Client{Timeout: announceBudget + 10*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint, token)
	if err != nil {
		return err
	}
	return Report(discovery, seq, moved, output)
}

func Report(discovery Discovery, seq uint64, moved time.Time, output io.Writer) error {
	switch {
	case discovery.Owner == "":
		_, err := fmt.Fprintf(output, "%s: no host owns the rollout now; its next owner reads the channel when it takes over\n", discovery.Region)
		return err
	case discovery.Seq < seq:
		return fmt.Errorf("%s: owner %s read channel seq %d (%s), not the published seq %d", discovery.Region, discovery.Owner, discovery.Seq, discovery.Release, seq)
	case moved.IsZero():
		_, err := fmt.Fprintf(output, "%s: owner %s holds channel seq %d (%s)\n", discovery.Region, discovery.Owner, discovery.Seq, discovery.Release)
		return err
	}
	_, err := fmt.Fprintf(output, "%s: owner %s discovered channel seq %d (%s) at %s, %s after the registry accepted it\n",
		discovery.Region, discovery.Owner, discovery.Seq, discovery.Release, discovery.Discovered.Format(time.RFC3339Nano), discovery.Discovered.Sub(moved).Round(time.Millisecond))
	return err
}
