package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func nativeMeshJourney(ctx context.Context, cfg configuration, current, authority *process) error {
	name := "gru." + mesh.Domain
	client, conn, err := swarmruntime.DialControl(cfg.Work + "/a")
	if err != nil {
		return err
	}
	defer conn.Close()
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	if len(services.Services) != 0 {
		return errors.New("native certificate proof requires no app services")
	}
	if err := current.wait(ctx, "edge certificate installed name="+name+" ", 1); err != nil {
		return err
	}
	first, err := fingerprint(cfg, "10.77.0.2", name, false)
	if err != nil {
		return err
	}
	response, err := (&http.Client{}).Get("http://10.77.0.1:8088/native-renew")
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("native renewal authorization: HTTP %d", response.StatusCode)
	}
	if err := authority.wait(ctx, "issued "+name+" ", 2); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate installed name="+name+" ", 2); err != nil {
		return err
	}
	renewed, err := fingerprint(cfg, "10.77.0.2", name, false)
	if err != nil {
		return err
	}
	if first == renewed {
		return errors.New("native certificate did not renew")
	}
	counts, err := fetchCounts()
	if err != nil {
		return err
	}
	if counts[name] != 2 {
		return fmt.Errorf("native certificate orders: %d, want 2", counts[name])
	}
	services, err = client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	if len(services.Services) != 0 {
		return errors.New("native certificate issuance or renewal applied an app service")
	}
	for _, path := range []string{"/", "/healthz", "/orchestrator/observation"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.77.0.2"+path, nil)
		if err != nil {
			return err
		}
		request.Host = name + ":80"
		response, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			return fmt.Errorf("unrouted native HTTP path %s: HTTP %d", path, response.StatusCode)
		}
	}
	fmt.Println("PASS native mesh name: HTTP-01 issuance and renewal with zero app services, two CA authorizations, distinct verified TLS certificates; arbitrary HTTP paths remain 404")
	return nil
}
