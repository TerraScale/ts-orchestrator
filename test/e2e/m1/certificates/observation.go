package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type observedInventory struct {
	Certificates []struct {
		Names       []string `json:"names"`
		KeyType     string   `json:"key_type"`
		Fingerprint string   `json:"fingerprint_sha256"`
		Valid       bool     `json:"valid"`
	} `json:"certificates"`
	MissingNames []string `json:"missing_names"`
	Errors       []string `json:"errors"`
}

func observationGet(address, path string) (int, []byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + address + path)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, data, err
}

func observationMetric(address, name string) (float64, error) {
	status, data, err := observationGet(address, "/edge/certificates/metrics")
	if err != nil || status != 200 {
		return 0, fmt.Errorf("metrics %s: status=%d error=%v body=%q", address, status, err, data)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			var value float64
			if _, err = fmt.Sscanf(fields[1], "%g", &value); err != nil {
				return 0, err
			}
			return value, nil
		}
	}
	return 0, fmt.Errorf("metric %s missing on %s", name, address)
}

func observationJourney(cfg configuration) error {
	for _, address := range []string{"10.77.0.2", "10.77.0.3"} {
		status, data, err := observationGet(address+":9108", "/edge/certificates")
		if err != nil || status != 200 {
			return fmt.Errorf("inventory %s: status=%d error=%v", address, status, err)
		}
		var inventory observedInventory
		if err = json.Unmarshal(data, &inventory); err != nil {
			return err
		}
		if len(inventory.MissingNames) != 0 || len(inventory.Errors) != 0 {
			return fmt.Errorf("inventory %s problems: %+v", address, inventory)
		}
		found := false
		for _, cert := range inventory.Certificates {
			if cert.Valid && containsName(cert.Names, "shared.e2e.test") && cert.KeyType == "ecdsa" {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("inventory %s omits the shared ECDSA certificate", address)
		}
		missing, err := observationMetric(address, "ts_edge_certificate_names_missing")
		if err != nil || missing != 0 {
			return fmt.Errorf("missing names metric %s: %g %v", address, missing, err)
		}
		if _, err = observationMetric(address, `ts_edge_autocert_orders_total{outcome="success"}`); err != nil {
			return fmt.Errorf("order metric %s: %v", address, err)
		}
		status, data, err = observationGet(address, "/edge/ready")
		if err != nil || status != 200 {
			return fmt.Errorf("readiness %s: status=%d error=%v body=%q", address, status, err, data)
		}
		var ready struct {
			Ready        bool     `json:"ready"`
			MissingNames []string `json:"missing_names"`
		}
		if err = json.Unmarshal(data, &ready); err != nil {
			return err
		}
		if !ready.Ready || len(ready.MissingNames) != 0 {
			return fmt.Errorf("readiness %s: %+v", address, ready)
		}
	}
	for _, node := range []string{"a", "b"} {
		cmd := exec.Command("ip", "netns", "exec", "cert-"+node, cfg.Binary, "edge", "certificates", "inventory", "local")
		data, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("inventory CLI %s: %v output=%s", node, err, data)
		}
		if !strings.Contains(string(data), "shared.e2e.test") {
			return fmt.Errorf("inventory CLI %s omitted the shared certificate: %s", node, data)
		}
	}
	if _, err := os.Stat(cfg.Work + "/a/edge-certs/shared.e2e.test"); err != nil {
		return err
	}
	fmt.Println("PASS fleet observation: inventory, readiness JSON, order metrics and the inventory CLI report the shared certificate on both nodes")
	return nil
}

func containsName(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}
