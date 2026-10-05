package cellscale

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRejectsTrailingValuesBeforeOCI(t *testing.T) {
	config := FileConfig{Cell: "gru-1", IntervalSeconds: 60, Endpoint: "http://{node}:9440", Policy: testPolicy(), Template: testTemplate()}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, trailing := range []string{"{}", "null", "1", "true", "garbage", "{"} {
		for _, command := range []string{"check", "run"} {
			t.Run(command+"/"+trailing, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "cell.json")
				if err := os.WriteFile(path, append(bytes.Clone(data), trailing...), 0o600); err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				if err := Run(t.Context(), []string{command, "--config", path}, &output); err == nil || output.Len() != 0 {
					t.Fatalf("invalid config reached execution: %v, output=%q", err, output.String())
				}
			})
		}
	}
	path := filepath.Join(t.TempDir(), "valid.json")
	if err := os.WriteFile(path, append(data, " \n\t"...), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"check", "--config", path}, &output); err != nil {
		t.Fatalf("valid whitespace rejected: %v", err)
	}
}

func TestConfigRejectsHostlessEndpointsBeforeOCI(t *testing.T) {
	for _, endpoint := range []string{"http:{node}", "http:///{node}", "https:{node}", "https:///{node}", "http://:9440/{node}"} {
		for _, command := range []string{"check", "run"} {
			t.Run(command+"/"+endpoint, func(t *testing.T) {
				config := FileConfig{Cell: "gru-1", IntervalSeconds: 60, Endpoint: endpoint, Policy: testPolicy(), Template: testTemplate()}
				data, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "cell.json")
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				if err := Run(context.Background(), []string{command, "--config", path}, &output); err == nil || !strings.Contains(err.Error(), "hostname") || output.Len() != 0 {
					t.Fatalf("hostless endpoint reached OCI setup: %v, output=%q", err, output.String())
				}
			})
		}
	}
	for _, endpoint := range []string{"http://{node}:9440", "https://gateway.example/{node}", "http://[::1]:9440/{node}"} {
		config := FileConfig{Cell: "gru-1", IntervalSeconds: 60, Endpoint: endpoint, Policy: testPolicy(), Template: testTemplate()}
		if err := config.Validate(); err != nil {
			t.Fatalf("valid endpoint %s rejected: %v", endpoint, err)
		}
	}
}
