package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
)

const hostMetadataFile = "host-metadata.json"
const hostMetadataWindow = 5 * time.Minute

func readHostMetadata(ctx context.Context, output io.Writer) (regionjoin.Instance, error) {
	window, cancel := context.WithTimeout(ctx, hostMetadataWindow)
	defer cancel()
	backoff := 250 * time.Millisecond
	var nextLog time.Time
	var lastErr error
	for {
		if err := window.Err(); err != nil {
			return regionjoin.Instance{}, errors.Join(lastErr, err)
		}
		instance, err := regionjoin.Local(window)
		if err == nil {
			err = validateHostMetadata(instance)
			if err == nil {
				return instance, nil
			}
		}
		lastErr = err
		if time.Now().After(nextLog) {
			fmt.Fprintf(output, "read host metadata: %v; retrying within startup window\n", err)
			nextLog = time.Now().Add(30 * time.Second)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-window.Done():
			timer.Stop()
			return regionjoin.Instance{}, errors.Join(lastErr, window.Err())
		case <-timer.C:
		}
		backoff = min(2*backoff, 5*time.Second)
	}
}

func storedHostMetadata(state string) (regionjoin.Instance, error) {
	data, err := os.ReadFile(filepath.Join(state, hostMetadataFile))
	if err != nil {
		return regionjoin.Instance{}, fmt.Errorf("read stored host metadata: %w", err)
	}
	var instance regionjoin.Instance
	if err := json.Unmarshal(data, &instance); err != nil {
		return regionjoin.Instance{}, fmt.Errorf("read stored host metadata: %w", err)
	}
	if err := validateHostMetadata(instance); err != nil {
		return regionjoin.Instance{}, err
	}
	for _, field := range []string{"board_asset_tag", "product_serial", "product_uuid"} {
		identity, err := os.ReadFile(filepath.Join("/sys/class/dmi/id", field))
		if err == nil && strings.TrimSpace(string(identity)) == instance.ID {
			return instance, nil
		}
	}
	return regionjoin.Instance{}, errors.New("stored host metadata instance ID does not match a network-independent firmware identity")
}

func validateHostMetadata(instance regionjoin.Instance) error {
	if _, ok := catalog.LookupName(instance.Region); !ok || strings.TrimSpace(instance.ID) == "" || net.ParseIP(instance.PrivateIP) == nil {
		return errors.New("host metadata has an invalid region, instance ID or private address")
	}
	return nil
}
