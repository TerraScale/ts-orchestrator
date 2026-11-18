package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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

func validateHostMetadata(instance regionjoin.Instance) error {
	if _, ok := catalog.LookupName(instance.Region); !ok || strings.TrimSpace(instance.ID) == "" || net.ParseIP(instance.PrivateIP) == nil {
		return errors.New("host metadata has an invalid region, instance ID or private address")
	}
	return nil
}
