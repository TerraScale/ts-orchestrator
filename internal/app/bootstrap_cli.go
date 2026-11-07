package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// RunBootstrapMaintenance arms stopped hosts offline or talks to the admitted
// executor. It never launches another executor or synthesizes a task spec.
func RunBootstrapMaintenance(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: ts-orch bootstrap-maintenance <status|arm|arm-stopped|pins-offline|arm-offline|stage|prepull|owner|replace|clear> --state DIR [--root MOUNT] [--manifest FILE | --id ID --source-task TASK --target-image REF@sha256:DIGEST --owner NODE --epoch EPOCH]"
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(out, usage)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("bootstrap-maintenance requires root")
	}
	action := args[0]
	fs := flag.NewFlagSet("bootstrap-maintenance", flag.ContinueOnError)
	fs.SetOutput(out)
	state := fs.String("state", "/var/lib/ts-orch", "local executor state directory")
	manifest := fs.String("manifest", "", "captured cold bootstrap pins; arm-stopped and arm-offline only")
	root := fs.String("root", "", "a stopped host's boot volume mounted on its founder; offline actions only")
	var request swarmruntime.BootstrapRequest
	fs.StringVar(&request.ID, "id", "", "finite transaction ID")
	fs.StringVar(&request.SourceTask, "source-task", "", "current admitted source task ID")
	fs.StringVar(&request.TargetImage, "target-image", "", "green candidate immutable image")
	fs.StringVar(&request.Owner, "owner", "", "retained regional owner member")
	fs.Int64Var(&request.Epoch, "epoch", 0, "retained regional owner epoch")
	peer := fs.String("node", "", "clear only: an admitted regional peer whose verified fence to clear")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(usage)
	}
	if action == "pins-offline" || action == "arm-offline" {
		if *root == "" {
			return errors.New("--root is required for offline actions")
		}
		if action == "pins-offline" {
			pin, err := swarmruntime.OfflinePins(*root, *state)
			if err != nil {
				return err
			}
			data, err := protocol.EncodeJSON(pin)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "%s\n", data)
			return err
		}
		input, err := readColdManifest(*manifest)
		if err != nil {
			return err
		}
		return swarmruntime.ArmOfflineColdBootstrap(ctx, *root, *state, input)
	}
	if *root != "" {
		return errors.New("--root is only valid for offline actions")
	}
	if action == "arm-stopped" {
		input, err := readColdManifest(*manifest)
		if err != nil {
			return err
		}
		return swarmruntime.ArmColdBootstrap(ctx, *state, input)
	}
	if *manifest != "" {
		return errors.New("manifest is only valid for arm-stopped and arm-offline")
	}
	method := http.MethodPost
	var data []byte
	var err error
	switch action {
	case "status":
		method = http.MethodGet
	case "arm":
		data, err = protocol.EncodeJSON(request)
	case "clear":
		data, err = protocol.EncodeJSON(struct {
			ID   string `json:"id"`
			Node string `json:"node,omitempty"`
		}{request.ID, *peer})
	case "stage", "replace", "owner", "prepull":
		data, err = protocol.EncodeJSON(struct {
			ID string `json:"id"`
		}{request.ID})
	default:
		return errors.New(usage)
	}
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", swarmruntime.BootstrapSocket(*state))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 65 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://executor/"+action, bytes.NewReader(data))
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return err
	}
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("bootstrap %s HTTP %d: %s", action, response.StatusCode, body)
	}
	_, err = out.Write(body)
	return err
}

func readColdManifest(path string) (swarmruntime.ColdBootstrap, error) {
	var input swarmruntime.ColdBootstrap
	file, err := os.Open(path)
	if err != nil {
		return input, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return input, err
	}
	return input, protocol.DecodeStrict(data, &input, 64<<10)
}
