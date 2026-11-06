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

// RunBootstrapMaintenance is a client of the running admitted executor. It does
// not launch a second executor or synthesize a task outside Swarm dispatch.
func RunBootstrapMaintenance(ctx context.Context, args []string, out io.Writer) error {
	const usage = "usage: ts-orch bootstrap-maintenance <status|arm|stage|replace> --state DIR [--id ID --source-task TASK --target-image REF@sha256:DIGEST --owner NODE --epoch EPOCH]"
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
	var request swarmruntime.BootstrapRequest
	fs.StringVar(&request.ID, "id", "", "finite transaction ID")
	fs.StringVar(&request.SourceTask, "source-task", "", "current admitted source task ID")
	fs.StringVar(&request.TargetImage, "target-image", "", "green candidate immutable image")
	fs.StringVar(&request.Owner, "owner", "", "retained regional owner member")
	fs.Int64Var(&request.Epoch, "epoch", 0, "retained regional owner epoch")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(usage)
	}
	method := http.MethodPost
	var data []byte
	var err error
	switch action {
	case "status":
		method = http.MethodGet
	case "arm":
		data, err = protocol.EncodeJSON(request)
	case "stage", "replace":
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
