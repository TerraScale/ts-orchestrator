package manager

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

const maxPATFileBytes = 4 << 10

// Commands lists the subcommands Run handles.
var Commands = []string{"sync", "prune-peers", "inventory"}

const usage = `Usage:
  ts-orch netbird sync [--apply] [--pat-file FILE] [--management-url URL]
  ts-orch netbird prune-peers [--apply] [--offline-for 24h] [--pat-file FILE] [--management-url URL]
  ts-orch netbird inventory [--pat-file FILE] [--management-url URL]

Without --apply, sync and prune-peers print the planned changes only. The
admin PAT comes from --pat-file (a regular owner-only file) or NB_PAT.
`

// Run executes one manager subcommand.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(stdout, usage)
		return err
	}
	command := args[0]
	flags := flag.NewFlagSet("netbird "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	patFile := flags.String("pat-file", "", "file holding the NetBird admin PAT")
	managementURL := flags.String("management-url", DefaultManagementURL, "NetBird management origin")
	var apply *bool
	var offlineFor *time.Duration
	switch command {
	case "sync":
		apply = flags.Bool("apply", false, "apply the changes")
	case "prune-peers":
		apply = flags.Bool("apply", false, "apply the changes")
		offlineFor = flags.Duration("offline-for", DefaultOfflineFor, "delete unattributed server peers offline this long")
	case "inventory":
	default:
		return fmt.Errorf("unknown netbird command %q", command)
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(stdout, usage)
			return err
		}
		return fmt.Errorf("netbird %s: %w", command, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("netbird %s accepts no positional arguments", command)
	}
	if offlineFor != nil && *offlineFor < time.Hour {
		return errors.New("netbird prune-peers --offline-for must be at least 1h")
	}
	token, err := readToken(*patFile)
	if err != nil {
		return err
	}
	api, err := NewAPI(*managementURL, string(token))
	clear(token)
	if err != nil {
		return err
	}
	defer api.Close()
	switch command {
	case "inventory":
		inventory, err := ReadInventory(ctx, api)
		if err != nil {
			return err
		}
		return json.MarshalWrite(stdout, inventory, jsontext.WithIndent("  "))
	case "sync":
		report, err := Sync(ctx, api, GRU(), *apply)
		writeReport(stdout, report, *apply)
		return err
	default:
		report, err := Prune(ctx, api, GRU(), PruneOptions{OfflineFor: *offlineFor}, *apply)
		writeReport(stdout, report, *apply)
		return err
	}
}

func writeReport(out io.Writer, report Report, applied bool) {
	prefix := "plan: "
	if applied {
		prefix = "applied: "
	}
	for _, change := range report.Changes {
		fmt.Fprintln(out, prefix+change.String())
	}
	for _, warning := range report.Warnings {
		fmt.Fprintln(out, "warning: "+warning)
	}
	switch {
	case len(report.Changes) == 0:
		fmt.Fprintln(out, "no changes")
	case !applied:
		fmt.Fprintf(out, "%d changes planned; rerun with --apply to apply them\n", len(report.Changes))
	}
}

// readToken reads the PAT from an owner-only regular file, refusing
// symlinks, or from NB_PAT.
func readToken(path string) ([]byte, error) {
	if path == "" {
		token := strings.TrimSpace(os.Getenv("NB_PAT"))
		if token == "" {
			return nil, errors.New("NetBird admin PAT is required: use --pat-file or NB_PAT")
		}
		return []byte(token), nil
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open the NetBird PAT file (symlinks are refused)")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect the NetBird PAT file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("NetBird PAT file must be a regular file owned by you with mode 0600")
	}
	if info.Size() > maxPATFileBytes {
		return nil, errors.New("NetBird PAT file is too large")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxPATFileBytes+1))
	if err != nil || len(wire) > maxPATFileBytes {
		clear(wire)
		return nil, errors.New("cannot read the NetBird PAT file")
	}
	token := bytes.Clone(bytes.TrimSpace(wire))
	clear(wire)
	if len(token) == 0 {
		return nil, errors.New("NetBird PAT file is empty")
	}
	return token, nil
}
