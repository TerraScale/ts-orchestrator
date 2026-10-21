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
var Commands = []string{"sync", "prune-peers", "remove-peers", "setup-key", "inventory", "image-input", "server"}

const usage = `Usage:
  ts-orch netbird sync [--apply] [--only NAME]... [--pat-file FILE] [--management-url URL]
  ts-orch netbird prune-peers [--apply] [--offline-for 24h] [--pat-file FILE] [--management-url URL]
  ts-orch netbird remove-peers (--slot NAME... | --all) [--apply] [--pat-file FILE] [--management-url URL]
  ts-orch netbird setup-key --out FILE [--servers-group GROUP] [--apply] [--pat-file FILE] [--management-url URL]
  ts-orch netbird inventory [--pat-file FILE] [--management-url URL]
  ts-orch netbird image-input --plan PLAN --setup-key-secret-id OCID --out FILE
  ts-orch netbird server --vault-id OCID --key-id OCID --compartment-id OCID --dir DIR

Without --apply, sync, prune-peers, remove-peers and setup-key print the
planned changes only. remove-peers deletes the disconnected server peers of
decommissioned slots. setup-key creates the servers' setup key and writes its
value to a new owner-only file; --servers-group names another region's servers
group (sfo-servers), whose key carries that name. The admin PAT comes from --pat-file (a regular
owner-only file) or NB_PAT. image-input writes a region's image netbird.json
(new file FILE) from its regional plan and the Vault secret holding its
servers' setup key; it needs no PAT and makes no call.
`

// Run executes one manager subcommand.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(stdout, usage)
		return err
	}
	command := args[0]
	if command == "server" {
		return runServer(ctx, args[1:], stdout)
	}
	flags := flag.NewFlagSet("netbird "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	patFile := flags.String("pat-file", "", "file holding the NetBird admin PAT")
	managementURL := flags.String("management-url", DefaultManagementURL, "NetBird management origin")
	var apply, all *bool
	var offlineFor *time.Duration
	var out, serversGroup, plan, secretID *string
	var slots, only []string
	switch command {
	case "sync":
		apply = flags.Bool("apply", false, "apply the changes")
		flags.Func("only", "plan and apply only the changes to this object (repeatable)", func(value string) error {
			only = append(only, value)
			return nil
		})
	case "prune-peers":
		apply = flags.Bool("apply", false, "apply the changes")
		offlineFor = flags.Duration("offline-for", DefaultOfflineFor, "delete unattributed server peers offline this long")
	case "remove-peers":
		apply = flags.Bool("apply", false, "apply the changes")
		all = flags.Bool("all", false, "remove every disconnected server peer")
		flags.Func("slot", "remove the disconnected peers of this slot (repeatable)", func(value string) error {
			slots = append(slots, value)
			return nil
		})
	case "setup-key":
		apply = flags.Bool("apply", false, "create the key")
		out = flags.String("out", "", "new owner-only file that receives the key value")
		serversGroup = flags.String("servers-group", "", "servers group the key auto-assigns (default the GRU servers group)")
	case "inventory":
	case "image-input":
		plan = flags.String("plan", "", "reviewed regional plan")
		secretID = flags.String("setup-key-secret-id", "", "OCI Vault secret holding the servers' setup key")
		out = flags.String("out", "", "new file that receives the image input")
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
	if all != nil && *all == (len(slots) > 0) {
		return errors.New("netbird remove-peers needs either --slot or --all")
	}
	if out != nil && *out == "" {
		return fmt.Errorf("netbird %s requires --out", command)
	}
	if plan != nil {
		if *plan == "" || *secretID == "" {
			return errors.New("netbird image-input requires --plan and --setup-key-secret-id")
		}
		return writeImageInput(*plan, *secretID, *out)
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
		report, err := Sync(ctx, api, GRU(), *apply, only...)
		writeReport(stdout, report, *apply, err)
		return err
	case "prune-peers":
		report, err := Prune(ctx, api, GRU(), PruneOptions{OfflineFor: *offlineFor}, *apply)
		writeReport(stdout, report, *apply, err)
		return err
	case "remove-peers":
		report, err := Remove(ctx, api, GRU(), slots, *apply)
		writeReport(stdout, report, *apply, err)
		return err
	case "setup-key":
		desired := GRU()
		if *serversGroup != "" {
			desired.ServersGroup, desired.SetupKeyName = *serversGroup, *serversGroup
		}
		report, err := createSetupKeyFile(ctx, api, desired, *out, *apply)
		writeReport(stdout, report, *apply, err)
		return err
	default:
		return fmt.Errorf("unknown netbird command %q", command)
	}
}

// createSetupKeyFile creates the file before the key, so a refused path
// never leaves an unsaved key behind, and removes it when the run fails.
func createSetupKeyFile(ctx context.Context, api *API, d Desired, path string, apply bool) (Report, error) {
	if !apply {
		return CreateServerSetupKey(ctx, api, d, io.Discard, false)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return Report{}, fmt.Errorf("cannot create the setup key file: %w", err)
	}
	report, err := CreateServerSetupKey(ctx, api, d, file, true)
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("setup key file was not saved, revoke the new key: %w", closeErr)
	}
	if err != nil {
		os.Remove(path)
	}
	return report, err
}

// writeReport prints the changes a run planned or applied, including a
// partial report from a failed run, and a summary only when the run succeeded.
func writeReport(out io.Writer, report Report, applied bool, runErr error) {
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
	case runErr != nil:
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
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("cannot open the NetBird PAT file: symlinks are refused")
		}
		return nil, errors.New("cannot open the NetBird PAT file")
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
