// Package logscan counts the warnings and errors TerraScale's services
// logged recently, per service and node: ts-orchestrator (controller, host
// agent, embedded NATS) and the TerraBase and ts-auth members it runs, read
// from each node's journal over NetBird SSH. COS runs it every check; the
// goal is zero.
package logscan

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/logs"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
)

const usage = `Usage: ts-orch log-scan --vault-id OCID [--netbird COMMAND] [--since 20m] [--top 10] [--node NAME]...

Counts WARN and ERROR records per service and node over the last --since.
Without --node it reads every server the NetBird client lists: each peer
named like a cell node or server (ts-gru-1, gru-1-ctl-1). Each node is read
from its journal (units terrascale-orchestrator*: the
controller, the host agent, embedded NATS and the TerraBase and ts-auth
members) over "ts-orch netbird ssh" as the automation user, with the same
--vault-id and --netbird. Then lists the --top most frequent classes. Exits
unsuccessfully when a node cannot be read.
`

// Record is one warning or error.
type Record struct {
	Service, Level, Class string
}

// Fetchers read the logs; tests replace them.
type Fetchers struct {
	Node func(ctx context.Context, node, command string) ([]byte, error)
}

type names []string

func (n *names) String() string     { return strings.Join(*n, ",") }
func (n *names) Set(s string) error { *n = append(*n, s); return nil }

// Run executes ts-orch log-scan.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("log-scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	vaultID := flags.String("vault-id", "", "the Vault OCID holding the NetBird automation login")
	netbird := flags.String("netbird", "netbird", "the NetBird client command, split on spaces")
	since := flags.Duration("since", 20*time.Minute, "how far back to read")
	top := flags.Int("top", 10, "how many classes to list")
	var nodes names
	flags.Var(&nodes, "node", "a NetBird peer name to read, repeatable")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(stdout, usage)
			return err
		}
		return fmt.Errorf("log-scan: %w", err)
	}
	if flags.NArg() != 0 || *since < time.Second {
		return errors.New("log-scan needs a --since of at least 1s and no positional arguments")
	}
	if len(nodes) == 0 {
		peers, err := sshlogin.Peers(ctx, *netbird)
		if err != nil {
			return fmt.Errorf("log-scan: list the nodes: %w", err)
		}
		nodes = Servers(peers)
	}
	fetch := Fetchers{
		Node: func(ctx context.Context, node, command string) ([]byte, error) {
			var out, diagnostics bytes.Buffer
			err := sshlogin.Session(ctx, *vaultID, *netbird, []string{"root@" + node, command}, nil, &out, &diagnostics)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", err, lastLine(diagnostics.String()))
			}
			return out.Bytes(), nil
		},
	}
	return Scan(ctx, stdout, nodes, *since, *top, time.Now(), fetch)
}

// Servers are the peers named like a cell's node or server, sorted.
func Servers(peers map[string]string) []string {
	var servers []string
	for name := range peers {
		// A cell name (gru-1) is valid too but names no server.
		if !strings.Contains(name, ".") && strings.Count(name, "-") > 1 && naming.Validate(name) == nil {
			servers = append(servers, name)
		}
	}
	slices.Sort(servers)
	return servers
}

// Scan reads every node and prints the report.
func Scan(ctx context.Context, stdout io.Writer, nodes []string, since time.Duration, top int, now time.Time, fetch Fetchers) error {
	type row struct{ service, node string }
	counts := map[row][2]int{}
	classes := map[Record]int{}
	classNodes := map[Record][]string{}
	var failures []error
	var unreadable []string
	add := func(node string, records []Record, always string) {
		counts[row{always, node}] = counts[row{always, node}]
		for _, r := range records {
			c := counts[row{r.Service, node}]
			c[levelIndex(r.Level)]++
			counts[row{r.Service, node}] = c
			classes[r]++
			if !slices.Contains(classNodes[r], node) {
				classNodes[r] = append(classNodes[r], node)
			}
		}
	}
	for _, node := range nodes {
		out, err := fetch.Node(ctx, node, RemoteCommand(since))
		if err != nil {
			failures = append(failures, fmt.Errorf("node %s: %w", node, err))
			unreadable = append(unreadable, node)
			continue
		}
		add(node, ParseJournal(out), "ts-orchestrator")
	}

	fmt.Fprintf(stdout, "log-scan: the %s before %s\n", since, now.UTC().Format(time.RFC3339))
	table := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(table, "SERVICE\tNODE\tWARN\tERROR\n")
	rows := slices.SortedFunc(func(yield func(row) bool) {
		for r := range counts {
			if !yield(r) {
				return
			}
		}
	}, func(a, b row) int { return cmp.Or(cmp.Compare(a.service, b.service), cmp.Compare(a.node, b.node)) })
	var total [2]int
	for _, r := range rows {
		c := counts[r]
		total[0], total[1] = total[0]+c[0], total[1]+c[1]
		fmt.Fprintf(table, "%s\t%s\t%d\t%d\n", r.service, r.node, c[0], c[1])
	}
	for _, name := range unreadable {
		fmt.Fprintf(table, "unreadable\t%s\t-\t-\n", name)
	}
	fmt.Fprintf(table, "TOTAL\t\t%d\t%d\n", total[0], total[1])
	if err := table.Flush(); err != nil {
		return err
	}

	ranked := slices.SortedFunc(func(yield func(Record) bool) {
		for r := range classes {
			if !yield(r) {
				return
			}
		}
	}, func(a, b Record) int {
		return cmp.Or(cmp.Compare(classes[b], classes[a]), cmp.Compare(a.Service, b.Service), cmp.Compare(a.Class, b.Class))
	})
	if len(ranked) > 0 && top > 0 {
		fmt.Fprintf(stdout, "\nTOP CLASSES\n")
		for _, r := range ranked[:min(top, len(ranked))] {
			fmt.Fprintf(stdout, "%7d %-5s %-15s %s [%s]\n", classes[r], r.Level, r.Service, r.Class, strings.Join(classNodes[r], ","))
		}
	}
	return errors.Join(failures...)
}

func levelIndex(level string) int {
	if level == "ERROR" {
		return 1
	}
	return 0
}

// levelPattern matches, in journalctl's JSON, a .NET console record's first
// line, a slog JSON record and an embedded NATS server line at warning or
// above.
const levelPattern = `"MESSAGE":"(warn|fail|crit): |\\"level\\":\\"(WARN|ERROR)\\"|"MESSAGE":"\[[0-9]+\] \[(WRN|ERR|FTL)\] `

// RemoteCommand prints the orchestrator units' journal records of the last
// since that match levelPattern, each with the two records after it: a .NET
// record's message is the line after its level. No match is not an error.
func RemoteCommand(since time.Duration) string {
	return fmt.Sprintf(`set -o pipefail; journalctl --since -%ds --no-pager -o json --output-fields=_COMM,_PID,MESSAGE -u "terrascale-orchestrator*" | { grep -a -A2 -E '%s' || [ $? -eq 1 ]; }`,
		int(since.Seconds()), levelPattern)
}

// ParseJournal reads RemoteCommand's output: the WARN and ERROR records among
// the lines it matched, classified by internal/logs.
func ParseJournal(out []byte) []Record {
	var parser logs.Parser
	var records []Record
	add := func(r logs.Record, ok bool) {
		if ok && warning(r.Level) {
			records = append(records, Record{r.Service, r.Level, class(r)})
		}
	}
	for line := range bytes.Lines(out) {
		if e, ok := logs.DecodeJournal(line); ok { // grep's "--" separators are not records
			add(parser.Parse(e))
		}
	}
	for _, r := range parser.Flush() {
		add(r, true)
	}
	return records
}

func warning(level string) bool {
	return level == logs.LevelWarn || level == logs.LevelError
}

// class is the record's class text: the component, then the message.
func class(r logs.Record) string {
	if r.Component == "" {
		return r.Message
	}
	return r.Component + ": " + r.Message
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
