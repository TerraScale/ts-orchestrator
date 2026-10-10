package logs

import (
	"cmp"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Parser classifies journal entries. It is stateful: a .NET console record is
// a "warn: Category[id]" header, the indented message that follows from the
// same process, and any indented exception text after that. Other processes'
// lines interleave.
type Parser struct {
	// held maps a process to its header record, which waits for its message.
	held map[string]Record
	// inRecord marks a process whose .NET message arrived; its indented lines are the same record.
	inRecord map[string]bool
	// queue holds records that Parse has not returned yet.
	queue []Record
}

// Parse returns the record that e completes, if any. One call returns one
// record, so a header that ends with a non-indented line can leave that line's
// own record queued; Flush returns it.
func (p *Parser) Parse(e Entry) (Record, bool) {
	p.queue = append(p.queue, p.step(e)...)
	if len(p.queue) == 0 {
		return Record{}, false
	}
	r := p.queue[0]
	p.queue = p.queue[1:]
	return r, true
}

// Flush returns the queued records and the headers whose message never came.
func (p *Parser) Flush() []Record {
	out := p.queue
	p.queue = nil
	for pid, head := range p.held {
		out = append(out, head)
		delete(p.held, pid)
	}
	return out
}

func (p *Parser) step(e Entry) []Record {
	var out []Record
	indented := strings.HasPrefix(e.Message, " ")
	if head, ok := p.held[e.PID]; ok {
		delete(p.held, e.PID)
		if indented {
			if p.inRecord == nil {
				p.inRecord = make(map[string]bool)
			}
			p.inRecord[e.PID] = true
			head.Message, head.Example = Normalize(e.Message), example(e.Message)
			return []Record{head}
		}
		out = append(out, head)
	}
	// Exception text and stack frames are indented too; they end with the record.
	if indented && p.inRecord[e.PID] {
		return out
	}
	delete(p.inRecord, e.PID)
	if head, ok := dotnetHeader(e); ok {
		if p.held == nil {
			p.held = make(map[string]Record)
		}
		p.held[e.PID] = head
		return out
	}
	if r, ok := Classify(e); ok {
		out = append(out, r)
	}
	return out
}

// Classify classifies an entry that is a whole record by itself. Any other
// line is a record too, at the level its journal PRIORITY gives.
func Classify(e Entry) (Record, bool) {
	if strings.TrimSpace(e.Message) == "" {
		return Record{}, false
	}
	for _, classify := range []func(Entry) (Record, bool){slogRecord, natsRecord, netbirdRecord} {
		if r, ok := classify(e); ok {
			return r, true
		}
	}
	return Record{Service: unitService(e), Level: priorityLevel(e.Priority), Message: Normalize(e.Message), Example: example(e.Message)}, true
}

// slogRecord reads record v1 and slog JSON: {"level","msg","component","error","service"}.
func slogRecord(e Entry) (Record, bool) {
	var slog struct {
		Level     string `json:"level"`
		Msg       string `json:"msg"`
		Component string `json:"component"`
		Error     string `json:"error"`
		Service   string `json:"service"`
	}
	if !strings.HasPrefix(e.Message, "{") || json.Unmarshal([]byte(e.Message), &slog) != nil || !validLevel(slog.Level) {
		return Record{}, false
	}
	message := slog.Msg
	if slog.Error != "" {
		message += ": " + slog.Error
	}
	return Record{Service: cmp.Or(slog.Service, unitService(e)), Level: slog.Level, Component: slog.Component,
		Message: Normalize(message), Example: example(e.Message)}, true
}

var (
	dotnetHeaderLine = regexp.MustCompile(`^(trce|dbug|info|warn|fail|crit): ([^\[ ]+)`)
	dotnetLevels     = map[string]string{"trce": LevelDebug, "dbug": LevelDebug, "info": LevelInfo, "warn": LevelWarn, "fail": LevelError, "crit": LevelError}
)

// dotnetHeader reads a .NET console header; its message follows on a later line.
func dotnetHeader(e Entry) (Record, bool) {
	m := dotnetHeaderLine.FindStringSubmatch(e.Message)
	if m == nil {
		return Record{}, false
	}
	return Record{Service: commService(e), Level: dotnetLevels[m[1]], Component: m[2]}, true
}

var (
	natsLine   = regexp.MustCompile(`^\[\d+\] \[(INF|WRN|ERR|FTL|DBG|TRC)\] (.*)`)
	natsLevels = map[string]string{"TRC": LevelDebug, "DBG": LevelDebug, "INF": LevelInfo, "WRN": LevelWarn, "ERR": LevelError, "FTL": LevelError}
	// A permission violation names its client and account; one cause is one class.
	violationQuote   = regexp.MustCompile(`"[^"]*"`)
	violationAccount = regexp.MustCompile(`\b(account|JWT)\s+\S+`)
)

// natsRecord reads an embedded NATS server line: "[pid] [WRN] text".
func natsRecord(e Entry) (Record, bool) {
	m := natsLine.FindStringSubmatch(e.Message)
	if m == nil {
		return Record{}, false
	}
	text := m[2]
	if strings.Contains(text, "Violation") {
		text = violationAccount.ReplaceAllString(violationQuote.ReplaceAllString(text, ""), "")
	}
	return Record{Service: "ts-orchestrator", Level: natsLevels[m[1]], Component: "nats", Message: Normalize(text), Example: example(e.Message)}, true
}

var (
	netbirdLine   = regexp.MustCompile(`^\S+ (TRAC|DEBU|INFO|WARN|ERRO|FATA|PANI) (?:\[[^\]]*\] )?(\S+?):\d+: (.*)$`)
	netbirdLevels = map[string]string{"TRAC": LevelDebug, "DEBU": LevelDebug, "INFO": LevelInfo, "WARN": LevelWarn, "ERRO": LevelError, "FATA": LevelError, "PANI": LevelError}
)

// netbirdRecord reads a NetBird client line: "time LEVEL [peer] file.go:line: text".
func netbirdRecord(e Entry) (Record, bool) {
	m := netbirdLine.FindStringSubmatch(e.Message)
	if m == nil {
		return Record{}, false
	}
	return Record{Service: "netbird", Level: netbirdLevels[m[1]], Component: m[2], Message: Normalize(m[3]), Example: example(e.Message)}, true
}

// priorityLevel maps the syslog PRIORITY: 0-3 error, 4 warning, 7 debug, the rest info.
func priorityLevel(priority string) string {
	n, err := strconv.Atoi(priority)
	switch {
	case err != nil:
		return LevelInfo
	case n <= 3:
		return LevelError
	case n == 4:
		return LevelWarn
	case n == 7:
		return LevelDebug
	}
	return LevelInfo
}

// unitService names a line by its systemd unit, or its process when it has none.
func unitService(e Entry) string {
	switch {
	case e.Comm == "systemd":
		return "systemd"
	case strings.HasPrefix(e.Unit, "terrascale-orchestrator"):
		return "ts-orchestrator"
	case e.Unit != "":
		return strings.TrimSuffix(e.Unit, ".service")
	}
	return commService(e)
}

// commService names a line by its process.
func commService(e Entry) string {
	switch {
	case strings.HasPrefix(e.Comm, "terrascale-orch"):
		return "ts-orchestrator"
	case e.Comm == "":
		return "unknown"
	}
	return e.Comm
}
