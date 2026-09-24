package systemd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/w512/SysRail/internal/core"
)

var priorities = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

type logsArgs struct {
	Name         string `json:"name" jsonschema:"Service name, e.g. nginx or nginx.service"`
	Lines        int    `json:"lines,omitempty" jsonschema:"Number of most recent entries (default 100)"`
	SinceMinutes int    `json:"since_minutes,omitempty" jsonschema:"Only entries from the last N minutes"`
	Priority     string `json:"priority,omitempty" jsonschema:"Only entries at this priority or more severe"`
}

func logsSchema() *jsonschema.Schema {
	return core.SchemaFor[logsArgs](func(p map[string]*jsonschema.Schema) {
		p["name"].MaxLength = core.Ptr(255)
		p["lines"].Minimum, p["lines"].Maximum = core.Ptr(1.0), core.Ptr(1000.0)
		p["since_minutes"].Minimum, p["since_minutes"].Maximum = core.Ptr(1.0), core.Ptr(10080.0)
		enum := make([]any, len(priorities))
		for i, v := range priorities {
			enum[i] = v
		}
		p["priority"].Enum = enum
	})
}

func validateLogs(in *logsArgs) (string, error) {
	n, err := NormalizeUnit(in.Name)
	if err != nil {
		return "", err
	}
	in.Name = n
	if in.Lines == 0 {
		in.Lines = 100
	}
	return n, nil
}

type logEntry struct {
	Time       time.Time `json:"time"`
	Priority   string    `json:"priority,omitempty"`
	Identifier string    `json:"identifier,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Message    string    `json:"message"`
}

type logResult struct {
	Unit      string     `json:"unit"`
	Entries   []logEntry `json:"entries"`
	Count     int        `json:"count"`
	Truncated bool       `json:"truncated"`
}

// journalArgs builds the journalctl argv. The unit name has been validated,
// and "--unit=" keeps it from being parsed as an option.
func journalArgs(in logsArgs) []string {
	args := []string{
		"--unit=" + in.Name, "--output=json", "--lines=" + strconv.Itoa(in.Lines), "--no-pager", "--quiet",
	}
	if in.SinceMinutes > 0 {
		args = append(args, "--since=-"+strconv.Itoa(in.SinceMinutes)+"min")
	}
	if in.Priority != "" {
		args = append(args, "--priority="+in.Priority)
	}
	return args
}

func (p *Provider) logs(ctx context.Context, in logsArgs) (any, error) {
	raw, err := p.opts.Journal(ctx, journalArgs(in))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, core.Errorf(core.CodeProviderUnavailable, "journalctl failed: %v", err)
	}
	entries, truncated := parseJournal(raw, p.opts.MaxLogBytes)
	if len(entries) == 0 {
		// An unknown unit has no logs; distinguish that from a quiet one.
		if _, err := p.properties(ctx, in.Name); err != nil {
			return nil, err
		}
	}
	return logResult{Unit: in.Name, Entries: entries, Count: len(entries), Truncated: truncated}, nil
}

// parseJournal decodes `journalctl --output=json` lines, keeping the newest
// entries that fit in maxBytes of message text.
func parseJournal(raw []byte, maxBytes int) ([]logEntry, bool) {
	var all []logEntry
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		var rec map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		e := logEntry{Message: messageField(rec["MESSAGE"])}
		if us, err := strconv.ParseInt(stringField(rec["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
			e.Time = time.UnixMicro(us).UTC()
		}
		if pr, err := strconv.Atoi(stringField(rec["PRIORITY"])); err == nil && pr >= 0 && pr < len(priorities) {
			e.Priority = priorities[pr]
		}
		e.Identifier = stringField(rec["SYSLOG_IDENTIFIER"])
		e.PID, _ = strconv.Atoi(stringField(rec["_PID"]))
		all = append(all, e)
	}
	total, start := 0, len(all)
	for start > 0 && total+len(all[start-1].Message) <= maxBytes {
		total += len(all[start-1].Message)
		start--
	}
	entries := all[start:]
	if entries == nil {
		entries = []logEntry{}
	}
	return entries, start > 0
}

func stringField(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// messageField handles MESSAGE values journald encodes as byte arrays when
// they are not valid UTF-8.
func messageField(raw json.RawMessage) string {
	if s := stringField(raw); s != "" {
		return s
	}
	var b []byte
	var nums []int
	if json.Unmarshal(raw, &nums) == nil {
		for _, n := range nums {
			b = append(b, byte(n))
		}
		if utf8.Valid(b) {
			return string(b)
		}
		return string(bytes.ToValidUTF8(b, []byte("\uFFFD")))
	}
	return ""
}
