// Package systemd is the systemd provider: list services, inspect status,
// read journal logs and start/stop/restart services. Only .service units are
// supported, and protected units can never be changed.
package systemd

import (
	"context"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/w512/SysRail/internal/core"
)

// SelfUnit is always protected: an agent must never stop SysRail itself.
const SelfUnit = "sysrail.service"

// DefaultProtectedUnits may never be started, stopped or restarted unless the
// configuration replaces this list.
var DefaultProtectedUnits = []string{
	"dbus.service", "dbus-broker.service", "systemd-*.service", "polkit.service",
	"ssh.service", "sshd.service", "user@*.service", "getty@*.service", "serial-getty@*.service",
}

var (
	unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9_](?:[A-Za-z0-9:_.@-]|\\x[0-9a-f]{2})*$`)
	globPattern     = regexp.MustCompile(`^[A-Za-z0-9:_.@*?\[\]-]+$`)
	otherUnitTypes  = []string{".socket", ".target", ".mount", ".automount", ".timer", ".path",
		".slice", ".scope", ".swap", ".device"}
)

// Options configures the provider.
type Options struct {
	// Manager reaches systemd. Default: D-Bus.
	Manager Manager
	// Journal runs journalctl with the given arguments. Default: exec of
	// JournalctlPath with a fixed environment.
	Journal func(ctx context.Context, args []string) ([]byte, error)
	// JournalctlPath defaults to /usr/bin/journalctl.
	JournalctlPath string
	// ProtectedUnits are glob patterns; nil means DefaultProtectedUnits.
	// SelfUnit is always added.
	ProtectedUnits []string
	// MaxLogBytes caps the total size of returned log messages. Default 256 KiB.
	MaxLogBytes int
	// WatchInterval is how often Watch polls unit states. Default 5s.
	WatchInterval time.Duration
}

// Provider is the systemd provider.
type Provider struct {
	opts      Options
	protected []string
}

// New returns a systemd provider. It does not touch the host.
func New(opts Options) *Provider {
	if opts.Manager == nil {
		opts.Manager = NewDBusManager()
	}
	if opts.JournalctlPath == "" {
		opts.JournalctlPath = "/usr/bin/journalctl"
	}
	if opts.Journal == nil {
		opts.Journal = func(ctx context.Context, args []string) ([]byte, error) {
			return runJournalctl(ctx, opts.JournalctlPath, args)
		}
	}
	if opts.MaxLogBytes <= 0 {
		opts.MaxLogBytes = 256 << 10
	}
	protected := opts.ProtectedUnits
	if protected == nil {
		protected = DefaultProtectedUnits
	}
	protected = append(slices.Clone(protected), SelfUnit)
	return &Provider{opts: opts, protected: protected}
}

// Name implements providers.Provider.
func (p *Provider) Name() string { return "systemd" }

// NormalizeUnit validates a service name, appending ".service" if no unit
// type is given.
func NormalizeUnit(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", core.Errorf(core.CodeInvalidArgument, "unit name is required")
	}
	for _, t := range otherUnitTypes {
		if strings.HasSuffix(name, t) {
			return "", core.Errorf(core.CodeInvalidArgument, "only .service units are supported, got %q", name)
		}
	}
	if !strings.HasSuffix(name, ".service") {
		name += ".service"
	}
	if len(name) > 255 || !unitNamePattern.MatchString(name) {
		return "", core.Errorf(core.CodeInvalidArgument, "invalid unit name %q", name)
	}
	if strings.HasSuffix(name, "@.service") {
		return "", core.Errorf(core.CodeInvalidArgument, "%q is a template; specify an instance like name@instance.service", name)
	}
	return name, nil
}

func (p *Provider) isProtected(unit string) bool {
	for _, pat := range p.protected {
		if ok, _ := path.Match(pat, unit); ok {
			return true
		}
	}
	return false
}

type unitArgs struct {
	Name string `json:"name" jsonschema:"Service name, e.g. nginx or nginx.service"`
}

func unitSchema() *jsonschema.Schema {
	return core.SchemaFor[unitArgs](func(p map[string]*jsonschema.Schema) { p["name"].MaxLength = core.Ptr(255) })
}

func validateUnit(in *unitArgs) (string, error) {
	n, err := NormalizeUnit(in.Name)
	in.Name = n
	return n, err
}

// validateMutation additionally refuses protected units. This is a hard
// rule that policy cannot override.
func (p *Provider) validateMutation(in *unitArgs) (string, error) {
	n, err := validateUnit(in)
	if err != nil {
		return "", err
	}
	if p.isProtected(n) {
		return "", core.Errorf(core.CodePermissionDenied, "%s is a protected unit and cannot be changed through SysRail", n)
	}
	return n, nil
}

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() []core.Capability {
	mutation := func(id, tool, verb, impact string, risk core.Risk,
		op func(Manager, context.Context, string) (string, error)) core.Capability {
		return core.Define(core.Capability{
			ID: id, Tool: tool, Description: strings.ToUpper(verb[:1]) + verb[1:] + " a systemd service and report its resulting state.",
			Impact: impact, Risk: risk, Permission: id, Mutating: true, ResourceKind: "service",
			InputSchema: unitSchema(),
		}, p.validateMutation, func(ctx context.Context, in unitArgs) (any, error) {
			return p.mutate(ctx, verb, in.Name, op)
		})
	}
	return []core.Capability{
		core.Define(core.Capability{
			ID: "service.list", Tool: "service_list",
			Description: "List loaded systemd services with their load, active and sub state. " +
				"Use state=failed to find broken services.",
			Risk: core.RiskRead, Permission: "service.read", InputSchema: listSchema(),
		}, validateList, func(ctx context.Context, in listArgs) (any, error) { return p.list(ctx, in) }),
		core.Define(core.Capability{
			ID: "service.status", Tool: "service_get_status",
			Description: "Get detailed status of a systemd service: states, main PID, restart count, " +
				"exit status, memory and when it last changed state.",
			Risk: core.RiskRead, Permission: "service.read", ResourceKind: "service", InputSchema: unitSchema(),
		}, validateUnit, func(ctx context.Context, in unitArgs) (any, error) { return p.status(ctx, in.Name) }),
		core.Define(core.Capability{
			ID: "service.logs", Tool: "service_get_logs",
			Description: "Get recent journal entries for a systemd service, newest last. Secrets are redacted.",
			Risk:        core.RiskRead, Permission: "logs.read", ResourceKind: "service", InputSchema: logsSchema(),
		}, validateLogs, func(ctx context.Context, in logsArgs) (any, error) { return p.logs(ctx, in) }),
		mutation("service.start", "service_start", "start",
			"Starts the service; it begins consuming resources and may bind network ports.",
			core.RiskLow, Manager.Start),
		mutation("service.restart", "service_restart", "restart",
			"Stops and starts the service again; its clients see a brief interruption.",
			core.RiskLow, Manager.Restart),
		mutation("service.stop", "service_stop", "stop",
			"Stops the service until it is started again; services that depend on it may stop too.",
			core.RiskMedium, Manager.Stop),
	}
}

type listArgs struct {
	Pattern string `json:"pattern,omitempty" jsonschema:"Glob on the unit name, e.g. nginx* or *docker* (default: all services)"`
	State   string `json:"state,omitempty" jsonschema:"Filter: all (default), active, inactive, failed, running"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum entries to return (default 200)"`
}

func listSchema() *jsonschema.Schema {
	return core.SchemaFor[listArgs](func(p map[string]*jsonschema.Schema) {
		p["pattern"].MaxLength = core.Ptr(128)
		p["state"].Enum = []any{"all", "active", "inactive", "failed", "running"}
		p["limit"].Minimum, p["limit"].Maximum = core.Ptr(1.0), core.Ptr(1000.0)
	})
}

func validateList(in *listArgs) (string, error) {
	if in.Pattern == "" {
		in.Pattern = "*"
	}
	if !globPattern.MatchString(in.Pattern) {
		return "", core.Errorf(core.CodeInvalidArgument, "pattern may only contain unit name characters and * ? [ ]")
	}
	if !strings.HasSuffix(in.Pattern, ".service") && !strings.HasSuffix(in.Pattern, "*") {
		in.Pattern += ".service"
	}
	if in.State == "" {
		in.State = "all"
	}
	if in.Limit == 0 {
		in.Limit = 200
	}
	return "", nil
}

type serviceEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

type serviceList struct {
	Services  []serviceEntry `json:"services"`
	Total     int            `json:"total"`
	Truncated bool           `json:"truncated"`
	Note      string         `json:"note"`
}

func (p *Provider) list(ctx context.Context, in listArgs) (any, error) {
	var states []string
	if in.State != "all" {
		states = []string{in.State}
	}
	units, err := p.opts.Manager.ListUnits(ctx, states, []string{in.Pattern})
	if err != nil {
		return nil, err
	}
	out := serviceList{Services: []serviceEntry{},
		Note: "Only units loaded by systemd are listed; disabled services that never ran may be absent."}
	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".service") {
			continue
		}
		out.Services = append(out.Services, serviceEntry{Name: u.Name, Description: u.Description,
			LoadState: u.LoadState, ActiveState: u.ActiveState, SubState: u.SubState})
	}
	slices.SortFunc(out.Services, func(a, b serviceEntry) int { return strings.Compare(a.Name, b.Name) })
	out.Total = len(out.Services)
	if len(out.Services) > in.Limit {
		out.Services, out.Truncated = out.Services[:in.Limit], true
	}
	return out, nil
}

type serviceStatus struct {
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	LoadState      string     `json:"load_state"`
	ActiveState    string     `json:"active_state"`
	SubState       string     `json:"sub_state"`
	UnitFileState  string     `json:"unit_file_state,omitempty"`
	Healthy        bool       `json:"healthy"`
	MainPID        uint32     `json:"main_pid,omitempty"`
	Restarts       uint32     `json:"restarts"`
	ExecMainStatus int32      `json:"exec_main_status"`
	Result         string     `json:"result,omitempty"`
	MemoryBytes    *uint64    `json:"memory_bytes,omitempty"`
	StateChangedAt *time.Time `json:"state_changed_at,omitempty"`
	ActiveSince    *time.Time `json:"active_since,omitempty"`
	InactiveSince  *time.Time `json:"inactive_since,omitempty"`
	UnitFile       string     `json:"unit_file,omitempty"`
}

func (p *Provider) properties(ctx context.Context, unit string) (*UnitProperties, error) {
	props, err := p.opts.Manager.Properties(ctx, unit)
	if err != nil {
		return nil, err
	}
	if props.LoadState == "not-found" {
		return nil, core.Errorf(core.CodeResourceNotFound, "unit %s not found", unit)
	}
	return props, nil
}

func (p *Provider) status(ctx context.Context, unit string) (any, error) {
	props, err := p.properties(ctx, unit)
	if err != nil {
		return nil, err
	}
	st := serviceStatus{
		Name: unit, Description: props.Description, LoadState: props.LoadState,
		ActiveState: props.ActiveState, SubState: props.SubState, UnitFileState: props.UnitFileState,
		Healthy: props.ActiveState == "active", MainPID: props.MainPID, Restarts: props.NRestarts,
		ExecMainStatus: props.ExecMainStatus, Result: props.Result, UnitFile: props.FragmentPath,
		StateChangedAt: usecTime(props.StateChangeTimestamp), ActiveSince: usecTime(props.ActiveEnterTimestamp),
		InactiveSince: usecTime(props.InactiveEnterTimestamp),
	}
	// systemd reports UINT64_MAX when memory accounting is unavailable.
	if props.MemoryCurrent != 0 && props.MemoryCurrent != ^uint64(0) {
		st.MemoryBytes = core.Ptr(props.MemoryCurrent)
	}
	return st, nil
}

type mutationResult struct {
	Unit        string `json:"unit"`
	Action      string `json:"action"`
	JobResult   string `json:"job_result"`
	ActiveState string `json:"active_state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
	MainPID     uint32 `json:"main_pid,omitempty"`
}

func (p *Provider) mutate(ctx context.Context, verb, unit string, op func(Manager, context.Context, string) (string, error)) (any, error) {
	if _, err := p.properties(ctx, unit); err != nil {
		return nil, err
	}
	result, err := op(p.opts.Manager, ctx, unit)
	if err != nil {
		return nil, err
	}
	out := mutationResult{Unit: unit, Action: verb, JobResult: result}
	if props, err := p.opts.Manager.Properties(ctx, unit); err == nil {
		out.ActiveState, out.SubState, out.MainPID = props.ActiveState, props.SubState, props.MainPID
	}
	switch result {
	case "done", "skipped":
		return out, nil
	case "timeout":
		return nil, core.Errorf(core.CodeTimeout, "systemd timed out trying to %s %s", verb, unit)
	case "canceled":
		return nil, core.Errorf(core.CodeConflict, "the %s job for %s was canceled by another job", verb, unit)
	case "dependency":
		return nil, core.Errorf(core.CodeExecutionFailed, "cannot %s %s: a dependency failed", verb, unit).
			WithDetail("active_state", out.ActiveState)
	}
	return nil, core.Errorf(core.CodeExecutionFailed, "systemd could not %s %s (job result: %s); check service_get_logs",
		verb, unit, result).WithDetail("active_state", out.ActiveState).WithDetail("sub_state", out.SubState)
}

func usecTime(us uint64) *time.Time {
	if us == 0 {
		return nil
	}
	t := time.UnixMicro(int64(us)).UTC()
	return &t
}
