// Package linux is the generic Linux provider: system, CPU, memory, GPU,
// storage and network inspection from /proc, /sys and /etc. All capabilities
// are read-only. Host access goes through Options so parsers can be tested
// against fixture trees on any OS.
package linux

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"time"

	"github.com/w512/SysRail/internal/core"
)

// Options controls how the provider reaches the host.
type Options struct {
	// Root is the filesystem holding proc/, sys/ and etc/. Default: os.DirFS("/").
	Root fs.FS
	// Statfs reports filesystem usage for a mount point. Default: statfs(2).
	Statfs func(path string) (FSUsage, error)
	// Command runs a fixed helper binary (only nvidia-smi). Default: os/exec.
	Command func(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath locates helper binaries. Default: exec.LookPath.
	LookPath func(string) (string, error)
	// CPUSample is the interval between /proc/stat samples. Default: 250ms.
	CPUSample time.Duration
}

// FSUsage is the result of statfs on a mount point.
type FSUsage struct {
	Total, Free, Available uint64
	Inodes, InodesFree     uint64
}

// Provider is the generic Linux provider.
type Provider struct {
	opts Options
}

// New returns a Linux provider. It does not touch the host.
func New(opts Options) *Provider {
	if opts.Root == nil {
		opts.Root = os.DirFS("/")
	}
	if opts.Statfs == nil {
		opts.Statfs = statfs
	}
	if opts.Command == nil {
		opts.Command = runCommand
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.CPUSample == 0 {
		opts.CPUSample = 250 * time.Millisecond
	}
	return &Provider{opts: opts}
}

// Name implements providers.Provider.
func (p *Provider) Name() string { return "linux" }

type noArgs struct{}

type cpuArgs struct {
	PerCPU bool `json:"per_cpu,omitempty" jsonschema:"Include usage for each logical CPU"`
}

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() []core.Capability {
	return []core.Capability{
		core.Define(core.Capability{
			ID: "system.status", Tool: "system_get_status",
			Description: "Get a host overview: hostname, OS, kernel, uptime, load, CPU count, memory and process counts.",
			Risk:        core.RiskRead, Permission: "system.read",
		}, nil, func(ctx context.Context, _ noArgs) (any, error) { return p.systemStatus(ctx) }),
		core.Define(core.Capability{
			ID: "system.cpu", Tool: "system_get_cpu_status",
			Description: "Get CPU model, logical CPU count, load averages, current utilization and frequency.",
			Risk:        core.RiskRead, Permission: "system.read",
		}, nil, func(ctx context.Context, in cpuArgs) (any, error) { return p.cpuStatus(ctx, in) }),
		core.Define(core.Capability{
			ID: "system.memory", Tool: "system_get_memory_status",
			Description: "Get RAM and swap usage in bytes.",
			Risk:        core.RiskRead, Permission: "system.read",
		}, nil, func(ctx context.Context, _ noArgs) (any, error) { return p.memoryStatus() }),
		core.Define(core.Capability{
			ID: "system.gpu", Tool: "system_get_gpu_status",
			Description: "List GPUs with memory, utilization, temperature and power where available " +
				"(NVIDIA via nvidia-smi, others via sysfs). available=false means no GPU was found.",
			Risk: core.RiskRead, Permission: "system.read",
		}, nil, func(ctx context.Context, _ noArgs) (any, error) { return p.gpuStatus(ctx) }),
		core.Define(core.Capability{
			ID: "storage.status", Tool: "storage_get_status",
			Description: "Get capacity, usage and inode usage for every real filesystem, flagging ones above " +
				"90% (warning) or 95% (critical).",
			Risk: core.RiskRead, Permission: "storage.read",
		}, nil, func(ctx context.Context, _ noArgs) (any, error) { return p.storageStatus() }),
		core.Define(core.Capability{
			ID: "storage.mounts", Tool: "storage_list_mounts",
			Description: "List mounted filesystems and /etc/fstab entries that are expected but not mounted.",
			Risk:        core.RiskRead, Permission: "storage.read",
		}, nil, func(ctx context.Context, in mountsArgs) (any, error) { return p.listMounts(in) }),
		core.Define(core.Capability{
			ID: "network.connections", Tool: "network_get_connections",
			Description: "List TCP/UDP sockets: listening ports by default, or established connections.",
			Risk:        core.RiskRead, Permission: "network.read", InputSchema: connSchema(),
		}, validateConnArgs, func(ctx context.Context, in connArgs) (any, error) { return p.connections(in) }),
	}
}

func unavailable(what string, err error) error {
	return core.Errorf(core.CodeProviderUnavailable, "cannot read %s: %v", what, err)
}

type osInfo struct {
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	ID         string `json:"id,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
}

type memorySummary struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type systemStatus struct {
	Hostname      string        `json:"hostname"`
	OS            osInfo        `json:"os"`
	Kernel        string        `json:"kernel"`
	Arch          string        `json:"arch"`
	UptimeSeconds int64         `json:"uptime_seconds"`
	BootTime      time.Time     `json:"boot_time"`
	LoadAverage   loadAvg       `json:"load_average"`
	CPUCount      int           `json:"cpu_count"`
	Memory        memorySummary `json:"memory"`
	Processes     procCounts    `json:"processes"`
}

func (p *Provider) systemStatus(_ context.Context) (any, error) {
	root := p.opts.Root
	var st systemStatus
	var err error
	if st.Hostname, err = readTrimmed(root, "proc/sys/kernel/hostname"); err != nil {
		return nil, unavailable("hostname", err)
	}
	if st.Kernel, err = readTrimmed(root, "proc/sys/kernel/osrelease"); err != nil {
		return nil, unavailable("kernel release", err)
	}
	st.Arch = runtime.GOARCH
	if b, err := readFile(root, "etc/os-release"); err == nil {
		r := parseOSRelease(b)
		st.OS = osInfo{Name: r["NAME"], Version: r["VERSION"], ID: r["ID"], PrettyName: r["PRETTY_NAME"]}
	}
	b, err := readFile(root, "proc/uptime")
	if err != nil {
		return nil, unavailable("uptime", err)
	}
	up, err := parseUptime(b)
	if err != nil {
		return nil, unavailable("uptime", err)
	}
	st.UptimeSeconds = int64(up)
	st.BootTime = time.Now().Add(-time.Duration(up * float64(time.Second))).UTC().Truncate(time.Second)
	if b, err = readFile(root, "proc/loadavg"); err != nil {
		return nil, unavailable("load average", err)
	}
	if st.LoadAverage, st.Processes, err = parseLoadavg(b); err != nil {
		return nil, unavailable("load average", err)
	}
	if b, err = readFile(root, "proc/cpuinfo"); err == nil {
		st.CPUCount = parseCPUInfo(b).Logical
	}
	if b, err = readFile(root, "proc/meminfo"); err != nil {
		return nil, unavailable("memory info", err)
	}
	m := parseMeminfo(b)
	st.Memory = memorySummary{
		TotalBytes: m["MemTotal"], AvailableBytes: m["MemAvailable"],
		UsedPercent: percent(m["MemTotal"]-min(m["MemAvailable"], m["MemTotal"]), m["MemTotal"]),
	}
	return st, nil
}

type frequency struct {
	MinMHz float64 `json:"min_mhz"`
	MaxMHz float64 `json:"max_mhz"`
	AvgMHz float64 `json:"avg_mhz"`
}

type cpuStatus struct {
	Model        string     `json:"model"`
	LogicalCPUs  int        `json:"logical_cpus"`
	LoadAverage  loadAvg    `json:"load_average"`
	UsagePercent float64    `json:"usage_percent"`
	PerCPU       []float64  `json:"per_cpu_usage_percent,omitempty"`
	Frequency    *frequency `json:"frequency,omitempty"`
	SampleMS     int64      `json:"sample_ms"`
}

func (p *Provider) cpuStatus(ctx context.Context, in cpuArgs) (any, error) {
	root := p.opts.Root
	b, err := readFile(root, "proc/cpuinfo")
	if err != nil {
		return nil, unavailable("cpuinfo", err)
	}
	ci := parseCPUInfo(b)
	st := cpuStatus{Model: ci.Model, LogicalCPUs: ci.Logical, SampleMS: p.opts.CPUSample.Milliseconds()}
	if len(ci.MHz) > 0 {
		f := frequency{MinMHz: slices.Min(ci.MHz), MaxMHz: slices.Max(ci.MHz)}
		var sum float64
		for _, v := range ci.MHz {
			sum += v
		}
		f.AvgMHz = round1(sum / float64(len(ci.MHz)))
		f.MinMHz, f.MaxMHz = round1(f.MinMHz), round1(f.MaxMHz)
		st.Frequency = &f
	}
	if b, err = readFile(root, "proc/loadavg"); err != nil {
		return nil, unavailable("load average", err)
	}
	if st.LoadAverage, _, err = parseLoadavg(b); err != nil {
		return nil, unavailable("load average", err)
	}

	sample := func() (cpuTimes, []cpuTimes, error) {
		b, err := readFile(root, "proc/stat")
		if err != nil {
			return cpuTimes{}, nil, err
		}
		return parseStat(b)
	}
	a1, p1, err := sample()
	if err != nil {
		return nil, unavailable("/proc/stat", err)
	}
	select {
	case <-time.After(p.opts.CPUSample):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	a2, p2, err := sample()
	if err != nil {
		return nil, unavailable("/proc/stat", err)
	}
	st.UsagePercent = usagePercent(a1, a2)
	if in.PerCPU {
		for i := range min(len(p1), len(p2)) {
			st.PerCPU = append(st.PerCPU, usagePercent(p1[i], p2[i]))
		}
	}
	return st, nil
}

type swapStatus struct {
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

type memoryStatus struct {
	TotalBytes     uint64     `json:"total_bytes"`
	AvailableBytes uint64     `json:"available_bytes"`
	UsedBytes      uint64     `json:"used_bytes"`
	UsedPercent    float64    `json:"used_percent"`
	FreeBytes      uint64     `json:"free_bytes"`
	BuffersBytes   uint64     `json:"buffers_bytes"`
	CachedBytes    uint64     `json:"cached_bytes"`
	SharedBytes    uint64     `json:"shared_bytes"`
	Swap           swapStatus `json:"swap"`
	Note           string     `json:"note"`
}

func (p *Provider) memoryStatus() (any, error) {
	b, err := readFile(p.opts.Root, "proc/meminfo")
	if err != nil {
		return nil, unavailable("memory info", err)
	}
	m := parseMeminfo(b)
	used := m["MemTotal"] - min(m["MemAvailable"], m["MemTotal"])
	swapUsed := m["SwapTotal"] - min(m["SwapFree"], m["SwapTotal"])
	return memoryStatus{
		TotalBytes: m["MemTotal"], AvailableBytes: m["MemAvailable"], UsedBytes: used,
		UsedPercent: percent(used, m["MemTotal"]), FreeBytes: m["MemFree"], BuffersBytes: m["Buffers"],
		CachedBytes: m["Cached"], SharedBytes: m["Shmem"],
		Swap: swapStatus{
			TotalBytes: m["SwapTotal"], FreeBytes: m["SwapFree"], UsedBytes: swapUsed,
			UsedPercent: percent(swapUsed, m["SwapTotal"]),
		},
		Note: "used_bytes is total minus available; page cache is reclaimable and counted as available",
	}, nil
}
