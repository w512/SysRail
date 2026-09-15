package linux

import (
	"errors"
	"io/fs"
	"sort"
	"strings"
)

const (
	warnPercent     = 90.0
	criticalPercent = 95.0
)

// Filesystem types that do not represent persistent storage. squashfs is
// included because snap images are always 100% full by design.
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "ramfs": true,
	"securityfs": true, "cgroup": true, "cgroup2": true, "pstore": true, "efivarfs": true, "bpf": true,
	"autofs": true, "mqueue": true, "hugetlbfs": true, "debugfs": true, "tracefs": true, "fusectl": true,
	"configfs": true, "binfmt_misc": true, "nsfs": true, "rpc_pipefs": true, "selinuxfs": true,
	"overlay": true, "squashfs": true, "fuse.portal": true, "fuse.gvfsd-fuse": true, "fuse.snapfuse": true,
}

func isPseudo(fstype string) bool { return pseudoFS[fstype] }

// mounts reads the host mount table. PID 1's view is used because the daemon
// itself may run in a private mount namespace (systemd sandboxing).
func (p *Provider) mounts() ([]mountEntry, error) {
	b, err := readFile(p.opts.Root, "proc/1/mountinfo")
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		b, err = readFile(p.opts.Root, "proc/self/mountinfo")
	}
	if err != nil {
		return nil, unavailable("mount table", err)
	}
	m, err := parseMountinfo(b)
	if err != nil {
		return nil, unavailable("mount table", err)
	}
	return m, nil
}

type filesystem struct {
	MountPoint        string  `json:"mount_point"`
	Device            string  `json:"device"`
	FSType            string  `json:"fstype"`
	ReadOnly          bool    `json:"read_only"`
	TotalBytes        uint64  `json:"total_bytes"`
	UsedBytes         uint64  `json:"used_bytes"`
	AvailableBytes    uint64  `json:"available_bytes"`
	UsedPercent       float64 `json:"used_percent"`
	InodesTotal       uint64  `json:"inodes_total,omitempty"`
	InodesUsed        uint64  `json:"inodes_used,omitempty"`
	InodesUsedPercent float64 `json:"inodes_used_percent,omitempty"`
	Status            string  `json:"status"`
	Error             string  `json:"error,omitempty"`
}

type storageStatus struct {
	Filesystems []filesystem       `json:"filesystems"`
	Warnings    []string           `json:"warnings"`
	Thresholds  map[string]float64 `json:"thresholds_percent"`
}

func (p *Provider) storageStatus() (any, error) {
	mounts, err := p.mounts()
	if err != nil {
		return nil, err
	}
	// Bind mounts repeat a device+root; keep the first (original) mount.
	seen := map[string]bool{}
	var unique []mountEntry
	for _, m := range mounts {
		key := m.Device + "\x00" + m.Root
		if isPseudo(m.FSType) || seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, m)
	}
	out := storageStatus{Filesystems: []filesystem{}, Warnings: []string{},
		Thresholds: map[string]float64{"warning": warnPercent, "critical": criticalPercent}}
	for _, m := range unique {
		fsys := filesystem{MountPoint: m.MountPoint, Device: m.Source, FSType: m.FSType,
			ReadOnly: hasOption(m.Options, "ro"), Status: "ok"}
		u, err := p.opts.Statfs(m.MountPoint)
		if err != nil {
			fsys.Status, fsys.Error = "unknown", err.Error()
			out.Filesystems = append(out.Filesystems, fsys)
			continue
		}
		used := u.Total - min(u.Free, u.Total)
		fsys.TotalBytes, fsys.UsedBytes, fsys.AvailableBytes = u.Total, used, u.Available
		// Like df: reserved blocks count as unavailable, not as used.
		fsys.UsedPercent = percent(used, used+u.Available)
		if u.Inodes > 0 {
			fsys.InodesTotal = u.Inodes
			fsys.InodesUsed = u.Inodes - min(u.InodesFree, u.Inodes)
			fsys.InodesUsedPercent = percent(fsys.InodesUsed, u.Inodes)
		}
		worst := max(fsys.UsedPercent, fsys.InodesUsedPercent)
		switch {
		case worst >= criticalPercent:
			fsys.Status = "critical"
		case worst >= warnPercent:
			fsys.Status = "warning"
		}
		if fsys.Status != "ok" {
			what := "space"
			if fsys.InodesUsedPercent > fsys.UsedPercent {
				what = "inodes"
			}
			out.Warnings = append(out.Warnings, fsys.MountPoint+": "+what+" "+fsys.Status)
		}
		out.Filesystems = append(out.Filesystems, fsys)
	}
	return out, nil
}

type mountsArgs struct {
	IncludePseudo bool `json:"include_pseudo,omitempty" jsonschema:"Also list virtual filesystems (proc, sysfs, tmpfs, cgroup, squashfs, ...)"`
}

type mount struct {
	MountPoint string `json:"mount_point"`
	Source     string `json:"source"`
	FSType     string `json:"fstype"`
	ReadOnly   bool   `json:"read_only"`
	Options    string `json:"options"`
	Device     string `json:"device"`
}

type mountList struct {
	Mounts []mount `json:"mounts"`
	// FstabNotMounted lists /etc/fstab entries that should be mounted at boot
	// but currently are not.
	FstabNotMounted []fstabEntry `json:"fstab_not_mounted"`
	Hidden          int          `json:"hidden_pseudo_mounts,omitempty"`
}

func (p *Provider) listMounts(in mountsArgs) (any, error) {
	mounts, err := p.mounts()
	if err != nil {
		return nil, err
	}
	out := mountList{Mounts: []mount{}, FstabNotMounted: []fstabEntry{}}
	mounted := map[string]bool{}
	for _, m := range mounts {
		mounted[m.MountPoint] = true
		if !in.IncludePseudo && isPseudo(m.FSType) {
			out.Hidden++
			continue
		}
		out.Mounts = append(out.Mounts, mount{
			MountPoint: m.MountPoint, Source: m.Source, FSType: m.FSType,
			ReadOnly: hasOption(m.Options, "ro"), Options: m.Options, Device: m.Device,
		})
	}
	sort.Slice(out.Mounts, func(i, j int) bool { return out.Mounts[i].MountPoint < out.Mounts[j].MountPoint })
	if b, err := readFile(p.opts.Root, "etc/fstab"); err == nil {
		for _, e := range parseFstab(b) {
			if e.FSType == "swap" || e.MountPoint == "none" || !strings.HasPrefix(e.MountPoint, "/") ||
				hasOption(e.Options, "noauto") {
				continue
			}
			if !mounted[strings.TrimSuffix(e.MountPoint, "/")] && !mounted[e.MountPoint] {
				out.FstabNotMounted = append(out.FstabNotMounted, e)
			}
		}
	}
	return out, nil
}
