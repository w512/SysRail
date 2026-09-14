package linux

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

func readFile(fsys fs.FS, name string) ([]byte, error) {
	return fs.ReadFile(fsys, name)
}

func readTrimmed(fsys fs.FS, name string) (string, error) {
	b, err := readFile(fsys, name)
	return strings.TrimSpace(string(b)), err
}

// parseMeminfo returns /proc/meminfo values in bytes, keyed by field name.
func parseMeminfo(data []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			v *= 1024
		}
		out[key] = v
	}
	return out
}

type loadAvg struct {
	One     float64 `json:"1m"`
	Five    float64 `json:"5m"`
	Fifteen float64 `json:"15m"`
}

type procCounts struct {
	Running int `json:"running"`
	Total   int `json:"total"`
}

// parseLoadavg parses /proc/loadavg ("0.00 0.01 0.08 1/694 70693").
func parseLoadavg(data []byte) (loadAvg, procCounts, error) {
	f := strings.Fields(string(data))
	if len(f) < 4 {
		return loadAvg{}, procCounts{}, fmt.Errorf("malformed loadavg")
	}
	var la loadAvg
	var err error
	for i, dst := range []*float64{&la.One, &la.Five, &la.Fifteen} {
		if *dst, err = strconv.ParseFloat(f[i], 64); err != nil {
			return loadAvg{}, procCounts{}, fmt.Errorf("malformed loadavg: %w", err)
		}
	}
	var pc procCounts
	run, total, _ := strings.Cut(f[3], "/")
	pc.Running, _ = strconv.Atoi(run)
	pc.Total, _ = strconv.Atoi(total)
	return la, pc, nil
}

// parseUptime returns system uptime in seconds from /proc/uptime.
func parseUptime(data []byte) (float64, error) {
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("malformed uptime")
	}
	return strconv.ParseFloat(f[0], 64)
}

// cpuTimes holds jiffy counters from one /proc/stat cpu line.
type cpuTimes struct {
	idle, total uint64
}

// parseStat returns the aggregate counters followed by per-CPU counters.
func parseStat(data []byte) (cpuTimes, []cpuTimes, error) {
	var all cpuTimes
	var per []cpuTimes
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		var t cpuTimes
		for i, s := range f[1:] {
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return cpuTimes{}, nil, fmt.Errorf("malformed /proc/stat: %w", err)
			}
			// guest and guest_nice (fields 9, 10) are already counted in user/nice.
			if i >= 8 {
				continue
			}
			t.total += v
			if i == 3 || i == 4 { // idle, iowait
				t.idle += v
			}
		}
		if f[0] == "cpu" {
			all, found = t, true
		} else {
			per = append(per, t)
		}
	}
	if !found {
		return cpuTimes{}, nil, fmt.Errorf("no aggregate cpu line in /proc/stat")
	}
	return all, per, nil
}

// usagePercent computes busy time between two samples.
func usagePercent(prev, cur cpuTimes) float64 {
	dt := float64(cur.total) - float64(prev.total)
	if dt <= 0 {
		return 0
	}
	di := float64(cur.idle) - float64(prev.idle)
	return round1(100 * (dt - di) / dt)
}

type cpuInfo struct {
	Model   string
	Logical int
	MHz     []float64
}

func parseCPUInfo(data []byte) cpuInfo {
	var ci cpuInfo
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "processor":
			ci.Logical++
		case "model name":
			if ci.Model == "" {
				ci.Model = val
			}
		case "cpu MHz":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				ci.MHz = append(ci.MHz, v)
			}
		}
	}
	return ci
}

// parseOSRelease parses /etc/os-release KEY=VALUE lines.
func parseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `'"`)
		}
		out[k] = v
	}
	return out
}

// mountEntry is one line of /proc/self/mountinfo.
type mountEntry struct {
	ID         int
	Device     string // major:minor
	Root       string
	MountPoint string
	Options    string
	FSType     string
	Source     string
	SuperOpts  string
}

// parseMountinfo parses /proc/self/mountinfo (see proc(5)).
func parseMountinfo(data []byte) ([]mountEntry, error) {
	var out []mountEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 7 || sep < 0 || sep+2 >= len(f) {
			return nil, fmt.Errorf("malformed mountinfo line %q", sc.Text())
		}
		id, _ := strconv.Atoi(f[0])
		e := mountEntry{
			ID: id, Device: f[2], Root: unescapeOctal(f[3]), MountPoint: unescapeOctal(f[4]),
			Options: f[5], FSType: f[sep+1], Source: unescapeOctal(f[sep+2]),
		}
		if sep+3 < len(f) {
			e.SuperOpts = f[sep+3]
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

type fstabEntry struct {
	Spec       string `json:"spec"`
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fstype"`
	Options    string `json:"options"`
}

func parseFstab(data []byte) []fstabEntry {
	var out []fstabEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		e := fstabEntry{Spec: unescapeOctal(f[0]), MountPoint: unescapeOctal(f[1]), FSType: f[2]}
		if len(f) > 3 {
			e.Options = f[3]
		}
		out = append(out, e)
	}
	return out
}

// unescapeOctal decodes the \ooo escapes used for spaces etc. in mount tables.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hasOption(opts, name string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == name {
			return true
		}
	}
	return false
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

func percent(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return round1(100 * float64(part) / float64(whole))
}
