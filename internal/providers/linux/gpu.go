package linux

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var nvidiaQuery = []string{
	"--query-gpu=index,name,uuid,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw",
	"--format=csv,noheader,nounits",
}

var drmCard = regexp.MustCompile(`^card[0-9]+$`)

var pciVendors = map[string]string{"0x10de": "NVIDIA", "0x1002": "AMD", "0x8086": "Intel"}

type gpu struct {
	ID                 string   `json:"id"`
	Vendor             string   `json:"vendor"`
	Name               string   `json:"name"`
	Driver             string   `json:"driver,omitempty"`
	DriverVersion      string   `json:"driver_version,omitempty"`
	UUID               string   `json:"uuid,omitempty"`
	PCIID              string   `json:"pci_id,omitempty"`
	MemoryTotalBytes   *uint64  `json:"memory_total_bytes,omitempty"`
	MemoryUsedBytes    *uint64  `json:"memory_used_bytes,omitempty"`
	MemoryUsedPercent  *float64 `json:"memory_used_percent,omitempty"`
	UtilizationPercent *float64 `json:"utilization_percent,omitempty"`
	TemperatureC       *float64 `json:"temperature_c,omitempty"`
	PowerWatts         *float64 `json:"power_watts,omitempty"`
	Source             string   `json:"source"`
}

type gpuStatus struct {
	Available bool     `json:"available"`
	GPUs      []gpu    `json:"gpus"`
	Errors    []string `json:"errors,omitempty"`
}

func (p *Provider) gpuStatus(ctx context.Context) (any, error) {
	out := gpuStatus{GPUs: []gpu{}}
	nvidiaSeen := false
	if path, err := p.opts.LookPath("nvidia-smi"); err == nil {
		raw, err := p.opts.Command(ctx, path, nvidiaQuery...)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			out.Errors = append(out.Errors, "nvidia-smi failed: "+firstLine(err.Error()))
		} else {
			gpus, err := parseNvidiaSMI(raw)
			if err != nil {
				out.Errors = append(out.Errors, "nvidia-smi: "+err.Error())
			}
			out.GPUs = append(out.GPUs, gpus...)
			nvidiaSeen = len(gpus) > 0
		}
	}
	out.GPUs = append(out.GPUs, p.drmGPUs(nvidiaSeen)...)
	out.Available = len(out.GPUs) > 0
	return out, nil
}

func parseNvidiaSMI(raw []byte) ([]gpu, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []gpu
	for _, f := range recs {
		if len(f) < 9 {
			continue
		}
		g := gpu{
			ID: "nvidia:" + f[0], Vendor: "NVIDIA", Name: f[1], UUID: na(f[2]), DriverVersion: na(f[3]),
			Driver: "nvidia", Source: "nvidia-smi",
		}
		if total, ok := num(f[4]); ok {
			g.MemoryTotalBytes = ptr(uint64(total) << 20)
			if used, ok := num(f[5]); ok {
				g.MemoryUsedBytes = ptr(uint64(used) << 20)
				g.MemoryUsedPercent = ptr(percent(*g.MemoryUsedBytes, *g.MemoryTotalBytes))
			}
		}
		if v, ok := num(f[6]); ok {
			g.UtilizationPercent = ptr(v)
		}
		if v, ok := num(f[7]); ok {
			g.TemperatureC = ptr(v)
		}
		if v, ok := num(f[8]); ok {
			g.PowerWatts = ptr(round1(v))
		}
		out = append(out, g)
	}
	return out, nil
}

// drmGPUs enumerates /sys/class/drm cards. NVIDIA cards are skipped when
// nvidia-smi already reported them.
func (p *Provider) drmGPUs(skipNvidia bool) []gpu {
	entries, err := fs.ReadDir(p.opts.Root, "sys/class/drm")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if drmCard.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(names[i], "card"))
		b, _ := strconv.Atoi(strings.TrimPrefix(names[j], "card"))
		return a < b
	})
	var out []gpu
	for _, name := range names {
		dev := "sys/class/drm/" + name + "/device/"
		vendorID, err := readTrimmed(p.opts.Root, dev+"vendor")
		if err != nil {
			continue
		}
		vendor := pciVendors[vendorID]
		if vendor == "" {
			vendor = vendorID
		}
		if skipNvidia && vendorID == "0x10de" {
			continue
		}
		g := gpu{ID: "drm:" + name, Vendor: vendor, Source: "sysfs"}
		if b, err := readFile(p.opts.Root, dev+"uevent"); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				k, v, _ := strings.Cut(sc.Text(), "=")
				switch k {
				case "DRIVER":
					g.Driver = v
				case "PCI_ID":
					g.PCIID = strings.ToLower(v)
				}
			}
		}
		g.Name = strings.TrimSpace(vendor + " GPU " + g.PCIID)
		if total, ok := readUint(p.opts.Root, dev+"mem_info_vram_total"); ok {
			g.MemoryTotalBytes = ptr(total)
			if used, ok := readUint(p.opts.Root, dev+"mem_info_vram_used"); ok {
				g.MemoryUsedBytes = ptr(used)
				g.MemoryUsedPercent = ptr(percent(used, total))
			}
		}
		if busy, ok := readUint(p.opts.Root, dev+"gpu_busy_percent"); ok {
			g.UtilizationPercent = ptr(float64(busy))
		}
		out = append(out, g)
	}
	return out
}

func readUint(fsys fs.FS, name string) (uint64, bool) {
	s, err := readTrimmed(fsys, name)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func na(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "N/A") || strings.Contains(s, "Not Supported") {
		return ""
	}
	return s
}

func num(s string) (float64, bool) {
	v, err := strconv.ParseFloat(na(s), 64)
	return v, err == nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func ptr[T any](v T) *T { return &v }
