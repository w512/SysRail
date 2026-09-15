package linux

import (
	"errors"
	"testing"
)

func fakeStatfs(usage map[string]FSUsage) func(string) (FSUsage, error) {
	return func(path string) (FSUsage, error) {
		u, ok := usage[path]
		if !ok {
			return FSUsage{}, errors.New("permission denied")
		}
		return u, nil
	}
}

const gb = 1 << 30

func TestStorageStatus(t *testing.T) {
	p := testProvider(t, Options{Statfs: fakeStatfs(map[string]FSUsage{
		"/":                  {Total: 100 * gb, Free: 50 * gb, Available: 45 * gb, Inodes: 1000, InodesFree: 900},
		"/boot/efi":          {Total: gb, Free: gb / 20, Available: gb / 20, Inodes: 0},
		"/srv/media library": {Total: 100 * gb, Free: 8 * gb, Available: 8 * gb, Inodes: 100, InodesFree: 2},
		"/mnt/media-bind":    {Total: 1},
	})})
	m := call(t, p, "storage_get_status", `{}`)
	fss := m["filesystems"].([]any)
	byMount := map[string]map[string]any{}
	for _, f := range fss {
		fm := f.(map[string]any)
		byMount[fm["mount_point"].(string)] = fm
	}
	if len(fss) != 4 {
		t.Fatalf("want /, /boot/efi, media (deduplicated) and nas, got %v", byMount)
	}
	if _, ok := byMount["/mnt/media-bind"]; ok {
		t.Fatal("bind mount was not deduplicated")
	}
	root := byMount["/"]
	if root["used_percent"] != 52.6 || root["status"] != "ok" || root["inodes_used_percent"] != 10.0 || root["fstype"] != "ext4" {
		t.Fatalf("root: %v", root)
	}
	if efi := byMount["/boot/efi"]; efi["status"] != "critical" || efi["used_percent"] != 95.0 {
		t.Fatalf("efi: %v", efi)
	}
	if media := byMount["/srv/media library"]; media["status"] != "critical" || media["used_percent"] != 92.0 {
		t.Fatalf("media (inodes 98%%): %v", media)
	}
	if nas := byMount["/mnt/nas"]; nas["status"] != "unknown" || nas["error"] == nil || nas["read_only"] != true {
		t.Fatalf("nas: %v", nas)
	}
	warnings := m["warnings"].([]any)
	if len(warnings) != 2 || warnings[1] != "/srv/media library: inodes critical" {
		t.Fatalf("warnings: %v", warnings)
	}
}

func TestListMounts(t *testing.T) {
	p := testProvider(t, Options{})
	m := call(t, p, "storage_list_mounts", `{}`)
	mounts := m["mounts"].([]any)
	if len(mounts) != 5 || m["hidden_pseudo_mounts"] != 5.0 {
		t.Fatalf("mounts: %d hidden %v", len(mounts), m["hidden_pseudo_mounts"])
	}
	if first := mounts[0].(map[string]any); first["mount_point"] != "/" || first["source"] != "/dev/nvme0n1p2" {
		t.Fatalf("first mount: %v", first)
	}
	missing := m["fstab_not_mounted"].([]any)
	if len(missing) != 1 || missing[0].(map[string]any)["mount_point"] != "/mnt/backup" {
		t.Fatalf("fstab_not_mounted: %v", missing)
	}
	all := call(t, p, "storage_list_mounts", `{"include_pseudo":true}`)
	if len(all["mounts"].([]any)) != 10 {
		t.Fatalf("include_pseudo: %d", len(all["mounts"].([]any)))
	}
}

func TestParseMountinfo(t *testing.T) {
	m, err := parseMountinfo([]byte("36 35 98:0 /mnt1 /mnt\\040x rw,noatime master:1 shared:2 - ext3 /dev/root rw,errors=continue\n"))
	if err != nil || len(m) != 1 {
		t.Fatal(err)
	}
	e := m[0]
	if e.MountPoint != "/mnt x" || e.Root != "/mnt1" || e.FSType != "ext3" || e.Source != "/dev/root" || e.Device != "98:0" {
		t.Fatalf("%+v", e)
	}
	if _, err := parseMountinfo([]byte("garbage line\n")); err == nil {
		t.Fatal("malformed line accepted")
	}
}
