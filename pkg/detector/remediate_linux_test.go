//go:build linux

package detector

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestFindAFALGModuleFiles(t *testing.T) {
	tests := []struct {
		name    string
		layout  []string
		wantRel []string
	}{
		{
			name:    "missing directory returns empty",
			layout:  nil,
			wantRel: nil,
		},
		{
			name: "uncompressed .ko",
			layout: []string{
				"kernel/crypto/algif_aead.ko",
				"kernel/crypto/algif_hash.ko",
			},
			wantRel: []string{"kernel/crypto/algif_aead.ko"},
		},
		{
			name: "compressed variants are all detected",
			layout: []string{
				"kernel/crypto/algif_aead.ko.xz",
				"backup/algif_aead.ko.zst",
				"extra/algif_aead.ko.gz",
				"unrelated/notalgif_aead.ko",
			},
			wantRel: []string{
				"backup/algif_aead.ko.zst",
				"extra/algif_aead.ko.gz",
				"kernel/crypto/algif_aead.ko.xz",
			},
		},
		{
			name: "no matches in unrelated tree",
			layout: []string{
				"kernel/crypto/aes.ko",
				"kernel/net/tcp.ko",
			},
			wantRel: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			var moduleDir string
			if tt.layout == nil {
				// Point at a path that doesn't exist.
				moduleDir = filepath.Join(root, "missing")
			} else {
				moduleDir = root
				for _, rel := range tt.layout {
					full := filepath.Join(root, rel)
					if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
						t.Fatalf("mkdir: %v", err)
					}
					if err := os.WriteFile(full, []byte("stub"), 0o644); err != nil {
						t.Fatalf("write: %v", err)
					}
				}
			}

			got, err := findAFALGModuleFiles(moduleDir)
			if err != nil {
				t.Fatalf("findAFALGModuleFiles returned error: %v", err)
			}
			sort.Strings(got)

			want := make([]string, len(tt.wantRel))
			for i, rel := range tt.wantRel {
				want[i] = filepath.Join(root, rel)
			}
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("got %d matches, want %d: got=%v want=%v", len(got), len(want), got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("match[%d] = %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}

func TestRemoveAFALGModuleFilesIn(t *testing.T) {
	t.Run("removes every matching file and reports paths", func(t *testing.T) {
		dir := t.TempDir()
		paths := []string{
			filepath.Join(dir, "kernel/crypto/algif_aead.ko.xz"),
			filepath.Join(dir, "extra/algif_aead.ko"),
		}
		for _, p := range paths {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(p, []byte("stub"), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		// A sibling file that must not be touched.
		keep := filepath.Join(dir, "kernel/crypto/aes.ko")
		if err := os.WriteFile(keep, []byte("keep"), 0o644); err != nil {
			t.Fatalf("write keep: %v", err)
		}

		ok, detail := removeAFALGModuleFilesIn(dir)
		if !ok {
			t.Fatalf("expected success, got: %s", detail)
		}
		for _, p := range paths {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("%s should have been removed, stat err = %v", p, err)
			}
		}
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("sibling file %s should still exist: %v", keep, err)
		}
	})

	t.Run("missing directory is idempotent success", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "no-such-dir")
		ok, detail := removeAFALGModuleFilesIn(dir)
		if !ok {
			t.Fatalf("expected idempotent success when directory is missing, got: %s", detail)
		}
	})

	t.Run("no matching file is idempotent success", func(t *testing.T) {
		dir := t.TempDir()
		other := filepath.Join(dir, "kernel/crypto/aes.ko")
		if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(other, []byte("stub"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		ok, _ := removeAFALGModuleFilesIn(dir)
		if !ok {
			t.Fatalf("expected idempotent success when no algif_aead file is present")
		}
		if _, err := os.Stat(other); err != nil {
			t.Errorf("unrelated file should still exist: %v", err)
		}
	})
}
