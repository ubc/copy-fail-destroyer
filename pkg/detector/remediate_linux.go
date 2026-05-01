package detector

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	modprobeConfPath = "/host/run/modprobe.d/disable-algif-aead.conf"
	modprobeRule     = "install algif_aead /bin/false\n"
)

// modulesBasePath is the host's /lib/modules tree mounted into the container.
// Declared as a var so tests can point it at a temporary directory.
var modulesBasePath = "/host/lib/modules"

// algifAEADModuleNames lists every filename the algif_aead module may have on
// disk depending on the distribution's compression scheme.
var algifAEADModuleNames = map[string]struct{}{
	"algif_aead.ko":     {},
	"algif_aead.ko.xz":  {},
	"algif_aead.ko.zst": {},
	"algif_aead.ko.gz":  {},
}

// UnloadAFALGModule attempts to unload the algif_aead kernel module, which
// provides the attack surface for CVE-2026-31431. Requires CAP_SYS_MODULE.
// Returns true if the module was successfully unloaded or was not loaded.
func UnloadAFALGModule() (unloaded bool, detail string) {
	// O_NONBLOCK makes delete_module return immediately rather than waiting
	// for the module reference count to drop.
	err := unix.DeleteModule("algif_aead", unix.O_NONBLOCK)
	if err == nil {
		return true, "algif_aead module unloaded successfully"
	}

	// ENOENT means the module is not loaded — that's fine.
	if err == unix.ENOENT {
		return true, "algif_aead module is not loaded"
	}

	return false, fmt.Sprintf("failed to unload algif_aead: %v", err)
}

// BlacklistAFALGModule writes a modprobe rule to prevent the kernel from
// auto-loading algif_aead. The host's /etc must be mounted at /host/etc.
// Returns true if the blacklist is already in place or was written successfully.
func BlacklistAFALGModule() (applied bool, detail string) {
	// Check if already in place.
	existing, err := os.ReadFile(modprobeConfPath)
	if err == nil && string(existing) == modprobeRule {
		return true, "modprobe blacklist already in place"
	}

	if err := os.WriteFile(modprobeConfPath, []byte(modprobeRule), 0644); err != nil {
		return false, fmt.Sprintf("failed to write modprobe blacklist: %v", err)
	}

	return true, "modprobe blacklist written to " + modprobeConfPath
}

// RemoveAFALGModuleFile deletes the algif_aead kernel module file(s) from
// /host/lib/modules/<kernel release>/, so the module cannot be loaded again
// even after a reboot or removal of the modprobe blacklist. The host's
// /lib/modules tree must be mounted at /host/lib/modules with write access.
// Returns true if every matching file was deleted, or if no matching file was
// present (idempotent — already removed, or compiled into the kernel).
func RemoveAFALGModuleFile() (removed bool, detail string) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, fmt.Sprintf("uname failed: %v", err)
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")

	moduleDir := filepath.Join(modulesBasePath, release)
	return removeAFALGModuleFilesIn(moduleDir)
}

// removeAFALGModuleFilesIn is the directory-scoped worker behind
// RemoveAFALGModuleFile. Splitting it out lets tests exercise the file
// discovery and deletion logic with a temp directory.
func removeAFALGModuleFilesIn(moduleDir string) (removed bool, detail string) {
	matches, err := findAFALGModuleFiles(moduleDir)
	if err != nil {
		return false, fmt.Sprintf("walking %s: %v", moduleDir, err)
	}

	if len(matches) == 0 {
		return true, fmt.Sprintf("no algif_aead module file found under %s (already removed or built-in)", moduleDir)
	}

	var failures []string
	for _, path := range matches {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
		}
	}
	if len(failures) > 0 {
		return false, "failed to remove algif_aead module file(s): " + strings.Join(failures, "; ")
	}

	return true, fmt.Sprintf("removed %d algif_aead module file(s) under %s: %s",
		len(matches), moduleDir, strings.Join(matches, ", "))
}

// findAFALGModuleFiles walks moduleDir and returns paths to any algif_aead
// kernel module file (.ko, .ko.xz, .ko.zst, .ko.gz). A missing moduleDir
// returns an empty slice with no error — there is nothing to remove.
func findAFALGModuleFiles(moduleDir string) ([]string, error) {
	if _, err := os.Stat(moduleDir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	var matches []string
	err := filepath.WalkDir(moduleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable subtrees rather than aborting the whole walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if _, ok := algifAEADModuleNames[d.Name()]; ok {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", moduleDir, err)
	}
	return matches, nil
}
