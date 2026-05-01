//go:build !linux

package detector

// UnloadAFALGModule is a no-op on non-Linux platforms.
func UnloadAFALGModule() (unloaded bool, detail string) {
	return false, "module unloading is only supported on Linux"
}

// BlacklistAFALGModule is a no-op on non-Linux platforms.
func BlacklistAFALGModule() (applied bool, detail string) {
	return false, "modprobe blacklist is only supported on Linux"
}

// RemoveAFALGModuleFile is a no-op on non-Linux platforms.
func RemoveAFALGModuleFile() (removed bool, detail string) {
	return false, "module file removal is only supported on Linux"
}
