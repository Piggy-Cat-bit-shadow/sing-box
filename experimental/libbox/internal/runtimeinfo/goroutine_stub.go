//go:build !badlinkname || !tfogo_checklinkname0

package runtimeinfo

func collectGoroutines() *GoroutineReport {
	return nil
}
