//go:build linux

package proc

import (
	"os"
	"strconv"
)

// List returns every running interceptor process (excluding the caller).
func List() ([]Proc, error) {
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return listViaPgrep(self)
	}

	var procs []Proc
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		if p, ok := procFromProcFS(pid); ok {
			procs = append(procs, p)
		}
	}
	return procs, nil
}

// aliveInterceptor reports whether pid is alive AND /proc identifies it as an
// Interceptor binary, closing the same PID-reuse race that aliveInterceptor
// guards against on Windows. Falls back to the generic liveness check when
// /proc isn't readable (e.g. sandboxed environments without procfs).
func aliveInterceptor(pid int) bool {
	if _, ok := procFromProcFS(pid); ok {
		return true
	}
	if _, err := os.Stat("/proc"); err != nil {
		return Alive(pid)
	}
	return false
}
