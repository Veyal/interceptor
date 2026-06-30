//go:build !windows

package proc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

func procFromProcFS(pid int) (Proc, bool) {
	dir := filepath.Join("/proc", strconv.Itoa(pid))

	commBytes, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return Proc{}, false
	}
	comm := strings.TrimSpace(string(commBytes))

	exePath, _ := os.Readlink(filepath.Join(dir, "exe"))
	exeBase := baseFromPath(exePath)

	if matchesInterceptor(comm) {
		return Proc{PID: pid, Path: exePath}, true
	}
	if exeBase != "" && matchesInterceptor(exeBase) {
		return Proc{PID: pid, Path: exePath}, true
	}
	return Proc{}, false
}

func listViaPgrep(self int) ([]Proc, error) {
	out, err := exec.Command("pgrep", "-x", unixBinaryName).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("pgrep: %w", err)
	}

	var procs []Proc
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil || pid == self {
			continue
		}
		if p, ok := procFromProcFS(pid); ok {
			procs = append(procs, p)
		} else {
			procs = append(procs, Proc{PID: pid})
		}
	}
	return procs, nil
}

// Graceful sends SIGTERM to pid.
func Graceful(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// Force sends SIGKILL to pid.
func Force(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

// Alive reports whether pid still exists.
func Alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
