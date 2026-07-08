//go:build darwin

package proc

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// List returns every running interceptor process (excluding the caller).
// macOS has no /proc — use pgrep directly.
func List() ([]Proc, error) {
	return listViaPgrep(os.Getpid())
}

// aliveInterceptor reports whether pid is alive AND its command name is an
// Interceptor binary, closing the same PID-reuse race that aliveInterceptor
// guards against on Windows/Linux. macOS has no /proc, but `ps -p <pid> -o
// comm=` is a cheap, single-process query — no need to fall back to the
// generic Alive(pid) here.
func aliveInterceptor(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(out))
	if comm == "" {
		return false
	}
	return matchesInterceptor(baseFromPath(comm))
}
