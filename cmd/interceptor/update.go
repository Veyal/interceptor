package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Veyal/interceptor/internal/version"
)

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	check := fs.Bool("check", false, "only report whether an update is available")
	force := fs.Bool("force", false, "reinstall even if already on this version")
	ver := fs.String("version", "", "install a specific version (e.g. 0.7.0) instead of latest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return version.Update(ctx, version.UpdateOptions{
		Version: *ver,
		Check:   *check,
		Force:   *force,
		Out:     os.Stdout,
	})
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Interceptor — intercepting HTTP/HTTPS proxy

Usage:
  interceptor              start the proxy and control UI
  interceptor launcher     dashboard to run multiple projects at once, each its own instance
  interceptor mcp          run the MCP server on stdio (see GET /api/mcp for HTTP /mcp)
  interceptor update       install the latest release
  interceptor stop         stop all running instances
  interceptor version      print the running version

Common flags / env:
  --project <name|path>    open a specific project (or INTERCEPTOR_PROJECT)
  --open                   open the UI in your browser on start (or INTERCEPTOR_OPEN_BROWSER)
  --control-port <port>    control UI/API port on 127.0.0.1 (e.g. 9967 for a second instance)
  --control-addr host:port full control listen address (overrides --control-port; also --control_port)
  INTERCEPTOR_CONTROL_ADDR same as --control-addr when the flag is not set
  INTERCEPTOR_PROXY_ADDR   proxy listen address override (lets a second instance pick its own port)

Launcher flags:
  --addr host:port         dashboard listen address (default 127.0.0.1:9965)

Update flags:
  --check                  report whether an update is available
  --version vX.Y.Z         install a specific release
  --force                  reinstall even when already up to date

Stop flags:
  --force, -f              skip graceful shutdown and force-kill immediately
  --timeout 6s             grace period before force-kill (default 6s)

Examples:
  interceptor update
  interceptor update --check
  interceptor update --version 0.6.0
  interceptor stop
  interceptor stop --force
  interceptor launcher

Updates download a prebuilt binary from GitHub Releases when one is attached
for your OS/arch; otherwise `+"`go install github.com/Veyal/interceptor/cmd/interceptor@latest`"+` is used.
`)
}
