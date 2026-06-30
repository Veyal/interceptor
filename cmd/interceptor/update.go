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
  interceptor mcp          run the MCP server on stdio (see GET /api/mcp for HTTP /mcp)
  interceptor update       install the latest release
  interceptor version      print the running version

Common flags / env:
  --project <name|path>    open a specific project (or INTERCEPTOR_PROJECT)
  --open                   open the UI in your browser on start (or INTERCEPTOR_OPEN_BROWSER)
  INTERCEPTOR_CONTROL_ADDR control-plane listen addr (default 127.0.0.1:9966;
                           set e.g. 127.0.0.1:9967 to run a second instance)

Update flags:
  --check                  report whether an update is available
  --version vX.Y.Z         install a specific release
  --force                  reinstall even when already up to date

Examples:
  interceptor update
  interceptor update --check
  interceptor update --version 0.6.0

Updates download a prebuilt binary from GitHub Releases when one is attached
for your OS/arch; otherwise `+"`go install github.com/Veyal/interceptor/cmd/interceptor@latest`"+` is used.
`)
}
