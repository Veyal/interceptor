// Command interceptor runs the Interceptor HTTP proxy.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Veyal/interceptor/internal/capture"
	"github.com/Veyal/interceptor/internal/proxy"
	"github.com/Veyal/interceptor/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".interceptor")

	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	addr := "127.0.0.1:8080"
	if v, ok, _ := st.GetSetting("proxy.addr"); ok && v != "" {
		addr = v
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{Handler: proxy.New(st, capture.New(st), nil, nil, nil)}
	log.Printf("Interceptor proxy listening on http://%s (data: %s)", addr, dir)

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	log.Println("shutting down...")
	return srv.Shutdown(ctx)
}
