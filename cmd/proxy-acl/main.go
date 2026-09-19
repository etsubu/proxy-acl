// Command proxy-acl is a forward HTTP/HTTPS proxy that enforces per-subnet
// destination allow/deny rules loaded from a hot-reloaded YAML file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"proxy-acl/internal/config"
	"proxy-acl/internal/dnscache"
	"proxy-acl/internal/proxy"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML ACL config (reloaded on change and on SIGHUP)")
	listen := flag.String("listen", ":3128", "listen address")
	logFormat := flag.String("log-format", "json", "log format: json or console")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	zerolog.TimeFieldFormat = time.RFC3339
	switch *logFormat {
	case "json":
	case "console":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.DateTime})
	default:
		log.Fatal().Str("log_format", *logFormat).Msg("unknown log format")
	}

	store, err := config.NewStore(*configPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", *configPath).Msg("failed to load config")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := store.Watch(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to watch config")
	}

	p := proxy.New(store.Current, dnscache.New(net.DefaultResolver))
	go p.Maintain(ctx)

	srv := &http.Server{
		Handler: p,
		// No read/write timeouts: a proxy can't know how long a legitimate
		// upload or download takes. Tunnels are hijacked and have their own
		// idle timeout.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}
	log.Info().Str("listen", *listen).Str("version", version).Msg("proxy listening")
	if err := srv.Serve(p.Listener(ln)); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msg("server failed")
	}
}
