// Command proxy-acl is a forward HTTP/HTTPS proxy that enforces per-subnet
// destination allow/deny rules loaded from a hot-reloaded YAML file.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
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
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("proxy-acl failed")
	}
}

// run is separate from main so that every failure path unwinds the defers
// instead of exiting from under them.
func run() error {
	configPath := flag.String("config", "config.yaml", "path to the YAML ACL config (reloaded on change and on SIGHUP)")
	listen := flag.String("listen", ":3128", "listen address")
	logFormat := flag.String("log-format", "json", "log format: json or console")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	zerolog.TimeFieldFormat = time.RFC3339
	switch *logFormat {
	case "json":
	case "console":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.DateTime})
	default:
		return fmt.Errorf("unknown log format %q", *logFormat)
	}

	// The log level lives in the config file, so every load applies it here
	// rather than from inside the store.
	store, err := config.NewStore(*configPath, func(cfg *config.Config) {
		zerolog.SetGlobalLevel(cfg.LogLevel)
	})
	if err != nil {
		return fmt.Errorf("load config %s: %w", *configPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := store.Watch(ctx); err != nil {
		return fmt.Errorf("watch config: %w", err)
	}

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	log.Info().Str("listen", *listen).Str("version", version).Msg("proxy listening")

	return proxy.New(store.Current, dnscache.New(net.DefaultResolver)).Serve(ctx, ln)
}
