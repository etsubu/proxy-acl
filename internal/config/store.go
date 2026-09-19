package config

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// reloadDebounce coalesces the burst of events an editor save produces
// (truncate, write, rename, ...) into a single reload.
const reloadDebounce = 250 * time.Millisecond

// Store holds the active config and swaps it atomically on reload, so
// in-flight requests never see a half-applied config.
type Store struct {
	path string
	cur  atomic.Pointer[Config]
}

// NewStore loads the config at path. It fails if the initial load fails.
func NewStore(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: abs}
	return s, s.Reload()
}

// Current returns the active config.
func (s *Store) Current() *Config { return s.cur.Load() }

// Reload loads the config file. On error the previous config stays active.
func (s *Store) Reload() error {
	cfg, err := Load(s.path)
	if err != nil {
		return err
	}
	s.cur.Store(cfg)
	zerolog.SetGlobalLevel(cfg.LogLevel)
	log.Info().Str("path", s.path).Int("subnets", cfg.Policy.SubnetCount()).Msg("config loaded")
	return nil
}

// Watch reloads the config whenever the file changes or SIGHUP is received,
// until ctx is cancelled. It returns once the watcher is set up.
func (s *Store) Watch(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	// Watch the directory rather than the file: editors and config management
	// tools often replace the file via rename, which would orphan a file watch.
	if err := w.Add(filepath.Dir(s.path)); err != nil {
		w.Close()
		return err
	}
	go s.watchLoop(ctx, w)
	return nil
}

func (s *Store) watchLoop(ctx context.Context, w *fsnotify.Watcher) {
	defer w.Close()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	debounce := time.NewTimer(reloadDebounce)
	debounce.Stop()
	defer debounce.Stop()

	reload := func(trigger string) {
		if err := s.Reload(); err != nil {
			log.Error().Err(err).Str("path", s.path).Str("trigger", trigger).Msg("config reload failed, keeping previous config")
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if filepath.Clean(ev.Name) == s.path && ev.Op != fsnotify.Chmod {
				debounce.Reset(reloadDebounce)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Error().Err(err).Msg("config watcher error")
		case <-debounce.C:
			reload("file change")
		case <-hup:
			reload("SIGHUP")
		}
	}
}
