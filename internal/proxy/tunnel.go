package proxy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var errTunnelIdle = errors.New("tunnel idle timeout")

// tunnelCopy copies between client and upstream until both directions are
// done, or until neither has carried data for idle (0: never). Pass the raw
// connections: between two *net.TCPConn, io.Copy uses splice(2) and data
// never passes through user space; a wrapper would disable that.
func tunnelCopy(client, upstream net.Conn, idle time.Duration) (sent, received int64, err error) {
	t := &tunnelState{client: client, upstream: upstream, idle: idle}
	t.touch()
	done := make(chan error, 1)
	go func() {
		var err error
		sent, err = t.pipe(upstream, client)
		done <- err
	}()
	received, err = t.pipe(client, upstream)
	err = errors.Join(err, <-done)
	t.closeBoth()
	return sent, received, err
}

type tunnelState struct {
	client, upstream net.Conn
	idle             time.Duration
	last             atomic.Int64 // unix nanoseconds of the last data in either direction
	closeOnce        sync.Once
}

func (t *tunnelState) touch() { t.last.Store(time.Now().UnixNano()) }

func (t *tunnelState) idleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - t.last.Load())
}

func (t *tunnelState) closeBoth() {
	t.closeOnce.Do(func() {
		t.client.Close()
		t.upstream.Close()
	})
}

// pipe copies src to dst. On EOF it half-closes dst so the other direction
// can finish; on any error it closes both connections to stop the other
// direction too.
//
// With an idle timeout, a read deadline wakes the copy a few times per
// timeout; the tunnel closes once *neither* direction has carried data for
// the whole timeout. A deadline only interrupts splice(2) between reads,
// so no data is lost, and the copy stays one long splice in between.
func (t *tunnelState) pipe(dst, src net.Conn) (int64, error) {
	check := max(t.idle/4, 10*time.Millisecond)
	var total int64
	for {
		if t.idle > 0 {
			src.SetReadDeadline(time.Now().Add(check))
		}
		n, err := io.Copy(dst, src)
		total += n
		if n > 0 {
			t.touch()
		}
		switch {
		case !errors.Is(err, os.ErrDeadlineExceeded):
			return total, t.finish(dst, err)
		case t.idleFor() >= t.idle:
			t.closeBoth()
			return total, errTunnelIdle
		}
	}
}

func (t *tunnelState) finish(dst net.Conn, err error) error {
	if err == nil { // src reached EOF
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
			return nil
		}
	}
	t.closeBoth()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
