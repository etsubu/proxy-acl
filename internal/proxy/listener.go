package proxy

import (
	"io"
	"net"
	"net/netip"
)

// listener wraps ln so connections are vetted as they are accepted: clients
// outside every subnet are dropped before anything is read from them, and
// the per-client and total connection limits are enforced.
func (p *Proxy) listener(ln net.Listener) net.Listener {
	return &listener{Listener: ln, p: p}
}

type listener struct {
	net.Listener
	p *Proxy
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if admitted := l.p.admit(c); admitted != nil {
			return admitted, nil
		}
	}
}

func (p *Proxy) admit(c net.Conn) net.Conn {
	client := remoteAddr(c.RemoteAddr())
	cfg := p.config()
	subnet := cfg.Policy.SubnetOf(client)
	if subnet == nil {
		p.logRejected(client, "", "client not in any subnet")
		_ = c.Close()
		return nil
	}
	release, err := p.clients.Acquire(client, cfg.ClientLimits(subnet), cfg.TotalConnections)
	if err != nil {
		p.logRejected(client, subnet.Name(), err.Error())
		_ = c.Close()
		return nil
	}
	return &clientConn{Conn: c, release: release}
}

// clientConn frees the client's connection slot when closed, whichever
// code path closes it: the HTTP server, goproxy, or a tunnel.
type clientConn struct {
	net.Conn
	release func()
}

func (c *clientConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// The HTTP server looks for these on *net.TCPConn: CloseWrite for a graceful
// close (so a client doesn't get a reset instead of its 403), ReadFrom for
// zero-copy response bodies. Forward them.

func (c *clientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *clientConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.Conn}, r)
}

// unwrap returns the underlying connection, which tunnels need for splice.
func unwrap(c net.Conn) net.Conn {
	if cc, ok := c.(*clientConn); ok {
		return cc.Conn
	}
	return c
}

func remoteAddr(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap.Addr().Unmap()
}
