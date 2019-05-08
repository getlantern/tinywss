package tinywss

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/ops"
	"github.com/xtaci/smux"
)

var _ Client = &smuxClient{}

type smuxClient struct {
	wrapped *client
	session *smux.Session
	config  *smux.Config
	mx      sync.Mutex
	closed  bool
}

func wrapClientSmux(c *client, opts *ClientOpts) Client {
	cfg := smux.DefaultConfig()
	if opts.KeepAliveInterval != 0 {
		cfg.KeepAliveInterval = opts.KeepAliveInterval
	}
	if opts.KeepAliveTimeout != 0 {
		cfg.KeepAliveTimeout = opts.KeepAliveTimeout
	}
	if opts.MaxFrameSize != 0 {
		cfg.MaxFrameSize = opts.MaxFrameSize
	}
	if opts.MaxReceiveBuffer != 0 {
		cfg.MaxReceiveBuffer = opts.MaxReceiveBuffer
	}

	return &smuxClient{
		wrapped: c,
		config:  cfg,
	}
}

// implements Client.DialContext
func (c *smuxClient) DialContext(ctx context.Context) (net.Conn, error) {
	return c.wrapped.dialOrDie.Do(ctx, c.dialContext)
}

func (c *smuxClient) dialContext(ctx context.Context) (net.Conn, error) {
	c.mx.Lock()
	defer c.mx.Unlock()

	if c.closed {
		return nil, ErrClientClosed
	}
	var err error
	for tries := 0; tries < 2; tries++ {
		if c.session == nil {
			if c.session, err = c.connect(ctx); err != nil {
				return nil, err
			}
		}

		conn, err := c.session.OpenStream()

		if err == nil {
			return conn, nil
		} else {
			c.session.Close()
			c.session = nil
		}
	}
	return nil, err
}

// implements Client.Close
func (c *smuxClient) Close() error {
	c.mx.Lock()
	c.closed = true
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	c.mx.Unlock()
	return nil
}

// implements Client.SetHeaders
func (c *smuxClient) SetHeaders(h http.Header) {
	c.wrapped.SetHeaders(h)
}

func (c *smuxClient) connect(ctx context.Context) (*smux.Session, error) {
	conn, err := c.wrapped.dialContext(ctx)
	if err != nil {
		return nil, err
	}
	session, err := smux.Client(conn, c.config)
	if err != nil {
		c.Close()
		return nil, err
	}
	return session, nil
}

var _ net.Listener = &smuxListener{}

type smuxListener struct {
	wrapped               *listener
	connections           chan net.Conn
	closed                chan struct{}
	config                *smux.Config
	numConnections        int64
	numVirtualConnections int64
	mx                    sync.Mutex
}

func wrapListenerSmux(l *listener, opts *ListenOpts) (net.Listener, error) {
	cfg := smux.DefaultConfig()
	if opts.KeepAliveInterval != 0 {
		cfg.KeepAliveInterval = opts.KeepAliveInterval
	}
	if opts.KeepAliveTimeout != 0 {
		cfg.KeepAliveTimeout = opts.KeepAliveTimeout
	}
	if opts.MaxFrameSize != 0 {
		cfg.MaxFrameSize = opts.MaxFrameSize
	}
	if opts.MaxReceiveBuffer != 0 {
		cfg.MaxReceiveBuffer = opts.MaxReceiveBuffer
	}

	ll := &smuxListener{
		wrapped:     l,
		connections: make(chan net.Conn, 1000),
		closed:      make(chan struct{}),
		config:      cfg,
	}

	ops.Go(ll.listen)
	ops.Go(ll.logStats)
	return ll, nil
}

func (l *smuxListener) listen() {
	defer l.Close()
	for {
		conn, err := l.wrapped.Accept()
		if err != nil {
			if err != ErrListenerClosed {
				log.Errorf("tinywss mux listener: %s", err)
			}
			return
		}
		l.handleConn(conn)
	}
}

func (l *smuxListener) handleConn(conn net.Conn) {
	wconn, ok := conn.(*wsConn)
	if !ok {
		log.Errorf("not handling unexpected connection type")
		conn.Close()
		return
	}
	atomic.AddInt64(&l.numConnections, 1)

	if strings.EqualFold(wconn.protocol, ProtocolMux) {
		ops.Go(func() {
			l.handleSession(wconn)
			atomic.AddInt64(&l.numConnections, -1)
		})
	} else {
		// not multiplexed
		wconn.onClose = func() {
			atomic.AddInt64(&l.numConnections, -1)
		}
		l.connections <- conn
	}
}

func (l *smuxListener) handleSession(conn *wsConn) {
	session, err := smux.Server(conn, l.config)
	if err != nil {
		log.Errorf("error handing mux connection: %s", err)
	}

	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Debugf("accepting stream: %v", err)
			return
		}
		atomic.AddInt64(&l.numVirtualConnections, 1)
		l.connections <- &wsConn{
			Conn:     stream,
			protocol: ProtocolMux,
			onClose: func() {
				atomic.AddInt64(&l.numVirtualConnections, -1)
			},
		}
	}
}

// implements net.Listener.Accept
func (l *smuxListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.connections:
		if !ok {
			return nil, ErrListenerClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, ErrListenerClosed
	}
}

// implements net.Listener.Close
func (l *smuxListener) Close() error {
	l.mx.Lock()
	defer l.mx.Unlock()
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
		return l.wrapped.Close()
	}
}

func (l *smuxListener) Addr() net.Addr {
	return l.wrapped.Addr()
}

func (l *smuxListener) logStats() {
	for {
		select {
		case <-time.After(5 * time.Second):
			log.Debugf("Connections: %d   Virtual: %d", atomic.LoadInt64(&l.numConnections), atomic.LoadInt64(&l.numVirtualConnections))
		case <-l.closed:
			log.Debugf("Connections: %d   Virtual: %d", atomic.LoadInt64(&l.numConnections), atomic.LoadInt64(&l.numVirtualConnections))
			log.Debug("Done logging stats.")
			return
		}
	}
}
