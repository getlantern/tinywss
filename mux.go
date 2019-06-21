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
	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

var _ Client = &smuxClient{}

var (
	nullCtx    = &smuxContext{}
	errTimeout = &timeoutError{}
)

type smuxContext struct {
	session *smux.Session
	conn    net.Conn // the underlying Conn
}

type smuxClient struct {
	closed   uint64
	ctx      atomic.Value
	wrapped  *client
	config   *smux.Config
	mx       sync.Mutex
	createMx sync.Mutex
}

type smuxConn struct {
	net.Conn
	next net.Conn // next Wrapped (underlying Conn)
}

func (c *smuxConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, translateSmuxErr(err)
}

func (c *smuxConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, translateSmuxErr(err)
}

func (c *smuxConn) Close() error {
	return translateSmuxErr(c.Conn.Close())
}

func (c *smuxConn) SetDeadline(t time.Time) error {
	return translateSmuxErr(c.Conn.SetDeadline(t))
}

func (c *smuxConn) SetReadDeadline(t time.Time) error {
	return translateSmuxErr(c.Conn.SetReadDeadline(t))
}

func (c *smuxConn) SetWriteDeadline(t time.Time) error {
	return translateSmuxErr(c.Conn.SetWriteDeadline(t))
}

func (c *smuxConn) Wrapped() net.Conn {
	return c.next
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
	var err error
	var session *smux.Session
	var conn, sconn net.Conn

	for tries := 0; tries < 2; tries++ {
		session, sconn, err = c.getOrCreateSession(ctx)
		if err != nil {
			continue
		}

		conn, err = session.OpenStream()
		err = translateSmuxErr(err)
		if err == nil {
			return &smuxConn{conn, sconn}, nil
		} else {
			c.sessionError(session, err)
		}
	}
	return nil, err
}

func (c *smuxClient) getOrCreateSession(ctx context.Context) (*smux.Session, net.Conn, error) {
	c.createMx.Lock()
	defer c.createMx.Unlock()

	if c.isClosed() {
		return nil, nil, ErrClientClosed
	}
	session, conn := c.curSession()
	if session != nil {
		return session, conn, nil
	}

	session, conn, err := c.connect(ctx)
	if err != nil {
		return nil, nil, err
	}

	return c.storeSession(session, conn)
}

func (c *smuxClient) sessionError(session *smux.Session, err error) {
	c.mx.Lock()
	cur, _ := c.curSession()
	if session == cur {
		c.ctx.Store(nullCtx)
	}
	c.mx.Unlock()
	session.Close()
}

func (c *smuxClient) storeSession(session *smux.Session, conn net.Conn) (*smux.Session, net.Conn, error) {
	c.mx.Lock()
	defer c.mx.Unlock()
	if c.isClosed() {
		session.Close()
		return nil, nil, ErrClientClosed
	}
	c.ctx.Store(&smuxContext{session, conn})
	return session, conn, nil
}

// implements Client.Close
func (c *smuxClient) Close() error {
	c.mx.Lock()
	atomic.StoreUint64(&c.closed, 1)
	c.mx.Unlock()

	session, _ := c.curSession()
	if session != nil {
		return session.Close()
	}
	return nil
}

func (c *smuxClient) curSession() (*smux.Session, net.Conn) {
	s, _ := c.ctx.Load().(*smuxContext)
	if s == nullCtx || s == nil {
		return nil, nil
	}
	return s.session, s.conn
}

func (c *smuxClient) isClosed() bool {
	return atomic.LoadUint64(&c.closed) == 1
}

// implements Client.SetHeaders
func (c *smuxClient) SetHeaders(h http.Header) {
	c.wrapped.SetHeaders(h)
}

func (c *smuxClient) connect(ctx context.Context) (*smux.Session, net.Conn, error) {
	conn, err := c.wrapped.dialContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	session, err := smux.Client(conn, c.config)
	err = translateSmuxErr(err)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return session, conn, nil
}

func translateSmuxErr(err error) error {
	err = errors.Cause(err)
	if err == nil {
		return err
	} else if _, ok := err.(net.Error); ok {
		return err
	} else if strings.Contains(err.Error(), "timeout") { // certain newer versions
		return errTimeout
	} else {
		return err
	}
}

var _ net.Error = &timeoutError{}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

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
	wconn, ok := conn.(*WsConn)
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

func (l *smuxListener) handleSession(conn *WsConn) {
	session, err := smux.Server(conn, l.config)
	err = translateSmuxErr(err)
	if err != nil {
		log.Errorf("error handing mux connection: %s", err)
	}

	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		err = translateSmuxErr(err)
		if err != nil {
			log.Debugf("accepting stream: %v", err)
			return
		}
		atomic.AddInt64(&l.numVirtualConnections, 1)
		l.connections <- &WsConn{
			Conn:     &smuxConn{stream, conn},
			protocol: ProtocolMux,
			onClose: func() {
				atomic.AddInt64(&l.numVirtualConnections, -1)
			},
			headers: cloneHeaders(conn.UpgradeHeaders()),
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
