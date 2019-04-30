package tinywss

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/ops"
)

// Configuration options for ListenAddr
type ListenOpts struct {
	Addr             string
	CertFile         string
	KeyFile          string
	TLSConf          *tls.Config
	HandshakeTimeout time.Duration
	Listener         net.Listener // wrap this listener if provided
	Protocols        []string     // allowed protocols

	// Multiplex options
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration
	MaxFrameSize      int
	MaxReceiveBuffer  int
}

// ListenAddr starts a tinywss server listening at the
// configured address.
func ListenAddr(opts *ListenOpts) (net.Listener, error) {
	l, err := listenAddr(opts)
	if err != nil {
		return nil, err
	}

	if l.supportsProtocol(ProtocolMux) {
		return wrapListenerSmux(l, opts)
	} else {
		return l, nil
	}
}

func listenAddr(opts *ListenOpts) (*listener, error) {
	handshakeTimeout := opts.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}

	var err error
	ll := opts.Listener
	if ll == nil {
		ll, err = net.Listen("tcp", opts.Addr)
		if err != nil {
			return nil, err
		}
	} else if opts.Addr != "" {
		return nil, fmt.Errorf("tinywss: cannot specify address and wrapped listener")
	}

	l := &listener{
		connections:      make(chan net.Conn, 1000),
		closed:           make(chan struct{}),
		handshakeTimeout: handshakeTimeout,
		innerListener:    ll,
	}

	var protos []string
	if len(opts.Protocols) > 0 {
		protos = opts.Protocols
	} else {
		protos = defaultProtocols
	}
	l.protocols = make([]string, len(protos))
	copy(l.protocols, protos)

	l.srv = &http.Server{
		Addr:      opts.Addr,
		Handler:   http.HandlerFunc(l.handleRequest),
		TLSConfig: opts.TLSConf,
	}

	ops.Go(func() {
		l.listen(opts.CertFile, opts.KeyFile)
	})
	return l, nil
}

var _ net.Listener = &listener{}

type listener struct {
	srv              *http.Server
	connections      chan net.Conn
	closed           chan struct{}
	mx               sync.Mutex
	innerListener    net.Listener
	protocols        []string
	handshakeTimeout time.Duration
}

func (l *listener) listen(certFile, keyFile string) {
	err := l.srv.ServeTLS(l.innerListener, certFile, keyFile)
	if err != http.ErrServerClosed {
		log.Errorf("tinywss listener: %s", err)
	}
	l.Close()
}

// implements net.Listener.Accept
func (l *listener) Accept() (net.Conn, error) {
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
func (l *listener) Close() error {
	l.mx.Lock()
	defer l.mx.Unlock()
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
		return l.srv.Close()
	}
}

// implements net.Listener.Addr
func (l *listener) Addr() net.Addr {
	return l.innerListener.Addr()
}

func (l *listener) handleRequest(w http.ResponseWriter, r *http.Request) {
	c, err := l.upgrade(w, r)
	if err != nil {
		if _, ok := err.(HandshakeError); ok {
			log.Debugf("upgrading request: %s", err)
		} else {
			log.Errorf("upgrading request: %s", err)
		}
		return
	}
	l.connections <- c
}

func (l *listener) upgrade(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if r.Method != "GET" {
		sendError(w, http.StatusBadRequest)
		return nil, handshakeErr("request method must be GET")
	}

	if !headerHasValue(r.Header, "Connection", "upgrade") {
		sendError(w, http.StatusBadRequest)
		return nil, handshakeErr("`Connection` header is missing or invalid")
	}

	if !headerHasValue(r.Header, "Upgrade", "websocket") {
		sendError(w, http.StatusBadRequest)
		return nil, handshakeErr("`Upgrade` header is missing or invalid")
	}

	wskey := r.Header.Get("Sec-Websocket-Key")
	if wskey == "" {
		sendError(w, http.StatusBadRequest)
		return nil, handshakeErr("`Sec-WebSocket-Key' header is missing or invalid")
	}

	wsproto := r.Header.Get("Sec-Websocket-Protocol")
	if !l.supportsProtocol(wsproto) {
		sendError(w, http.StatusBadRequest)
		return nil, handshakeErr(fmt.Sprintf("`Sec-WebSocket-Protocol' header is missing or invalid (%s)", wsproto))
	}

	h, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("response was not http.Hijacker")
	}
	conn, buf, err := h.Hijack()

	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if buf.Reader.Buffered() > 0 {
		conn.Close()
		return nil, handshakeErr("request payload before handshake")
	}

	hdr := make(http.Header, 0)
	hdr.Set("Connection", "Upgrade")
	hdr.Set("Upgrade", "websocket")
	hdr.Set("Sec-WebSocket-Accept", acceptForKey(wskey))
	hdr.Set("Sec-WebSocket-Protocol", wsproto)

	res := bytes.NewBufferString("HTTP/1.1 101 Switching Protocols\r\n")
	hdr.Write(res)
	res.WriteString("\r\n")

	if l.handshakeTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(l.handshakeTimeout))
	}
	if _, err = conn.Write(res.Bytes()); err != nil {
		conn.Close()
		return nil, err
	}
	if l.handshakeTimeout > 0 {
		conn.SetWriteDeadline(time.Time{})
	}

	return &wsConn{conn, wsproto, nil}, nil
}

func (l *listener) supportsProtocol(p string) bool {
	for _, proto := range l.protocols {
		if strings.EqualFold(proto, p) {
			return true
		}
	}
	return false
}
