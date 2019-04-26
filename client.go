package tinywss

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getlantern/netx"
)

// DialFN is the type used for providing a custom dialer to tinywss
type DialFN func(ctx context.Context, network, addr string) (net.Conn, error)

// DialFN instances that can be provided
var netDialer net.Dialer
var DialWithNet = netDialer.DialContext
var DialWithNetx = netx.DialContext

// Configuration options for NewClient
type ClientOpts struct {
	Addr            string
	TLSConf         *tls.Config
	Dial            DialFN // default DialWithNetx
	MaxPendingDials int64

	// Multiplex Options
	Multiplexed       bool
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration
	MaxFrameSize      int
	MaxReceiveBuffer  int
}

type client struct {
	addr      string
	tlsConf   *tls.Config
	dial      DialFN
	headers   http.Header // Sent with each https connection
	dialOrDie *dialHelper
}

// NewClient constructs a new tinywss.Client with
// the specified options
func NewClient(opts *ClientOpts) Client {
	dial := opts.Dial
	if dial == nil {
		dial = DialWithNetx
	}
	c := &client{
		addr:      opts.Addr,
		tlsConf:   opts.TLSConf,
		dial:      dial,
		headers:   make(http.Header, 0),
		dialOrDie: newDialHelper(opts.MaxPendingDials),
	}

	if !opts.Multiplexed {
		c.headers.Set("Sec-Websocket-Protocol", ProtocolRaw)
		return c
	} else {
		c.headers.Set("Sec-Websocket-Protocol", ProtocolMux)
		return wrapClientSmux(c, opts)
	}
}

// implements Client.DialContext
func (c *client) DialContext(ctx context.Context) (net.Conn, error) {
	return c.dialOrDie.Do(ctx, c.dialContext)
}

func (c *client) dialContext(ctx context.Context) (net.Conn, error) {
	tlsConf := c.tlsConf
	if tlsConf == nil {
		// fill SNI ServerName only if no explicit config is given.
		tlsConf = &tls.Config{
			ServerName: c.host(),
		}
	}

	conn, err := c.dial(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	closeOnExit := true
	defer func() {
		if closeOnExit {
			conn.Close()
		}
	}()

	tlsConn := tls.Client(conn, tlsConf)
	conn = tlsConn
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if !tlsConf.InsecureSkipVerify {
		if err := tlsConn.VerifyHostname(tlsConf.ServerName); err != nil {
			return nil, err
		}
	}

	err = c.websocketHandshake(ctx, conn)
	if err != nil {
		return nil, err
	}

	closeOnExit = false
	return conn, nil
}

func (c *client) websocketHandshake(ctx context.Context, conn net.Conn) error {
	wskey, err := genKey()
	if err != nil {
		return err
	}

	req, err := c.createUpgradeRequest(wskey)
	if err != nil {
		return err
	}
	if err = req.Write(conn); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	buf := bufio.NewReaderSize(conn, 4096)
	res, err := http.ReadResponse(buf, req)
	if err != nil {
		return err
	}
	return c.validateResponse(res, wskey)
}

func (c *client) createUpgradeRequest(wskey string) (*http.Request, error) {
	urlStr := fmt.Sprintf("https://%s/", c.addr)
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	hdr := cloneHeaders(c.headers)
	hdr.Set("Upgrade", "websocket")
	hdr.Set("Connection", "Upgrade")
	hdr.Set("Sec-WebSocket-Key", wskey)
	hdr.Set("Sec-WebSocket-Version", "13")

	// respect Host header if provided,
	// but fill it into the http.Request
	// Host field.
	vhost := c.host()
	if h := hdr.Get("Host"); h != "" {
		hdr.Del("Host")
		vhost = h
	}

	return &http.Request{
		Method:     "GET",
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     hdr,
		Host:       vhost,
	}, nil
}

func (c *client) validateResponse(res *http.Response, wskey string) error {
	if res.StatusCode != 101 {
		return handshakeErr(fmt.Sprintf("unexpected status %d", res.StatusCode))
	}
	if !headerHasValue(res.Header, "Connection", "upgrade") {
		return handshakeErr("`Connection` header is missing or invalid")
	}
	if !strings.EqualFold(res.Header.Get("Upgrade"), "websocket") {
		return handshakeErr("`Upgrade` header is missing or invalid")
	}
	if !strings.EqualFold(res.Header.Get("Sec-Websocket-Accept"), acceptForKey(wskey)) {
		return handshakeErr("`Sec-Websocket-Accept` header is missing or invalid")
	}

	proto := res.Header.Get("Sec-Websocket-Protocol")
	if !strings.EqualFold(proto, c.headers.Get("Sec-Websocket-Protocol")) {
		return handshakeErr(fmt.Sprintf("`Sec-Websocket-Protocol` header is missing or invalid (%s)", proto))
	}

	return nil
}

// implements Client.SetHeaders
func (c *client) SetHeaders(h http.Header) {
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		c.headers[k] = vv2
	}
}

// implements Client.Close
func (c *client) Close() error {
	return nil
}

func (c *client) host() string {
	host, _, err := net.SplitHostPort(c.addr)
	if err != nil {
		return c.addr
	}
	return host
}
