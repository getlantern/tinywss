package tinywss

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Configuration options for NewClient
type ClientOpts struct {
	URL             string
	MaxPendingDials int64
	RoundTrip       RoundTripHijacker

	// Multiplex Options
	Multiplexed       bool
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration
	MaxFrameSize      int
	MaxReceiveBuffer  int
}

type client struct {
	url       string
	rt        RoundTripHijacker
	headers   http.Header // Sent with each https connection
	dialOrDie *dialHelper
}

// NewClient constructs a new tinywss.Client with
// the specified options
func NewClient(opts *ClientOpts) Client {

	rt := opts.RoundTrip
	if rt == nil {
		rt = NewRoundTripper(nil)
	}
	c := &client{
		url:       opts.URL,
		rt:        rt,
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
	wskey, err := genKey()
	if err != nil {
		return nil, err
	}

	req, err := c.createUpgradeRequest(wskey)
	if err != nil {
		return nil, err
	}
	res, conn, err := c.rt.RoundTripHijack(req)
	if err != nil {
		return nil, err
	}
	closeOnExit := true
	defer func() {
		if closeOnExit {
			conn.Close()
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	err = c.validateResponse(res, wskey)
	if err != nil {
		return nil, err
	}

	closeOnExit = false
	return conn, nil
}

func (c *client) createUpgradeRequest(wskey string) (*http.Request, error) {

	u, err := url.Parse(c.url)
	if err != nil {
		return nil, err
	}

	hdr := cloneHeaders(c.headers)
	hdr.Set("Upgrade", "websocket")
	hdr.Set("Connection", "Upgrade")
	hdr.Set("Sec-WebSocket-Key", wskey)
	hdr.Set("Sec-WebSocket-Version", "13")

	return &http.Request{
		Method:     "GET",
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     hdr,
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
