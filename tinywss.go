// tinywss
//
// A module for establishing a rudimentary secure "websocket".
// Performs websocket handshake, but does not actually
// enforce the websocket protocol for data exchanged afterwards.
// Exposes a dialer and listener returning objects conforming to
// net.Conn and net.Listener.
//
// It is not meant to be compatible with anything but itself.
//
package tinywss

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/getlantern/golog"
)

var (
	ErrListenerClosed       = errors.New("listener closed")
	ErrDialerClosed         = errors.New("dialer closed")
	log                     = golog.LoggerFor("tinywss")
	defaultHandshakeTimeout = 10 * time.Second
	defaultProtocols        = []string{ProtocolMux, ProtocolRaw}
)

const (
	ProtocolRaw            = "tinywss-raw"  // raw connection
	ProtocolMux            = "tinywss-smux" // multiplexed protocol
	defaultMaxPendingDials = 1024
)

// HandshakeError is returned when handshake expectations fail
type HandshakeError struct {
	message string
}

func (e HandshakeError) Error() string { return e.message }

func handshakeErr(message string) error {
	return HandshakeError{
		message: "websocket handshake: " + message,
	}
}

type wsConn struct {
	net.Conn
	Protocol string
	onClose  func()
}

// Wrapped implements the interface netx.WrappedConn
func (c *wsConn) Wrapped() net.Conn {
	return c.Conn
}

// implements net.Conn.Close()
func (c *wsConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type Client interface {

	// DialContext attempts to dial the configured server, returning an error if
	// the context given expires before the server can be contacted.
	DialContext(ctx context.Context) (net.Conn, error)

	// SetHeaders sets additional custom headers sent on each HTTP connection
	SetHeaders(header http.Header)

	// Close shuts down any resources associated with the client
	Close() error
}

// This interface is used to make the http upgrade request and hijack the
// the underlying connection.
type RoundTripHijacker interface {
	RoundTripHijack(*http.Request) (*http.Response, net.Conn, error)
}
