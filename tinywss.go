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
	"errors"
	"time"

	"github.com/getlantern/golog"
)

var (
	ErrListenerClosed       = errors.New("listener closed")
	ErrDialerClosed         = errors.New("dialer closed")
	log                     = golog.LoggerFor("tinywss")
	defaultHandshakeTimeout = 10 * time.Second
)

const (
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
