package tinywss

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/getlantern/ops"
	"golang.org/x/sync/semaphore"
)

var magic = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

func acceptForKey(k string) string {
	h := sha1.New()
	h.Write([]byte(k))
	h.Write(magic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func genKey() (string, error) {
	p := make([]byte, 16)
	if _, err := rand.Read(p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

func cloneHeaders(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func headerHasValue(h http.Header, key, value string) bool {
	for _, v := range h[key] {
		if strings.EqualFold(value, v) {
			return true
		}
	}
	return false
}

func sendError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

// cargo culted from net/http, used in ListenAndServeTLS
//
// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// helps wrap a dial function that may-or-may-not respect the given
// Context so that it always returns when the Context is done.
// Uses a limited number of goroutines.  If goroutes are exhausted,
// an error is immediately returned.
type dialHelper struct {
	dialCap *semaphore.Weighted
}

// creats a new dialHelper.  The number of
// goroutines used is limited by maxDials if a positive
// integer is given.
func newDialHelper(maxDials int64) *dialHelper {
	if maxDials <= 0 {
		maxDials = defaultMaxPendingDials
	}
	return &dialHelper{
		dialCap: semaphore.NewWeighted(maxDials),
	}
}

func (c *dialHelper) Do(ctx context.Context, dial func(ctx context.Context) (net.Conn, error)) (net.Conn, error) {
	var err error
	var conn net.Conn

	err = c.dialCap.Acquire(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("maximum pending dials reached: %v", err)
	}

	closeConn := true
	dialDone := make(chan struct{})
	exited := make(chan struct{})
	defer close(exited)

	ops.Go(func() {
		defer c.dialCap.Release(1)
		conn, err = dial(ctx)
		close(dialDone)
		<-exited
		if closeConn && conn != nil {
			conn.Close()
		}
	})

	select {
	case <-dialDone:
		closeConn = false
		return conn, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
