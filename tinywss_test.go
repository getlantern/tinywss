package tinywss

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/netx"
	"github.com/stretchr/testify/assert"
)

const (
	authHeader = "X-Auth-Foo"
	authValue  = "BarBarBar"
)

func TestEchoRaw(t *testing.T) {
	l, err := startEchoServerOptions([]string{ProtocolMux, ProtocolRaw}, true)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	c := testClientFor(l, false)

	for i := 0; i < 3; i++ {
		if !_tryDialAndEcho(t, c) {
			return
		}
	}
}

func TestEchoMux(t *testing.T) {
	l, err := startEchoServerOptions([]string{ProtocolMux, ProtocolRaw}, true)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	c := testClientFor(l, true)

	for i := 0; i < 3; i++ {
		if !_tryDialAndEcho(t, c) {
			return
		}
	}
}

func TestEchoRawAndMux(t *testing.T) {
	l, err := startEchoServerOptions([]string{ProtocolMux, ProtocolRaw}, true)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	clients := []Client{
		testClientFor(l, true),
		testClientFor(l, false),
	}
	for _, c := range clients {
		for i := 0; i < 3; i++ {
			if !_tryDialAndEcho(t, c) {
				return
			}
		}
	}
}

func TestParallel(t *testing.T) {
	l, err := startEchoServerOptions([]string{ProtocolMux, ProtocolRaw}, true)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	clients := []Client{
		testClientFor(l, true),
		testClientFor(l, false),
	}

	wg := &sync.WaitGroup{}
	var fails int64

	for i := 0; i < 25; i++ {
		for _, c := range clients {
			cc := c
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !_tryDialAndEcho(t, cc) {
					atomic.AddInt64(&fails, 1)
				}
			}()
		}
	}
	wg.Wait()

	assert.Equal(t, fails, int64(0))
}

func _tryDialAndEcho(t *testing.T, c Client) bool {
	testHdr := make(http.Header, 1)
	testHdr.Set(authHeader, authValue)
	c.SetHeaders(testHdr)

	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, 1*time.Second)
	conn, err := c.DialContext(ctx)
	if !assert.NoError(t, err) {
		return false
	}

	buf := make([]byte, 512)
	_, err = rand.Read(buf)
	if !assert.NoError(t, err) {
		return false
	}

	_, err = conn.Write(buf)
	if !assert.NoError(t, err) {
		return false
	}

	buf2 := make([]byte, 512)
	_, err = io.ReadFull(conn, buf2)
	if !assert.NoError(t, err) {
		return false
	}

	if !assert.Equal(t, buf, buf2) {
		return false
	}
	conn.Close()
	return true
}

// tests timeout if server never accepts connection
func TestDialTimeout1(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	clients := []Client{
		testClientFor(l, true),
		testClientFor(l, false),
	}
	for _, c := range clients {
		ctx := context.Background()
		ctx, _ = context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := c.DialContext(ctx)
		assert.NotNil(t, err)
		assert.Equal(t, "context deadline exceeded", err.Error())
	}
}

// tests timeout if server never replies to handshake
func TestDialTimeout2(t *testing.T) {
	laddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	l, err := net.ListenTCP("tcp", laddr)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			time.Sleep(150 * time.Millisecond)
			conn.Close()
		}
	}()

	clients := []Client{
		testClientFor(l, true),
		testClientFor(l, false),
	}

	for _, c := range clients {
		ctx := context.Background()
		ctx, _ = context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := c.DialContext(ctx)
		assert.NotNil(t, err)
		assert.Equal(t, "context deadline exceeded", err.Error())
	}
}

// tests timeout if server never replies with http response
func TestDialTimeout3(t *testing.T) {
	srvTLSConf, err := generateTLSConfig()
	if !assert.NoError(t, err) {
		return
	}

	l, err := tls.Listen("tcp", ":0", srvTLSConf)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			time.Sleep(150 * time.Millisecond)
			conn.Close()
		}
	}()

	clients := []Client{
		testClientFor(l, true),
		testClientFor(l, false),
	}
	for _, c := range clients {
		ctx := context.Background()
		ctx, _ = context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := c.DialContext(ctx)
		assert.NotNil(t, err)
		assert.Equal(t, "context deadline exceeded", err.Error())
	}
}

// tests timeout if server replies but takes too long
func TestDialTimeout4(t *testing.T) {
	srvTLSConf, err := generateTLSConfig()
	if !assert.NoError(t, err) {
		return
	}

	ll, err := net.Listen("tcp", ":0")
	if !assert.NoError(t, err) {
		return
	}
	defer ll.Close()
	addr := ll.Addr().String()

	tl := &listener{protocols: []string{ProtocolMux, ProtocolRaw}}
	handleRequest := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		tl.upgrade(w, r)
	}
	srv := &http.Server{
		Addr:      addr,
		Handler:   http.HandlerFunc(handleRequest),
		TLSConfig: srvTLSConf,
	}

	go func() {
		srv.ServeTLS(ll, "", "")
	}()

	clients := []Client{
		testClientFor(ll, true),
		testClientFor(ll, false),
	}

	for _, c := range clients {
		ctx := context.Background()
		ctx, _ = context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := c.DialContext(ctx)
		if !assert.NotNil(t, err) {
			continue
		}
		assert.Equal(t, "context deadline exceeded", err.Error())
	}
}

func TestBadResponse(t *testing.T) {
	srvTLSConf, err := generateTLSConfig()
	if !assert.NoError(t, err) {
		return
	}

	ll, err := net.Listen("tcp", ":0")
	if !assert.NoError(t, err) {
		return
	}
	defer ll.Close()
	addr := ll.Addr().String()

	var statusCode int
	var adjustHeaders func(h http.Header)
	handleRequest := func(w http.ResponseWriter, r *http.Request) {
		wskey := r.Header.Get("Sec-Websocket-Key")
		wsproto := r.Header.Get("Sec-Websocket-Protocol")

		hdr := w.Header()
		hdr.Set("Connection", "Upgrade")
		hdr.Set("Upgrade", "websocket")
		hdr.Set("Sec-WebSocket-Accept", acceptForKey(wskey))
		hdr.Set("Sec-WebSocket-Protocol", wsproto)
		adjustHeaders(hdr)
		w.WriteHeader(statusCode)
	}
	srv := &http.Server{
		Addr:      addr,
		Handler:   http.HandlerFunc(handleRequest),
		TLSConfig: srvTLSConf,
	}

	go func() {
		srv.ServeTLS(ll, "", "")
	}()

	c := testClientFor(ll, false)

	ctx := context.Background()

	statusCode = 101
	adjustHeaders = func(h http.Header) {}
	conn, err := c.DialContext(ctx)
	if !assert.NoError(t, err) {
		return
	}
	conn.Close()

	adjustHeaders = func(h http.Header) { h.Del("Connection") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Connection` header is missing or invalid", err.Error())

	adjustHeaders = func(h http.Header) { h.Set("Connection", "downgrade") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Connection` header is missing or invalid", err.Error())

	adjustHeaders = func(h http.Header) { h.Del("Upgrade") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Upgrade` header is missing or invalid", err.Error())

	adjustHeaders = func(h http.Header) { h.Set("Upgrade", "wubsocket") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Upgrade` header is missing or invalid", err.Error())

	adjustHeaders = func(h http.Header) { h.Del("Sec-Websocket-Accept") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Sec-Websocket-Accept` header is missing or invalid", err.Error())

	adjustHeaders = func(h http.Header) { h.Set("Sec-Websocket-Accept", "1234") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Sec-Websocket-Accept` header is missing or invalid", err.Error())

	adjustHeaders = func(h http.Header) { h.Del("Sec-Websocket-Protocol") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Sec-Websocket-Protocol` header is missing or invalid ()", err.Error())

	adjustHeaders = func(h http.Header) { h.Set("Sec-Websocket-Protocol", "gopher") }
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: `Sec-Websocket-Protocol` header is missing or invalid (gopher)", err.Error())

	statusCode = 200
	adjustHeaders = func(h http.Header) {}
	_, err = c.DialContext(ctx)
	assert.Equal(t, "websocket handshake: unexpected status 200", err.Error())
}

func TestBadRequest(t *testing.T) {
	l, err := startEchoServer([]string{ProtocolRaw})
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	addr := fmt.Sprintf("https://%s", l.Addr().String())

	wskey, err := genKey()
	if !assert.NoError(t, err) {
		return
	}

	makeUpgrade := func() *http.Request {
		r, _ := http.NewRequest("GET", addr, nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Sec-WebSocket-Key", wskey)
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-Websocket-Protocol", "tinywss-raw")
		return r
	}

	// valid request
	req := makeUpgrade()
	resp, err := client.Do(req)
	if !assert.NoError(t, err) && assert.Equal(t, resp.StatusCode, 101) {
		return
	}

	bads := []*http.Request{}

	req = makeUpgrade()
	req.Method = "POST"
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Del("Connection")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Set("Connection", "downgrade")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Del("Upgrade")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Set("Upgrade", "wubsocket")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Del("Sec-Websocket-Key")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Set("Sec-Websocket-Key", "wub")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Del("Sec-Websocket-Protocol")
	bads = append(bads, req)

	req = makeUpgrade()
	req.Header.Set("Sec-Websocket-Protocol", "wub")
	bads = append(bads, req)

	for _, r := range bads {
		resp, err = client.Do(r)
		if !assert.NoError(t, err) && assert.Equal(t, resp.StatusCode, 400) {
			continue
		}
	}
}

func TestDialHelperLimit(t *testing.T) {
	dh := newDialHelper(2)

	stall := func(ctx context.Context) (net.Conn, error) {
		time.Sleep(1 * time.Second)
		return nil, errors.New("unexpected case")
	}

	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, 1*time.Millisecond)
	_, err := dh.Do(ctx, stall)
	assert.Equal(t, "context deadline exceeded", err.Error())

	ctx = context.Background()
	ctx, _ = context.WithTimeout(ctx, 1*time.Millisecond)
	_, err = dh.Do(ctx, stall)
	assert.Equal(t, "context deadline exceeded", err.Error())

	// refuses to dial until other calls to stall return (max of 2 pending)
	ctx = context.Background()
	ctx, _ = context.WithTimeout(ctx, 1*time.Millisecond)
	_, err = dh.Do(ctx, stall)
	assert.Equal(t, "maximum pending dials reached: context deadline exceeded", err.Error())

	// wait for the pending dials to return
	time.Sleep(1 * time.Second)

	// can dial again
	ctx = context.Background()
	ctx, _ = context.WithTimeout(ctx, 1*time.Millisecond)
	_, err = dh.Do(ctx, stall)
	assert.Equal(t, "context deadline exceeded", err.Error())
}

func TestDeadlineErrorShapes(t *testing.T) {
	l, err := startEchoServerOptions([]string{ProtocolMux}, false)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	c := testClientFor(l, true)

	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, 1*time.Second)
	conn, err := c.DialContext(ctx)
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	buf := make([]byte, 512)
	buf2 := make([]byte, 512)

	// read that will time out
	err = conn.SetReadDeadline(time.Now().Add(-1 * time.Second))
	if !assert.NoError(t, err) {
		return
	}
	_, err = conn.Read(buf2)
	if !assert.True(t, netx.IsTimeout(err), "error was not a timeout: %v", err) {
		return
	}
	err = conn.SetReadDeadline(time.Time{})
	if !assert.NoError(t, err) {
		return
	}

	_, err = rand.Read(buf)
	if !assert.NoError(t, err) {
		return
	}

	// write that should time out
	err = conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))
	if !assert.NoError(t, err) {
		return
	}
	_, err = conn.Write(buf)
	if !assert.True(t, netx.IsTimeout(err), "error was not a timeout: %v", err) {
		return
	}
	err = conn.SetWriteDeadline(time.Time{})
	if !assert.NoError(t, err) {
		return
	}
	// Note: this only works in the mux case, a tls.Conn can only
	// have one write timeout fire, then it becomes corrupt forever:
	// https://golang.org/pkg/crypto/tls/#Conn.SetWriteDeadline
	_, err = conn.Write(buf)
	if !assert.NoError(t, err) {
		return
	}

	_, err = io.ReadFull(conn, buf2)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Equal(t, buf, buf2) {
		return
	}
}

func generateTLSConfig() (*tls.Config, error) {
	tlsCert, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}

func generateKeyPair() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, err
}

func startEchoServer(protocols []string) (net.Listener, error) {
	return startEchoServerOptions(protocols, false)
}

func startEchoServerOptions(protocols []string, requireHeader bool) (net.Listener, error) {
	tlsConf, err := generateTLSConfig()
	if err != nil {
		return nil, err
	}
	l, err := ListenAddr(&ListenOpts{
		Addr:      ":0",
		TLSConf:   tlsConf,
		Protocols: protocols,
	})
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if requireHeader {
					wc, ok := c.(*WsConn)
					if !ok {
						log.Debugf("rejecting echo client (not WsConn?)")
						return
					}
					hdr := wc.UpgradeHeaders()
					if hdr.Get(authHeader) != authValue {
						log.Debugf("rejecting echo client (bad auth header)")
						return
					}
				}

				io.Copy(c, c)
			}()
		}
	}()

	return l, nil
}

func testClientFor(l net.Listener, multiplexed bool) Client {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}
	return NewClient(&ClientOpts{
		URL:         fmt.Sprintf("wss://%s", l.Addr().String()),
		RoundTrip:   NewRoundTripper(TLSDialFN(tlsConf)),
		Multiplexed: multiplexed,
	})
}
