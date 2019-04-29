package tinywss

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/getlantern/tlsdialer"
)

// creates a new default RoundTripHijacker
func NewRoundTripper(tlsConfig *tls.Config) *roundTripHijacker {
	return &roundTripHijacker{
		tlsConfig: tlsConfig,
	}
}

var _ RoundTripHijacker = &roundTripHijacker{}

// this is the default RoundTripHijacker used for Clients
type roundTripHijacker struct {
	tlsConfig *tls.Config
}

func (rt *roundTripHijacker) RoundTripHijack(req *http.Request) (*http.Response, net.Conn, error) {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	conn, err := tlsdialer.Dial("tcp", addr, true, rt.tlsConfig)
	if err != nil {
		return nil, nil, err
	}

	if err = req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}

	buf := bufio.NewReaderSize(conn, 4096)
	res, err := http.ReadResponse(buf, req)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return res, conn, nil
}
