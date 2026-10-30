package anytls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	sessionctx "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type httpTestPolicy struct{}

func (httpTestPolicy) Type() interface{} { return policy.ManagerType() }
func (httpTestPolicy) Start() error      { return nil }
func (httpTestPolicy) Close() error      { return nil }
func (httpTestPolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Timeouts: policy.Timeout{Handshake: 500 * time.Millisecond, ConnectionIdle: time.Second * 5}}
}
func (httpTestPolicy) ForSystem() policy.System { return policy.System{} }

type httpTestDispatcher struct{ calls atomic.Int64 }

func (*httpTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*httpTestDispatcher) Start() error      { return nil }
func (*httpTestDispatcher) Close() error      { return nil }
func (d *httpTestDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	d.calls.Add(1)
	r, w := pipe.New()
	return &transport.Link{Reader: r, Writer: w}, nil
}
func (*httpTestDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	panic("unexpected DispatchLink")
}

func startHTTPTestServer(t *testing.T, enabled bool) (*Server, *httpTestDispatcher, func() *tls.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"test.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{policyManager: httpTestPolicy{}, rejectHTTP: enabled, authSlots: make(chan struct{}, 128)}
	user := &protocol.MemoryUser{Email: "test-user", Account: &MemoryAccount{Password: "test-password"}}
	sum := sha256.Sum256([]byte("test-password"))
	s.store.Store(&userStoreSnapshot{users: map[[32]byte]*protocol.MemoryUser{sum: user}, emailIndex: map[string][32]byte{user.Email: sum}})
	dispatcher := &httpTestDispatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
				defer conn.Close()
				inbound := &sessionctx.Inbound{}
				_ = s.Process(sessionctx.ContextWithInbound(ctx, inbound), xnet.Network_TCP, conn, dispatcher)
			}()
		}
	}()
	t.Cleanup(func() { cancel(); listener.Close(); <-accepted; workers.Wait() })
	return s, dispatcher, func() *tls.Conn {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{ServerName: "test.invalid", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second * 3))
		if conn.ConnectionState().NegotiatedProtocol != "http/1.1" || !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, der) {
			t.Fatal("ALPN or certificate changed")
		}
		return conn
	}
}

func TestAnyTLSHTTPRejection(t *testing.T) {
	s, dispatcher, connect := startHTTPTestServer(t, true)
	for _, tc := range []struct {
		name, request, method string
		fragmented            bool
	}{
		{"get", "GET /private-probe?token=secret HTTP/1.1\r\nHost: test.invalid\r\n\r\n", "GET", false},
		{"head", "HEAD / HTTP/1.1\r\nHost: test.invalid\r\n\r\n", "HEAD", false},
		{"post", "POST / HTTP/1.1\r\nHost: test.invalid\r\nContent-Length: 200\r\n\r\n", "POST", false},
		{"buffered_headers", "GET / HTTP/1.1\r\nHost: test.invalid\r\nX-Pad: " + strings.Repeat("x", 4096) + "\r\n\r\n", "GET", false},
		{"short_http10", "GET / HTTP/1.0\r\n\r\n", "GET", false},
		{"fragmented_short_http10", "HEAD / HTTP/1.0\r\n\r\n", "HEAD", true},
		{"fragmented_headers", "GET / HTTP/1.1\r\nHost: test.invalid\r\n\r\n", "GET", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := connect()
			defer conn.Close()
			if tc.fragmented {
				for offset := 0; offset < len(tc.request); offset += 5 {
					end := offset + 5
					if end > len(tc.request) {
						end = len(tc.request)
					}
					if _, err := io.WriteString(conn, tc.request[offset:end]); err != nil {
						t.Fatal(err)
					}
					time.Sleep(time.Millisecond)
				}
			} else if _, err := io.WriteString(conn, tc.request); err != nil {
				t.Fatal(err)
			}
			capture := &httpResponseRecorder{Reader: conn}
			reader := bufio.NewReader(capture)
			response, err := http.ReadResponse(reader, &http.Request{Method: tc.method})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.Proto != "HTTP/1.1" || response.Status != "404 Not Found" || response.Header.Get("Server") != "nginx" || response.Header.Get("Content-Type") != "text/html" || response.ContentLength != int64(len(notFoundHTTPBody)) || !response.Close {
				t.Fatalf("unexpected response: %s %v", response.Status, response.Header)
			}
			if _, err := http.ParseTime(response.Header.Get("Date")); err != nil {
				t.Fatal(err)
			}
			want := notFoundHTTPBody
			if tc.method == "HEAD" {
				want = ""
			}
			if string(body) != want {
				t.Fatalf("incorrect body: %q", body)
			}
			if extra, _ := io.ReadAll(reader); len(extra) != 0 {
				t.Fatalf("extra bytes after the response: %q", extra)
			}
			head, rawBody, _ := bytes.Cut(capture.data.Bytes(), []byte("\r\n\r\n"))
			lines := strings.Split(string(head), "\r\n")
			if len(lines) != 6 || lines[0] != "HTTP/1.1 404 Not Found" || lines[1] != "Server: nginx" || !strings.HasPrefix(lines[2], "Date: ") || lines[3] != "Content-Type: text/html" || !strings.HasPrefix(lines[4], "Content-Length: ") || lines[5] != "Connection: close" || string(rawBody) != want {
				t.Fatal("raw nginx header order or HEAD body semantics differ")
			}
		})
	}
	if dispatcher.calls.Load() != 0 {
		t.Fatal("HTTP request reached authenticated routing")
	}
	deadline := time.Now().Add(time.Second)
	for len(s.authSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.authSlots) != 0 {
		t.Fatal("HTTP authentication slots leaked")
	}
}

type httpResponseRecorder struct {
	io.Reader
	data bytes.Buffer
}

func (r *httpResponseRecorder) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.data.Write(p[:n])
	return n, err
}

func TestAnyTLSHTTPTimeoutAndHeaderBudget(t *testing.T) {
	s, dispatcher, connect := startHTTPTestServer(t, true)
	for _, request := range []string{"GET / HTTP/1.1\r\nHost: unfinished", "GET / HTTP/1.1\r\nHost: test.invalid\r\nX-Pad: " + strings.Repeat("x", 40*1024) + "\r\n\r\n"} {
		conn := connect()
		io.WriteString(conn, request)
		data, _ := io.ReadAll(conn)
		conn.Close()
		if len(data) != 0 {
			t.Fatal("incomplete or oversized request received a response")
		}
	}
	if dispatcher.calls.Load() != 0 {
		t.Fatal("invalid HTTP reached routing")
	}
	deadline := time.Now().Add(time.Second)
	for len(s.authSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.authSlots) != 0 {
		t.Fatal("auth slots not released")
	}
}

func testWriteFrame(t *testing.T, conn io.Writer, cmd byte, sid uint32, data []byte) {
	t.Helper()
	wire := make([]byte, 7+len(data))
	wire[0] = cmd
	binary.BigEndian.PutUint32(wire[1:5], sid)
	binary.BigEndian.PutUint16(wire[5:7], uint16(len(data)))
	copy(wire[7:], data)
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
}

func testReadFrame(t *testing.T, conn io.Reader) (byte, []byte) {
	t.Helper()
	var head [7]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(head[5:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatal(err)
	}
	return head[0], body
}

func TestAnyTLSAuthenticatedStreamUnaffected(t *testing.T) {
	_, dispatcher, connect := startHTTPTestServer(t, true)
	conn := connect()
	defer conn.Close()
	sum := sha256.Sum256([]byte("test-password"))
	auth := append(sum[:], 0, 0)
	if _, err := conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	testWriteFrame(t, conn, cmdSettings, 0, []byte("v=2"))
	cmd, _ := testReadFrame(t, conn)
	if cmd != cmdServerSettings {
		t.Fatalf("not an AnyTLS server settings frame: %d", cmd)
	}
	testWriteFrame(t, conn, cmdSYN, 1, nil)
	payload := []byte("authenticated-payload")
	testWriteFrame(t, conn, cmdPSH, 1, append([]byte{1, 127, 0, 0, 1, 0, 80}, payload...))
	for i := 0; i < 8; i++ {
		cmd, body := testReadFrame(t, conn)
		if cmd == cmdPSH {
			if !bytes.Equal(body, payload) {
				t.Fatalf("incorrect proxy payload: %q", body)
			}
			if dispatcher.calls.Load() != 1 {
				t.Fatal("unexpected route count")
			}
			return
		}
	}
	t.Fatal("no proxied response")
}

func TestAnyTLSBinaryAndDisabledRejection(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		_, dispatcher, connect := startHTTPTestServer(t, enabled)
		conn := connect()
		wire := strings.Repeat("\x00", 34)
		if !enabled {
			wire = "GET / HTTP/1.1\r\nHost: test.invalid\r\n\r\n"
		}
		io.WriteString(conn, wire)
		body, _ := io.ReadAll(conn)
		conn.Close()
		if len(body) != 0 || dispatcher.calls.Load() != 0 {
			t.Fatal("unexpected binary/disabled HTTP banner or route")
		}
	}
}

func TestAnyTLSShortHTTPPrefixPreservesKnownHash(t *testing.T) {
	s, _, connect := startHTTPTestServer(t, true)
	short := []byte("GET / HTTP/1.0\r\n\r\n")
	var sum [32]byte
	copy(sum[:], short)
	user := &protocol.MemoryUser{Email: "known-prefix", Account: &MemoryAccount{Password: "fixture-only"}}
	s.store.Store(&userStoreSnapshot{users: map[[32]byte]*protocol.MemoryUser{sum: user}})
	conn := connect()
	defer conn.Close()
	conn.Write(short)
	time.Sleep(time.Millisecond * 10)
	conn.Write(append(sum[len(short):], 0, 0))
	testWriteFrame(t, conn, cmdSettings, 0, []byte("v=2"))
	cmd, _ := testReadFrame(t, conn)
	if cmd != cmdServerSettings {
		t.Fatal("valid auth hash was mistaken for HTTP")
	}
}
