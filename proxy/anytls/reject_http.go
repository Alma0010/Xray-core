package anytls

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const notFoundHTTPBody = "<html>\r\n<head><title>404 Not Found</title></head>\r\n" +
	"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n" +
	"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

const invalidHTTPBody = "<html>\r\n<head><title>400 Bad Request</title></head>\r\n" +
	"<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n" +
	"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

func looksLikeHTTP(prefix []byte) bool {
	if len(prefix) == 0 {
		return false
	}
	return (prefix[0] >= 'A' && prefix[0] <= 'Z') || (prefix[0] >= 'a' && prefix[0] <= 'z')
}

func completeShortHTTP(prefix []byte) bool {
	if !looksLikeHTTP(prefix) || (!bytes.Contains(prefix, []byte("\r\n\r\n")) && !bytes.Contains(prefix, []byte("\n\n"))) {
		return false
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(prefix)))
	return err == nil && request.ProtoMajor == 1 && request.ProtoMinor <= 1
}

// This scan runs only for a short, complete HTTP-looking prefix. Normal AnyTLS
// authentication keeps the existing constant-time hash-map lookup.
func (s *Server) matchesUserPrefix(prefix []byte) bool {
	if len(prefix) > 32 {
		var sum [32]byte
		copy(sum[:], prefix)
		return s.loadStore().users[sum] != nil
	}
	for sum := range s.loadStore().users {
		if bytes.Equal(sum[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// The connection is already decrypted by the inbound TLS transport. Reinsert
// the inspected authentication bytes and retain buf's read-ahead data.
func rejectHTTP(conn net.Conn, buffered io.Reader, prefix []byte) error {
	reader := bufio.NewReader(io.LimitReader(io.MultiReader(bytes.NewReader(prefix), buffered), 32*1024))
	request, err := http.ReadRequest(reader)
	if err != nil {
		// Incomplete or oversized input has no response; the existing auth
		// deadline bounds this read. Never put an HTTP banner in binary input.
		return err
	}
	status, body := "404 Not Found", notFoundHTTPBody
	if request.ProtoMajor != 1 || request.ProtoMinor > 1 || (request.ProtoMinor == 1 && request.Host == "") {
		status, body = "400 Bad Request", invalidHTTPBody
	}
	response := fmt.Sprintf("HTTP/1.1 %s\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, time.Now().UTC().Format(http.TimeFormat), len(body))
	if request.Method != http.MethodHead {
		response += body
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = io.WriteString(conn, response)
	return err
}
