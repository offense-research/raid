// Raid client: minimal HTTP/1.1 over a Unix socket for the CLI, TUI, and
// CLI, TUI, and execution-proxy integration.
package raidclient

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"
)

// Client talks to the raidd unix socket.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// NewClient returns a client for the default socket.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = "/run/offense/raid/raid.sock"
	}
	return &Client{SocketPath: socketPath, Timeout: 10 * time.Second}
}

// Response is a parsed HTTP response.
type Response struct {
	Status int
	Body   []byte
}

func (r *Response) BodyString() string { return string(r.Body) }

// errorResponse wraps a transport failure.
type ClientError struct {
	msg string
}

func (e *ClientError) Error() string { return e.msg }

// Post sends a JSON POST request.
func (c *Client) Post(path, body string, approver string, headers map[string]string) (*Response, error) {
	return c.request("POST", path, body, approver, headers)
}

// Get sends a GET request.
func (c *Client) Get(path string, approver string) (*Response, error) {
	return c.request("GET", path, "", approver, nil)
}

// Delete sends a DELETE request.
func (c *Client) Delete(path, approver string) (*Response, error) {
	return c.request("DELETE", path, "", approver, nil)
}

func (c *Client) request(method, path, body, approver string, headers map[string]string) (*Response, error) {
	raddr := &net.UnixAddr{Name: c.SocketPath, Net: "unix"}
	conn, err := net.DialUnix("unix", nil, raddr)
	if err != nil {
		return nil, &ClientError{msg: "cannot connect to raidd: " + err.Error()}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.Timeout))

	var req strings.Builder
	req.WriteString(method)
	req.WriteByte(' ')
	req.WriteString(path)
	req.WriteString(" HTTP/1.1\r\nHost: raid\r\n")
	if len(body) > 0 {
		req.WriteString("Content-Type: application/json\r\n")
	}
	req.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	if approver != "" {
		req.WriteString("X-Raid-Approver: " + approver + "\r\n")
	}
	if headers != nil {
		for k, v := range headers {
			req.WriteString(k + ": " + v + "\r\n")
		}
	}
	req.WriteString("Connection: close\r\n\r\n")
	req.WriteString(body)
	reqBytes := []byte(req.String())
	// write everything; Write may return short counts
	for off := 0; off < len(reqBytes); {
		n, err := conn.Write(reqBytes[off:])
		if err != nil {
			return nil, &ClientError{msg: "write failed: " + err.Error()}
		}
		if n <= 0 {
			return nil, &ClientError{msg: "write made no progress"}
		}
		off += n
	}

	// read until the server closes (Connection: close)
	var buf [65536]byte
	var raw []byte
	for {
		n, err := conn.Read(buf[:])
		if err == io.EOF || n == 0 {
			break
		}
		if err != nil {
			return nil, &ClientError{msg: "read failed: " + err.Error()}
		}
		raw = slices.Concat(raw, buf[:n])
		if len(raw) > 4*1024*1024 {
			return nil, &ClientError{msg: "response too large"}
		}
	}
	if len(raw) == 0 {
		return nil, &ClientError{msg: "empty response from raidd"}
	}
	status, bodyBytes, perr := parseStatus(raw)
	if perr != nil {
		return nil, perr
	}
	return &Response{Status: status, Body: bodyBytes}, nil
}

func parseStatus(raw []byte) (int, []byte, error) {
	i := bytesIndex(raw, []byte("\r\n"))
	if i < 0 {
		return 0, nil, &ClientError{msg: "malformed response status"}
	}
	line := string(raw[:i])
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return 0, nil, &ClientError{msg: "malformed status line: " + line}
	}
	code, ok := parseNum(parts[1])
	if !ok {
		return 0, nil, &ClientError{msg: "malformed status code"}
	}
	// find header/body split
	hdrEnd := bytesIndex(raw, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return int(code), raw[i+2:], nil
	}
	bodyStart := hdrEnd + 4
	cl := contentLengthOf(raw[:hdrEnd])
	if cl >= 0 {
		return int(code), raw[bodyStart : bodyStart+int(cl)], nil
	}
	return int(code), raw[bodyStart:], nil
}

func splitBody(raw []byte) ([]byte, []byte, bool) {
	hdrEnd := bytesIndex(raw, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return raw, nil, false
	}
	cl := contentLengthOf(raw[:hdrEnd])
	if cl < 0 {
		return nil, raw[hdrEnd+4:], true
	}
	return raw[:hdrEnd+4], raw[hdrEnd+4 : hdrEnd+4+int(cl)], true
}

func contentLengthOf(head []byte) int64 {
	lines := strings.Split(string(head), "\r\n")
	for _, ln := range lines {
		parts := strings.Split(ln, ":")
		if len(parts) >= 2 && strings.ToLower(parts[0]) == "content-length" {
			n, ok := parseNum(strings.Trim(parts[1], " "))
			if ok {
				return n
			}
		}
	}
	return -1
}

func parseNum(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n := int64(0)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

func bytesIndex(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if hay[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
