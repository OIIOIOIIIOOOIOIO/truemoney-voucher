package twapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"
)

// ---------------------------------------------------------------------------
// HTTP/2 frame constants
// ---------------------------------------------------------------------------

const (
	frameData         = 0x0
	frameHeaders      = 0x1
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePing         = 0x6
	frameGoaway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9

	flagAck        = 0x1
	flagEndHeaders = 0x4
	flagEndStream  = 0x1

	settingHeaderTableSize      = 0x1
	settingMaxConcurrentStreams = 0x3
	settingInitialWindowSize    = 0x4
	settingMaxHeaderListSize    = 0x6

	// Chrome 133 SETTINGS values.
	chromeHeaderTableSize      uint32 = 65536
	chromeMaxConcurrentStreams uint32 = 1000
	chromeInitialWindowSize    uint32 = 6291456
	chromeMaxHeaderListSize    uint32 = 262144

	http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// ---------------------------------------------------------------------------
// Low-level frame I/O
// ---------------------------------------------------------------------------

// writeFrameHeader writes a 9-byte HTTP/2 frame header.
func writeFrameHeader(w io.Writer, length int, ftype, flags byte, streamID uint32) error {
	var hdr [9]byte
	hdr[0] = byte(length >> 16)
	hdr[1] = byte(length >> 8)
	hdr[2] = byte(length)
	hdr[3] = ftype
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	_, err := w.Write(hdr[:])
	return err
}

// readFrameHeader reads a 9-byte HTTP/2 frame header from r.
type h2frameHeader struct {
	Length   int
	Type     byte
	Flags    byte
	StreamID uint32
}

func readFrameHeader(r io.Reader) (h2frameHeader, error) {
	var buf [9]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return h2frameHeader{}, err
	}
	return h2frameHeader{
		Length:   int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2]),
		Type:     buf[3],
		Flags:    buf[4],
		StreamID: binary.BigEndian.Uint32(buf[5:9]) & 0x7FFFFFFF,
	}, nil
}

// writeSettings writes a SETTINGS frame with the given id/value pairs.
func writeSettings(w io.Writer, settings ...[2]uint32) error {
	payloadLen := len(settings) * 6
	if err := writeFrameHeader(w, payloadLen, frameSettings, 0, 0); err != nil {
		return err
	}
	var pair [6]byte
	for _, s := range settings {
		binary.BigEndian.PutUint16(pair[0:2], uint16(s[0]))
		binary.BigEndian.PutUint32(pair[2:6], s[1])
		if _, err := w.Write(pair[:]); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// HTTP/2 connection
// ---------------------------------------------------------------------------

// h2conn is a single HTTP/2 connection that mimics Chrome 133 at the frame level.
type h2conn struct {
	conn net.Conn
	bw   *bufio.Writer
	br   *bufio.Reader

	serverInitialWindow uint32
	serverMaxConcurrent uint32

	nextStreamID uint32
	mu           sync.Mutex
}

// dialH2 opens a TCP+TLS connection, performs the HTTP/2 handshake.
func dialH2(ctx context.Context, hostport string, dialer *net.Dialer,
	tlsSpec *utls.ClientHelloSpec) (*h2conn, error) {

	// 1. TCP
	raw, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	// 2. TLS with Chrome fingerprint — use HelloCustom+ApplyPreset to keep h2 ALPN.
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         hostportToSNI(hostport),
		InsecureSkipVerify: false,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(tlsSpec); err != nil {
		raw.Close()
		return nil, fmt.Errorf("apply preset: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		uconn.SetDeadline(deadline)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	if uconn.ConnectionState().NegotiatedProtocol != "h2" {
		uconn.Close()
		return nil, fmt.Errorf("server did not negotiate h2, got %q",
			uconn.ConnectionState().NegotiatedProtocol)
	}

	bw := bufio.NewWriter(uconn)
	br := bufio.NewReader(uconn)

	// 3. HTTP/2 connection preface + Chrome SETTINGS
	if _, err := io.WriteString(bw, http2Preface); err != nil {
		uconn.Close()
		return nil, err
	}
	if err := writeSettings(bw,
		[2]uint32{settingHeaderTableSize, chromeHeaderTableSize},
		[2]uint32{settingMaxConcurrentStreams, chromeMaxConcurrentStreams},
		[2]uint32{settingInitialWindowSize, chromeInitialWindowSize},
		[2]uint32{settingMaxHeaderListSize, chromeMaxHeaderListSize},
	); err != nil {
		uconn.Close()
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		uconn.Close()
		return nil, err
	}

	c := &h2conn{
		conn:                uconn,
		bw:                  bw,
		br:                  br,
		nextStreamID:        1,
		serverInitialWindow: 65535,
	}

	// 4. Read server preface, ACK its SETTINGS.
	if err := c.readServerPreface(); err != nil {
		uconn.Close()
		return nil, err
	}

	return c, nil
}

func hostportToSNI(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func (c *h2conn) readServerPreface() error {
	for {
		hdr, err := readFrameHeader(c.br)
		if err != nil {
			return fmt.Errorf("read preface frame: %w", err)
		}
		switch hdr.Type {
		case frameSettings:
			if hdr.Flags&flagAck != 0 {
				continue
			}
			payload := make([]byte, hdr.Length)
			if _, err := io.ReadFull(c.br, payload); err != nil {
				return fmt.Errorf("read settings payload: %w", err)
			}
			for i := 0; i < len(payload); i += 6 {
				id := binary.BigEndian.Uint16(payload[i : i+2])
				val := binary.BigEndian.Uint32(payload[i+2 : i+6])
				switch id {
				case settingInitialWindowSize:
					c.serverInitialWindow = val
				case settingMaxConcurrentStreams:
					c.serverMaxConcurrent = val
				}
			}
			// ACK.
			if err := writeFrameHeader(c.bw, 0, frameSettings, flagAck, 0); err != nil {
				return err
			}
			if err := c.bw.Flush(); err != nil {
				return err
			}
			return nil
		case frameWindowUpdate:
			if _, err := io.CopyN(io.Discard, c.br, int64(hdr.Length)); err != nil {
				return err
			}
		default:
			if _, err := io.CopyN(io.Discard, c.br, int64(hdr.Length)); err != nil {
				return err
			}
		}
	}
}

// do sends one HTTP request and reads the response.
func (c *h2conn) do(req *http.Request, headerOrder []string) (*http.Response, error) {
	c.mu.Lock()
	streamID := c.nextStreamID
	c.nextStreamID += 2
	c.mu.Unlock()

	headerBlock, err := encodeHpackHeaders(req, headerOrder)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	// HEADERS frame
	flags := byte(flagEndHeaders)
	if req.Body == nil || req.ContentLength == 0 {
		flags |= flagEndStream
	}
	if err := writeFrameHeader(c.bw, len(headerBlock), frameHeaders, flags, streamID); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if _, err := c.bw.Write(headerBlock); err != nil {
		c.mu.Unlock()
		return nil, err
	}

	// DATA frame (if body present)
	if req.Body != nil && req.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			c.mu.Unlock()
			return nil, fmt.Errorf("read body: %w", err)
		}
		if err := writeFrameHeader(c.bw, len(bodyBytes), frameData, flagEndStream, streamID); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		if _, err := c.bw.Write(bodyBytes); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}

	if err := c.bw.Flush(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Unlock()

	return c.readResponse(streamID, req)
}

// encodeHpackHeaders returns the HPACK-encoded HEADERS payload in Chrome header order.
func encodeHpackHeaders(req *http.Request, headerOrder []string) ([]byte, error) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)

	// Pseudo-headers (required order: :method, :scheme, :authority, :path)
	for _, f := range [][2]string{
		{":method", req.Method},
		{":scheme", "https"},
		{":authority", req.URL.Host},
		{":path", req.URL.RequestURI()},
	} {
		if err := enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
			return nil, fmt.Errorf("hpack encode %s: %w", f[0], err)
		}
	}

	// Regular headers in Chrome order.
	skip := map[string]bool{
		"Content-Length": true,
		"Connection":     true,
		"Host":           true,
	}
	for _, key := range headerOrder {
		canonical := http.CanonicalHeaderKey(key)
		if skip[canonical] {
			continue
		}
		values := req.Header[canonical]
		if len(values) == 0 {
			if canonical == "Accept-Encoding" {
				values = []string{"gzip, deflate, br"}
			} else {
				continue
			}
		}
		skip[canonical] = true
		for _, v := range values {
			if err := enc.WriteField(hpack.HeaderField{Name: strings.ToLower(key), Value: v}); err != nil {
				return nil, fmt.Errorf("hpack encode %s: %w", key, err)
			}
		}
	}

	return buf.Bytes(), nil
}

// readResponse reads HEADERS + DATA frames for streamID and builds *http.Response.
func (c *h2conn) readResponse(streamID uint32, req *http.Request) (*http.Response, error) {
	var (
		headerBlock []byte
		bodyBuf     bytes.Buffer
		done        bool
	)

	for !done {
		hdr, err := readFrameHeader(c.br)
		if err != nil {
			return nil, fmt.Errorf("read response frame: %w", err)
		}

		payload := make([]byte, hdr.Length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return nil, fmt.Errorf("read frame payload: %w", err)
		}

		switch {
		case (hdr.Type == frameHeaders || hdr.Type == frameContinuation) && hdr.StreamID == streamID:
			headerBlock = append(headerBlock, payload...)
			if hdr.Flags&flagEndHeaders != 0 || hdr.Flags&flagEndStream != 0 {
				if hdr.Flags&flagEndStream != 0 {
					done = true
				}
			}

		case hdr.Type == frameData && hdr.StreamID == streamID:
			bodyBuf.Write(payload)
			if hdr.Flags&flagEndStream != 0 {
				done = true
			}

		case hdr.Type == frameRSTStream && hdr.StreamID == streamID:
			return nil, fmt.Errorf("server reset stream")

		case hdr.Type == frameSettings && hdr.Flags&flagAck == 0:
			c.mu.Lock()
			writeFrameHeader(c.bw, 0, frameSettings, flagAck, 0)
			c.bw.Flush()
			c.mu.Unlock()

		case hdr.Type == framePing && hdr.Flags&flagAck == 0:
			c.mu.Lock()
			writeFrameHeader(c.bw, 8, framePing, flagAck, 0)
			c.bw.Write(payload)
			c.bw.Flush()
			c.mu.Unlock()

		case hdr.Type == frameGoaway:
			return nil, fmt.Errorf("server sent GOAWAY")

		case hdr.Type == frameWindowUpdate:
			// Ignore.

		default:
			// RST_STREAM, PRIORITY, etc.
		}
	}

	return decodeHpackResponse(headerBlock, req, &bodyBuf)
}

func decodeHpackResponse(block []byte, req *http.Request, body io.Reader) (*http.Response, error) {
	if len(block) == 0 {
		return nil, fmt.Errorf("empty response: no HEADERS frame received")
	}
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     make(http.Header),
		Body:       io.NopCloser(body),
		Request:    req,
	}

	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		switch {
		case f.Name == ":status":
			resp.StatusCode = parseStatus(f.Value)
			resp.Status = f.Value + " " + http.StatusText(resp.StatusCode)
		case strings.HasPrefix(f.Name, ":"):
			// skip pseudo-headers
		default:
			resp.Header.Add(f.Name, f.Value)
		}
	})

	if _, err := dec.Write(block); err != nil {
		return nil, fmt.Errorf("hpack decode: %w", err)
	}

	return resp, nil
}

func parseStatus(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// Close closes the underlying connection.
func (c *h2conn) Close() error {
	return c.conn.Close()
}
