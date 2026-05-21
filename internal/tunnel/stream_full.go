package tunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	ycrypto "github.com/y5neko/ysock/internal/crypto"
	"github.com/y5neko/ysock/internal/logger"
	"github.com/y5neko/ysock/internal/mux"
	"github.com/y5neko/ysock/internal/protocol"
)

const fullDuplexContentLength = 1073741824 // 1GB

type FullDuplexFactory struct {
	tunnel *Tunnel
}

func NewFullDuplexFactory(t *Tunnel) *FullDuplexFactory {
	return &FullDuplexFactory{tunnel: t}
}

func (f *FullDuplexFactory) Close() error { return nil }

func (f *FullDuplexFactory) OpenSession(target string) (io.ReadWriteCloser, error) {
	t := f.tunnel
	host, port, err := parseHostPort(target)
	if err != nil {
		return nil, err
	}

	session := t.manager.Create(target)
	sid := session.SID()

	logger.Debugf(tag, "full open sid=%d target=%s:%d", sid, host, port)

	u, err := url.Parse(t.url)
	if err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("parse url: %w", err)
	}

	conn, err := dialRaw(u)
	if err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("dial raw: %w", err)
	}

	synData := mux.EncodeTarget(host, port)
	synFrame := &protocol.Frame{Packets: []*protocol.Packet{
		{Flag: protocol.FlagSYN, SID: sid, SEQ: t.nextSeq(), Data: synData},
	}}
	raw := synFrame.Marshal()
	encrypted := t.cipher.Encrypt(raw)
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	jsonBody, _ := json.Marshal(map[string]string{
		"a": "f",
		"d": encoded,
	})

	httpReq := buildLargeContentLengthPost(u, "application/octet-stream", jsonBody)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write(httpReq); err != nil {
		conn.Close()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("write http request: %w", err)
	}

	reader := bufio.NewReader(conn)
	if err := skipHTTPResponse(reader); err != nil {
		conn.Close()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("read http response: %w", err)
	}

	cr := newChunkedReader(reader)
	ackType, _, err := readStreamFrame(cr, t.cipher)
	if err != nil {
		conn.Close()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("read ack: %w", err)
	}
	if ackType != 0x00 {
		conn.Close()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("unexpected ack type: 0x%02x", ackType)
	}

	conn.SetDeadline(time.Time{})
	logger.Debugf(tag, "full session established sid=%d", sid)

	fs := &fullDuplexSession{
		sid:     sid,
		tunnel:  t,
		session: session,
		conn:    conn,
		reader:  cr,
	}

	t.wg.Add(2)
	go fs.readLoop()
	go fs.writeLoop()

	return mux.NewSessionConn(session, t.manager), nil
}

type fullDuplexSession struct {
	sid     uint32
	tunnel  *Tunnel
	session *mux.Session
	conn    net.Conn
	reader  io.Reader
	once    sync.Once
}

func (fs *fullDuplexSession) readLoop() {
	defer fs.tunnel.wg.Done()
	defer fs.cleanup()

	for {
		select {
		case <-fs.tunnel.closeCh:
			logger.Debugf(tag, "full read sid=%d: tunnel closing", fs.sid)
			return
		default:
		}

		fs.conn.SetReadDeadline(time.Now().Add(idleTimeout))

		typ, data, err := readStreamFrame(fs.reader, fs.tunnel.cipher)
		if err != nil {
			if isTimeout(err) {
				select {
				case <-fs.session.CloseCh():
					return
				case <-fs.tunnel.closeCh:
					return
				default:
					continue
				}
			}
			logger.Debugf(tag, "full read sid=%d: %v", fs.sid, err)
			return
		}

		fs.conn.SetReadDeadline(time.Time{})

		switch typ {
		case 0x01: // DATA
			fs.session.PushInbound(data)
			logger.Debugf(tag, "full recv sid=%d len=%d", fs.sid, len(data))
		case 0x02: // FIN
			logger.Debugf(tag, "full recv FIN sid=%d", fs.sid)
			return
		}
	}
}

func (fs *fullDuplexSession) writeLoop() {
	defer fs.tunnel.wg.Done()

	for {
		select {
		case <-fs.session.OutboundReady():
		case <-fs.session.CloseCh():
			return
		case <-fs.tunnel.closeCh:
			return
		}

		data := fs.session.PopOutbound(maxPayloadSize)
		if data == nil {
			continue
		}

		if err := writeStreamFrame(fs.conn, 0x01, data, fs.tunnel.cipher); err != nil {
			logger.Errorf(tag, "full write sid=%d: %v", fs.sid, err)
			return
		}
		logger.Debugf(tag, "full send sid=%d len=%d", fs.sid, len(data))
	}
}

func (fs *fullDuplexSession) cleanup() {
	fs.once.Do(func() {
		logger.Debugf(tag, "full cleanup sid=%d", fs.sid)
		_ = writeStreamFrame(fs.conn, 0x02, nil, fs.tunnel.cipher)
		fs.conn.Close()
		fs.session.Close()
		fs.tunnel.manager.Remove(fs.sid)
	})
}

// ---- Chunked Transfer Encoding Reader ----

type chunkedReader struct {
	reader *bufio.Reader
	n      int64
	err    error
}

func newChunkedReader(r *bufio.Reader) *chunkedReader {
	return &chunkedReader{reader: r, n: 0}
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.err != nil {
		return 0, cr.err
	}
	if cr.n == 0 {
		line, err := cr.reader.ReadString('\n')
		if err != nil {
			cr.err = err
			return 0, err
		}
		line = strings.TrimSpace(line)
		var size int64
		for _, ch := range line {
			if ch >= '0' && ch <= '9' {
				size = size*16 + int64(ch-'0')
			} else if ch >= 'a' && ch <= 'f' {
				size = size*16 + int64(ch-'a'+10)
			} else if ch >= 'A' && ch <= 'F' {
				size = size*16 + int64(ch-'A'+10)
			} else {
				break
			}
		}
		if size == 0 {
			cr.err = io.EOF
			cr.reader.ReadString('\n')
			return 0, io.EOF
		}
		cr.n = size
	}

	toRead := cr.n
	if int64(len(p)) < toRead {
		toRead = int64(len(p))
	}
	n, err := io.ReadFull(cr.reader, p[:toRead])
	cr.n -= int64(n)
	if cr.n == 0 {
		if _, trailErr := cr.reader.ReadString('\n'); trailErr != nil {
			cr.err = trailErr
		}
	}
	return n, err
}

// ---- HTTP 工具 ----

func dialRaw(u *url.URL) (net.Conn, error) {
	targetAddr := u.Host
	if !strings.Contains(targetAddr, ":") {
		if u.Scheme == "https" {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "https" {
		host := u.Host
		if h, _, splitErr := net.SplitHostPort(u.Host); splitErr == nil {
			host = h
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tlsConn
	}

	return conn, nil
}

func buildLargeContentLengthPost(u *url.URL, contentType string, body []byte) []byte {
	reqPath := u.Path
	if u.RawQuery != "" {
		reqPath += "?" + u.RawQuery
	}
	header := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n", reqPath, u.Host, contentType, fullDuplexContentLength)
	return append([]byte(header), body...)
}

func skipHTTPResponse(reader *bufio.Reader) error {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	if !strings.Contains(statusLine, "200") {
		return fmt.Errorf("unexpected status: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
}

func DetectFullDuplex(urlStr string, cipher *ycrypto.Cipher) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	conn, err := dialRaw(u)
	if err != nil {
		logger.Debugf(tag, "detect full duplex: dial raw failed: %v", err)
		return false
	}
	defer conn.Close()

	testData := cipher.Encrypt([]byte("YSOCK_PING"))
	encoded := base64.StdEncoding.EncodeToString(testData)
	jsonBody, _ := json.Marshal(map[string]string{
		"a": "h",
		"d": encoded,
	})

	httpReq := buildLargeContentLengthPost(u, "application/octet-stream", jsonBody)
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(httpReq); err != nil {
		logger.Debugf(tag, "detect full duplex: write failed: %v", err)
		return false
	}

	reader := bufio.NewReader(conn)
	if err := skipHTTPResponse(reader); err != nil {
		logger.Debugf(tag, "detect full duplex: skip response failed: %v", err)
		return false
	}

	var buf [4096]byte
	n, err := reader.Read(buf[:])
	if err != nil && err != io.EOF {
		logger.Debugf(tag, "detect full duplex: read response failed: %v", err)
		return false
	}
	if n > 0 {
		data := string(buf[:n])
		logger.Debugf(tag, "detect full duplex: response=%q", data)
		if strings.Contains(data, `"d"`) {
			return true
		}
	}

	return false
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
