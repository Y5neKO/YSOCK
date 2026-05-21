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
	"github.com/y5neko/ysock/internal/mux"
	"github.com/y5neko/ysock/internal/protocol"
)

// 用超大 Content-Length 使 Tomcat 的 request.getInputStream() 持续可用
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

	u, err := url.Parse(t.url)
	if err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("parse url: %w", err)
	}

	// 建立原始 TCP 连接
	conn, err := dialRaw(u)
	if err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("dial raw: %w", err)
	}

	// 构造 SYN body（action='f'）
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

	// 发送 HTTP POST 请求（超大 Content-Length，初始 body 是 JSON）
	httpReq := buildLargeContentLengthPost(u, "application/octet-stream", jsonBody)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write(httpReq); err != nil {
		conn.Close()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("write http request: %w", err)
	}

	// 读取 HTTP 响应头
	reader := bufio.NewReader(conn)
	if err := skipHTTPResponse(reader); err != nil {
		conn.Close()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("read http response: %w", err)
	}

	// 读取 ACK 帧（响应使用 chunked 编码，需要解码）
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

	// 连接成功，清除 deadline
	conn.SetDeadline(time.Time{})

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
			return
		default:
		}

		// 设置读超时，防止死连接无限阻塞
		fs.conn.SetReadDeadline(time.Now().Add(idleTimeout))

		typ, data, err := readStreamFrame(fs.reader, fs.tunnel.cipher)
		if err != nil {
			// 超时且会话未关闭 → 可能是暂时空闲，继续等待
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
			return
		}

		// 成功读取，清除 deadline
		fs.conn.SetReadDeadline(time.Time{})

		switch typ {
		case 0x01: // DATA
			fs.session.PushInbound(data)
		case 0x02: // FIN
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
			logf("full write error sid=%d: %v", fs.sid, err)
			return
		}
	}
}

func (fs *fullDuplexSession) cleanup() {
	fs.once.Do(func() {
		_ = writeStreamFrame(fs.conn, 0x02, nil, fs.tunnel.cipher)
		fs.conn.Close()
		fs.session.Close()
		fs.tunnel.manager.Remove(fs.sid)
	})
}

// ---- Chunked Transfer Encoding Reader ----

// chunkedReader 解码 HTTP chunked transfer encoding
type chunkedReader struct {
	reader *bufio.Reader
	n      int64 // remaining bytes in current chunk
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
		// 读取下一个 chunk size
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
			// terminal chunk
			cr.err = io.EOF
			// 读取 trailing CRLF
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
		// 读取 chunk trailing CRLF，错误传播到下次调用
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

// buildLargeContentLengthPost 构造超大 Content-Length 的 HTTP POST
// body 是初始数据，后续数据通过同一连接持续发送
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

// DetectFullDuplex 检测服务端是否支持全双工
func DetectFullDuplex(urlStr string, cipher *ycrypto.Cipher) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	conn, err := dialRaw(u)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 发送握手请求（Content-Type: application/octet-stream + 超大 Content-Length）
	testData := cipher.Encrypt([]byte("YSOCK_PING"))
	encoded := base64.StdEncoding.EncodeToString(testData)
	jsonBody, _ := json.Marshal(map[string]string{
		"a": "h",
		"d": encoded,
	})

	httpReq := buildLargeContentLengthPost(u, "application/octet-stream", jsonBody)
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(httpReq); err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	if err := skipHTTPResponse(reader); err != nil {
		return false
	}

	// 尝试读取响应数据
	var buf [4096]byte
	n, err := reader.Read(buf[:])
	if err != nil && err != io.EOF {
		return false
	}
	if n > 0 {
		data := string(buf[:n])
		// JSON 响应包含 "d" 字段说明 JSP 正常处理了 octet-stream 请求
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
