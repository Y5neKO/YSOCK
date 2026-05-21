package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/y5neko/ysock/internal/protocol"
)

const (
	bufSize = 32 * 1024
)

// Session 代表一个 SOCKS5 连接通过隧道的映射
type Session struct {
	sid    uint32
	target string

	// synPend: 待发送的 SYN 包（pollLoop 会与 DATA 合并发送）
	synPend *protocol.Packet

	// outbound: SOCKS5 客户端 -> 隧道 -> Payload -> 目标
	outbound  [][]byte
	outMu     sync.Mutex
	outNotify chan struct{}

	// inbound: 目标 -> Payload -> 隧道 -> SOCKS5 客户端
	inbound   chan []byte
	inboundBuf []byte
	inMu      sync.Mutex

	closed  bool
	closeMu sync.Mutex
	closeCh chan struct{}
}

func NewSession(sid uint32, target string) *Session {
	return &Session{
		sid:       sid,
		target:    target,
		outNotify: make(chan struct{}, 1),
		inbound:   make(chan []byte, 128),
		closeCh:   make(chan struct{}),
	}
}

func (s *Session) SID() uint32    { return s.sid }
func (s *Session) Target() string { return s.target }

func (s *Session) CloseCh() <-chan struct{} { return s.closeCh }

func (s *Session) IsClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

func (s *Session) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	s.closeMu.Unlock()
	close(s.closeCh)
}

func (s *Session) SetSynPend(pkt *protocol.Packet) {
	s.outMu.Lock()
	s.synPend = pkt
	s.outMu.Unlock()
}

func (s *Session) PopSynPend() *protocol.Packet {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	pkt := s.synPend
	s.synPend = nil
	return pkt
}

// PushOutbound 接收来自 SOCKS5 客户端的数据（待发送到目标）
// 必须拷贝数据，因为调用方（relay）会复用 buffer
func (s *Session) PushOutbound(data []byte) {
	if s.IsClosed() {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	s.outMu.Lock()
	s.outbound = append(s.outbound, cp)
	s.outMu.Unlock()
	select {
	case s.outNotify <- struct{}{}:
	default:
	}
}

// PopOutbound 取出待发送的数据（隧道收集后发往 Payload）
func (s *Session) PopOutbound(maxSize int) []byte {
	s.outMu.Lock()
	defer s.outMu.Unlock()

	if len(s.outbound) == 0 {
		return nil
	}

	// 合并所有 chunk，限制 maxSize
	total := 0
	end := 0
	for i, chunk := range s.outbound {
		if total+len(chunk) > maxSize {
			break
		}
		total += len(chunk)
		end = i + 1
	}

	buf := make([]byte, 0, total)
	for i := 0; i < end; i++ {
		buf = append(buf, s.outbound[i]...)
	}
	s.outbound = s.outbound[end:]
	return buf
}

// OutboundReady 返回一个 channel，在有数据可发送时触发
func (s *Session) OutboundReady() <-chan struct{} {
	return s.outNotify
}

// PushInbound 接收来自隧道的数据（来自目标，待发送到 SOCKS5 客户端）
// 阻塞式写入，不丢弃数据（TLS 连接丢任何字节都会导致后续全部损坏）
func (s *Session) PushInbound(data []byte) {
	if s.IsClosed() {
		return
	}
	select {
	case s.inbound <- data:
	case <-s.closeCh:
	}
}

// ReadInbound 读取数据（SOCKS5 客户端调用）
func (s *Session) ReadInbound(p []byte) (n int, err error) {
	s.inMu.Lock()
	if len(s.inboundBuf) > 0 {
		n = copy(p, s.inboundBuf)
		s.inboundBuf = s.inboundBuf[n:]
		s.inMu.Unlock()
		return n, nil
	}
	s.inMu.Unlock()

	select {
	case data := <-s.inbound:
		n = copy(p, data)
		if n < len(data) {
			s.inMu.Lock()
			s.inboundBuf = append(s.inboundBuf, data[n:]...)
			s.inMu.Unlock()
		}
		return n, nil
	case <-s.closeCh:
		// 尝试读取残余数据
		select {
		case data := <-s.inbound:
			return copy(p, data), nil
		default:
			return 0, io.EOF
		}
	}
}

// SessionConn 包装 Session 为 io.ReadWriteCloser，供 SOCKS5 使用
type SessionConn struct {
	session *Session
	manager *SessionManager
	once    sync.Once
}

func NewSessionConn(s *Session, m *SessionManager) *SessionConn {
	return &SessionConn{session: s, manager: m}
}

func (sc *SessionConn) Read(p []byte) (n int, err error) {
	return sc.session.ReadInbound(p)
}

func (sc *SessionConn) Write(p []byte) (n int, err error) {
	if sc.session.IsClosed() {
		return 0, fmt.Errorf("session closed")
	}
	sc.session.PushOutbound(p)
	return len(p), nil
}

func (sc *SessionConn) Close() error {
	sc.once.Do(func() {
		sc.session.Close()
		sc.manager.Remove(sc.session.SID())
	})
	return nil
}

// SessionManager 管理所有活跃会话
type SessionManager struct {
	sessions map[uint32]*Session
	mu       sync.RWMutex
	seq      uint32
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint32]*Session),
	}
}

func (m *SessionManager) Create(target string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq++
	sid := m.seq
	s := NewSession(sid, target)
	m.sessions[sid] = s
	return s
}

func (m *SessionManager) Get(sid uint32) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[sid]
}

func (m *SessionManager) Remove(sid uint32) {
	m.mu.Lock()
	delete(m.sessions, sid)
	m.mu.Unlock()
}

func (m *SessionManager) Range(fn func(sid uint32, s *Session) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for sid, s := range m.sessions {
		if !fn(sid, s) {
			return
		}
	}
}

func (m *SessionManager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// ParseTarget 从 SYN 包的 Data 解析目标地址
// 格式: host_len(1B) + host + port(2B)
func ParseTarget(data []byte) (string, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("empty target data")
	}
	hostLen := int(data[0])
	if len(data) < 1+hostLen+2 {
		return "", fmt.Errorf("target data too short: need %d, got %d", 1+hostLen+2, len(data))
	}
	host := string(data[1 : 1+hostLen])
	port := binary.BigEndian.Uint16(data[1+hostLen : 1+hostLen+2])
	return fmt.Sprintf("%s:%d", host, port), nil
}

// EncodeTarget 编码目标地址为 SYN 包的 Data
// IPv6 地址加方括号存储，确保 PHP stream_socket_client 兼容
func EncodeTarget(host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	buf := make([]byte, 1+len(host)+2)
	buf[0] = byte(len(host))
	copy(buf[1:], host)
	binary.BigEndian.PutUint16(buf[1+len(host):], port)
	return buf
}
