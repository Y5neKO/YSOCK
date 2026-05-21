package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/y5neko/ysock/internal/logger"
)

const tag = "socks5"

const (
	socksVersion = 0x05

	authNone = 0x00
	authNo   = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

type Dialer func(network, target string) (io.ReadWriteCloser, error)

type Server struct {
	Addr   string
	Dialer Dialer
}

func NewServer(addr string, dialer Dialer) *Server {
	return &Server{Addr: addr, Dialer: dialer}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Addr, err)
	}
	defer ln.Close()
	logger.Infof(tag, "listening on %s", s.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Errorf(tag, "accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	target, err := s.handshake(conn)
	if err != nil {
		logger.Debugf(tag, "handshake %s: %v", conn.RemoteAddr(), err)
		return
	}

	logger.Debugf(tag, "connect %s → %s", conn.RemoteAddr(), target)

	remote, err := s.Dialer("tcp", target)
	if err != nil {
		logger.Errorf(tag, "dial %s: %v", target, err)
		sendReply(conn, 0x05, nil)
		return
	}
	defer remote.Close()

	sendReply(conn, 0x00, conn.LocalAddr())

	go relay(remote, conn)
	relay(conn, remote)
}

func (s *Server) handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	if buf[0] != socksVersion {
		return "", fmt.Errorf("unsupported version: 0x%02x", buf[0])
	}

	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}

	if _, err := conn.Write([]byte{socksVersion, authNone}); err != nil {
		return "", fmt.Errorf("write method: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socksVersion {
		return "", fmt.Errorf("unsupported version in request: 0x%02x", header[0])
	}
	if header[1] != cmdConnect {
		return "", fmt.Errorf("unsupported command: 0x%02x", header[1])
	}

	var host string
	switch header[3] {
	case atypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(ipBuf).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)

	case atypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("read ipv6: %w", err)
		}
		host = net.IP(ipBuf).String()

	default:
		return "", fmt.Errorf("unsupported atyp: 0x%02x", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", host, port), nil
	}
	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendReply(conn net.Conn, rep byte, bindAddr net.Addr) {
	resp := []byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			ip := tcpAddr.IP.To4()
			if ip != nil {
				copy(resp[4:8], ip)
				binary.BigEndian.PutUint16(resp[8:10], uint16(tcpAddr.Port))
			}
		}
	}
	_, _ = conn.Write(resp)
}

func relay(dst io.WriteCloser, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
