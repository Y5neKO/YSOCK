package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	ycrypto "github.com/y5neko/ysock/internal/crypto"
	"github.com/y5neko/ysock/internal/mux"
	"github.com/y5neko/ysock/internal/protocol"
)

const (
	maxPayloadSize = 32 * 1024
	writeRetry     = 3
	writeBaseDelay = 500 * time.Millisecond
	streamTimeout  = 60 * time.Second
	idleTimeout    = 300 * time.Second
)

type Mode byte

const (
	ModeAuto       Mode = 0x00
	ModeFullDuplex Mode = 0x01
	ModeHalfDuplex Mode = 0x02
	ModeClassic    Mode = 0x03
)

func (m Mode) String() string {
	switch m {
	case ModeFullDuplex:
		return "full"
	case ModeHalfDuplex:
		return "half"
	case ModeClassic:
		return "classic"
	default:
		return "auto"
	}
}

func ParseMode(s string) Mode {
	switch s {
	case "full":
		return ModeFullDuplex
	case "half":
		return ModeHalfDuplex
	case "classic":
		return ModeClassic
	default:
		return ModeAuto
	}
}

type StreamFactory interface {
	OpenSession(target string) (io.ReadWriteCloser, error)
	Close() error
}

type Tunnel struct {
	url     string
	cipher  *ycrypto.Cipher
	manager *mux.SessionManager
	client  *http.Client
	mode    Mode
	factory StreamFactory
	seq     uint64
	closeCh chan struct{}
	wg      sync.WaitGroup
}

func NewTunnel(url, key string, mode Mode) *Tunnel {
	return &Tunnel{
		url:     url,
		cipher:  ycrypto.NewCipher(key),
		manager: mux.NewSessionManager(),
		mode:    mode,
		closeCh: make(chan struct{}),
		client: &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxConnsPerHost:     50,
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 10,
			},
		},
	}
}

func (t *Tunnel) Manager() *mux.SessionManager { return t.manager }
func (t *Tunnel) Cipher() *ycrypto.Cipher      { return t.cipher }
func (t *Tunnel) URL() string                   { return t.url }
func (t *Tunnel) Client() *http.Client          { return t.client }
func (t *Tunnel) CloseCh() <-chan struct{}      { return t.closeCh }
func (t *Tunnel) WG() *sync.WaitGroup           { return &t.wg }
func (t *Tunnel) Mode() Mode                    { return t.mode }

func (t *Tunnel) nextSeq() uint32 {
	return uint32(atomic.AddUint64(&t.seq, 1))
}

func (t *Tunnel) Run() error {
	// 所有模式都先验证连通性和 key 正确性
	logf("probing %s ...", t.url)
	if err := Probe(t.url, t.cipher, t.client); err != nil {
		return fmt.Errorf("probe %s: %w", t.url, err)
	}
	logf("probe ok, payload reachable and key verified")

	if t.mode == ModeAuto {
		detected := DetectMode(t.url, t.cipher, t.client)
		t.mode = detected
	}

	switch t.mode {
	case ModeFullDuplex:
		t.factory = NewFullDuplexFactory(t)
	case ModeHalfDuplex:
		t.factory = NewHalfDuplexFactory(t)
	case ModeClassic:
		t.factory = NewClassicFactory(t)
	default:
		t.factory = NewHalfDuplexFactory(t)
	}

	return nil
}

func (t *Tunnel) Stop() {
	close(t.closeCh)
	if t.factory != nil {
		t.factory.Close()
	}
	t.wg.Wait()
}

func (t *Tunnel) DialFunc() func(network, target string) (io.ReadWriteCloser, error) {
	return func(network, target string) (io.ReadWriteCloser, error) {
		return t.factory.OpenSession(target)
	}
}

func buildSynBody(sid uint32, seq uint32, host string, port uint16, cipher *ycrypto.Cipher) ([]byte, error) {
	synData := mux.EncodeTarget(host, port)
	synFrame := &protocol.Frame{Packets: []*protocol.Packet{
		{Flag: protocol.FlagSYN, SID: sid, SEQ: seq, Data: synData},
	}}
	raw := synFrame.Marshal()
	encrypted := cipher.Encrypt(raw)
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	return json.Marshal(map[string]string{
		"a":  "c",
		"d":  encoded,
		"id": fmt.Sprintf("%d", sid),
	})
}

// ---- 流式帧读写 ----

func readStreamFrame(r io.Reader, cipher *ycrypto.Cipher) (byte, []byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, fmt.Errorf("read frame length: %w", err)
	}

	frameLen := binary.BigEndian.Uint32(lenBuf)
	if frameLen == 0 || frameLen > 256*1024 {
		return 0, nil, fmt.Errorf("invalid frame length: %d", frameLen)
	}

	frameBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frameBuf); err != nil {
		return 0, nil, fmt.Errorf("read frame data: %w", err)
	}

	decrypted, err := cipher.Decrypt(frameBuf)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt frame: %w", err)
	}

	if len(decrypted) < 1 {
		return 0, nil, fmt.Errorf("empty decrypted data")
	}

	return decrypted[0], decrypted[1:], nil
}

func writeStreamFrame(w io.Writer, typ byte, data []byte, cipher *ycrypto.Cipher) error {
	payload := make([]byte, 1+len(data))
	payload[0] = typ
	copy(payload[1:], data)

	encrypted := cipher.Encrypt(payload)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))

	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(encrypted)
	return err
}

// ---- 工具函数 ----

func parseHostPort(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	return host, port, nil
}

func sendClose(url string, sid uint32, client *http.Client) {
	body, _ := json.Marshal(map[string]string{
		"a":  "x",
		"id": fmt.Sprintf("%d", sid),
	})
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

func logf(format string, args ...interface{}) {
	log.Printf("[tunnel] "+format, args...)
}
