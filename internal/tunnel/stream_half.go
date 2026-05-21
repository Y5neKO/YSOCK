package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/y5neko/ysock/internal/logger"
	"github.com/y5neko/ysock/internal/mux"
)

type HalfDuplexFactory struct {
	tunnel *Tunnel
}

func NewHalfDuplexFactory(t *Tunnel) *HalfDuplexFactory {
	return &HalfDuplexFactory{tunnel: t}
}

func (f *HalfDuplexFactory) Close() error { return nil }

func (f *HalfDuplexFactory) OpenSession(target string) (io.ReadWriteCloser, error) {
	t := f.tunnel
	host, port, err := parseHostPort(target)
	if err != nil {
		return nil, err
	}

	session := t.manager.Create(target)
	sid := session.SID()

	logger.Debugf(tag, "half open sid=%d target=%s:%d", sid, host, port)

	body, err := buildSynBody(sid, t.nextSeq(), host, port, t.cipher)
	if err != nil {
		t.manager.Remove(sid)
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "POST", t.url, bytes.NewReader(body))
	if err != nil {
		cancel()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("connect: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	ackType, _, err := readStreamFrame(resp.Body, t.cipher)
	if err != nil {
		resp.Body.Close()
		cancel()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("read ack: %w", err)
	}
	if ackType != 0x00 {
		resp.Body.Close()
		cancel()
		t.manager.Remove(sid)
		return nil, fmt.Errorf("unexpected ack type: 0x%02x", ackType)
	}

	logger.Debugf(tag, "half session established sid=%d", sid)

	ss := &halfDuplexSession{
		sid:     sid,
		tunnel:  t,
		session: session,
		resp:    resp,
		cancel:  cancel,
	}

	t.wg.Add(2)
	go ss.readLoop()
	go ss.writeLoop()

	return mux.NewSessionConn(session, t.manager), nil
}

type halfDuplexSession struct {
	sid     uint32
	tunnel  *Tunnel
	session *mux.Session
	resp    *http.Response
	cancel  context.CancelFunc
	once    sync.Once
}

func (ss *halfDuplexSession) readLoop() {
	defer ss.tunnel.wg.Done()
	defer ss.cleanup()

	for {
		select {
		case <-ss.tunnel.closeCh:
			return
		default:
		}

		typ, data, err := readStreamFrame(ss.resp.Body, ss.tunnel.cipher)
		if err != nil {
			logger.Debugf(tag, "half read sid=%d: %v", ss.sid, err)
			return
		}

		switch typ {
		case 0x01:
			ss.session.PushInbound(data)
			logger.Debugf(tag, "half recv sid=%d len=%d", ss.sid, len(data))
		case 0x02:
			logger.Debugf(tag, "half recv FIN sid=%d", ss.sid)
			return
		}
	}
}

func (ss *halfDuplexSession) writeLoop() {
	defer ss.tunnel.wg.Done()

	for {
		select {
		case <-ss.session.OutboundReady():
		case <-ss.session.CloseCh():
			return
		case <-ss.tunnel.closeCh:
			return
		}

		data := ss.session.PopOutbound(maxPayloadSize)
		if data == nil {
			continue
		}

		if err := ss.sendData(data); err != nil {
			logger.Errorf(tag, "half write sid=%d: %v", ss.sid, err)
			return
		}
		logger.Debugf(tag, "half send sid=%d len=%d", ss.sid, len(data))
	}
}

func (ss *halfDuplexSession) sendData(data []byte) error {
	encrypted := ss.tunnel.cipher.Encrypt(data)
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	body, _ := json.Marshal(map[string]string{
		"a":  "d",
		"d":  encoded,
		"id": fmt.Sprintf("%d", ss.sid),
	})

	var lastErr error
	for i := 0; i < writeRetry; i++ {
		resp, err := ss.tunnel.client.Post(ss.tunnel.url, "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = err
			logger.Debugf(tag, "half sendData retry sid=%d attempt=%d: %v", ss.sid, i+1, err)
			delay := writeBaseDelay * time.Duration(1<<uint(i))
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
			time.Sleep(delay)
			continue
		}
		resp.Body.Close()
		return nil
	}
	return lastErr
}

func (ss *halfDuplexSession) cleanup() {
	ss.once.Do(func() {
		logger.Debugf(tag, "half cleanup sid=%d", ss.sid)
		ss.cancel()
		ss.resp.Body.Close()
		ss.session.Close()
		ss.tunnel.manager.Remove(ss.sid)
		sendClose(ss.tunnel.url, ss.sid, ss.tunnel.client)
	})
}
