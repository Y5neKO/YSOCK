package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/y5neko/ysock/internal/logger"
	"github.com/y5neko/ysock/internal/mux"
	"github.com/y5neko/ysock/internal/protocol"
)

const classicPollInterval = 200 * time.Millisecond

type ClassicFactory struct {
	tunnel *Tunnel
}

func NewClassicFactory(t *Tunnel) *ClassicFactory {
	return &ClassicFactory{tunnel: t}
}

func (f *ClassicFactory) Close() error { return nil }

func (f *ClassicFactory) OpenSession(target string) (io.ReadWriteCloser, error) {
	t := f.tunnel
	host, port, err := parseHostPort(target)
	if err != nil {
		return nil, err
	}

	session := t.manager.Create(target)
	sid := session.SID()

	logger.Debugf(tag, "classic open sid=%d target=%s:%d", sid, host, port)

	synData := mux.EncodeTarget(host, port)
	synFrame := &protocol.Frame{Packets: []*protocol.Packet{
		{Flag: protocol.FlagSYN, SID: sid, SEQ: t.nextSeq(), Data: synData},
	}}
	raw := synFrame.Marshal()
	encrypted := t.cipher.Encrypt(raw)
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	body, _ := json.Marshal(map[string]string{
		"a":  "cc",
		"d":  encoded,
		"id": fmt.Sprintf("%d", sid),
	})

	resp, err := t.client.Post(t.url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("classic connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("classic unexpected status: %d", resp.StatusCode)
	}

	var ackResp struct {
		D string `json:"d"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ackResp); err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("classic read ack: %w", err)
	}

	if ackResp.D == "" {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("classic empty ack")
	}

	ackEnc, _ := base64.StdEncoding.DecodeString(ackResp.D)
	ackRaw, err := t.cipher.Decrypt(ackEnc)
	if err != nil {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("classic decrypt ack: %w", err)
	}

	if len(ackRaw) < 2 {
		t.manager.Remove(sid)
		return nil, fmt.Errorf("classic short ack")
	}
	_ = binary.BigEndian.Uint16(ackRaw[:2])

	logger.Debugf(tag, "classic session established sid=%d", sid)

	cs := &classicSession{
		sid:     sid,
		tunnel:  t,
		session: session,
	}
	t.wg.Add(1)
	go cs.pollLoop()

	return mux.NewSessionConn(session, t.manager), nil
}

type classicSession struct {
	sid     uint32
	tunnel  *Tunnel
	session *mux.Session
	once    sync.Once
}

func (cs *classicSession) pollLoop() {
	defer cs.tunnel.wg.Done()
	defer cs.cleanup()

	ticker := time.NewTicker(classicPollInterval)
	defer ticker.Stop()

	const maxConsecutiveErrors = 5
	consecutiveErrors := 0

	for {
		select {
		case <-cs.session.OutboundReady():
		case <-ticker.C:
		case <-cs.session.CloseCh():
			return
		case <-cs.tunnel.closeCh:
			return
		}

		outbound := cs.session.PopOutbound(maxPayloadSize)

		var encodedData string
		if outbound != nil {
			encrypted := cs.tunnel.cipher.Encrypt(outbound)
			encodedData = base64.StdEncoding.EncodeToString(encrypted)
		}

		body, _ := json.Marshal(map[string]string{
			"a":  "cp",
			"d":  encodedData,
			"id": fmt.Sprintf("%d", cs.sid),
		})

		sendLen := 0
		if outbound != nil {
			sendLen = len(outbound)
		}

		resp, err := cs.tunnel.client.Post(cs.tunnel.url, "application/json", bytes.NewReader(body))
		if err != nil {
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				logger.Errorf(tag, "classic poll max errors sid=%d, giving up", cs.sid)
				return
			}
			logger.Debugf(tag, "classic poll error sid=%d (%d/%d) send=%d: %v",
				cs.sid, consecutiveErrors, maxConsecutiveErrors, sendLen, err)
			continue
		}

		var pollResp struct {
			D   string `json:"d"`
			Fin bool   `json:"fin"`
		}
		jsonErr := json.NewDecoder(resp.Body).Decode(&pollResp)
		resp.Body.Close()

		if jsonErr != nil {
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				return
			}
			if jsonErr != io.EOF {
				logger.Debugf(tag, "classic poll decode error sid=%d (%d/%d): %v",
					cs.sid, consecutiveErrors, maxConsecutiveErrors, jsonErr)
			}
			continue
		}

		consecutiveErrors = 0

		if pollResp.D != "" {
			enc, _ := base64.StdEncoding.DecodeString(pollResp.D)
			raw, decErr := cs.tunnel.cipher.Decrypt(enc)
			if decErr != nil {
				logger.Debugf(tag, "classic poll decrypt error sid=%d: %v", cs.sid, decErr)
				continue
			}

			if len(raw) >= 2 {
				cnt := int(binary.BigEndian.Uint16(raw[:2]))
				off := 2
				for i := 0; i < cnt && off+17 <= len(raw); i++ {
					flag := raw[off]
					pktSID := binary.BigEndian.Uint32(raw[off+1 : off+5])
					_ = binary.BigEndian.Uint32(raw[off+5 : off+9])
					_ = binary.BigEndian.Uint32(raw[off+9 : off+13])
					dlen := int(binary.BigEndian.Uint32(raw[off+13 : off+17]))
					off += 17

					if off+dlen > len(raw) {
						break
					}
					data := raw[off : off+dlen]
					off += dlen

					switch flag & 0x0F {
					case 0x02: // DATA
						if pktSID == cs.sid {
							cs.session.PushInbound(data)
						}
					case 0x08: // FIN
						logger.Debugf(tag, "classic recv FIN sid=%d", cs.sid)
						return
					}
				}
			}
			logger.Debugf(tag, "classic poll sid=%d send=%d recv_len=%d fin=%v",
				cs.sid, sendLen, len(pollResp.D), pollResp.Fin)
		}

		if pollResp.Fin {
			return
		}
	}
}

func (cs *classicSession) cleanup() {
	cs.once.Do(func() {
		logger.Debugf(tag, "classic cleanup sid=%d", cs.sid)
		cs.session.Close()
		cs.tunnel.manager.Remove(cs.sid)
		sendClose(cs.tunnel.url, cs.sid, cs.tunnel.client)
	})
}
