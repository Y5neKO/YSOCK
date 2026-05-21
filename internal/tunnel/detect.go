package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	ycrypto "github.com/y5neko/ysock/internal/crypto"
	"github.com/y5neko/ysock/internal/logger"
)

func Probe(url string, cipher *ycrypto.Cipher, client *http.Client) error {
	testData := cipher.Encrypt([]byte("YSOCK_PING"))
	encoded := base64.StdEncoding.EncodeToString(testData)

	body, _ := json.Marshal(map[string]string{
		"a": "h",
		"d": encoded,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var ackResp struct {
		D string `json:"d"`
		M int    `json:"m"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ackResp); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	if ackResp.D == "" {
		return fmt.Errorf("empty response — key mismatch or payload error")
	}

	enc, _ := base64.StdEncoding.DecodeString(ackResp.D)
	plain, err := cipher.Decrypt(enc)
	if err != nil {
		return fmt.Errorf("decrypt failed — key mismatch")
	}

	if string(plain) != "YSOCK_PING" {
		return fmt.Errorf("echo mismatch — payload returned unexpected data")
	}

	logger.Debugf(tag, "probe handshake resp m=%d", ackResp.M)
	return nil
}

func DetectMode(url string, cipher *ycrypto.Cipher, client *http.Client) Mode {
	logger.Debugf(tag, "detecting optimal mode...")

	if DetectFullDuplex(url, cipher) {
		logger.Debugf(tag, "detect: full duplex supported")
		return ModeFullDuplex
	}
	logger.Debugf(tag, "detect: full duplex not available, testing half duplex...")

	return detectHalfDuplex(url, cipher, client)
}

func detectHalfDuplex(url string, cipher *ycrypto.Cipher, client *http.Client) Mode {
	testData := cipher.Encrypt([]byte("YSOCK_PING"))
	encoded := base64.StdEncoding.EncodeToString(testData)

	body, _ := json.Marshal(map[string]string{
		"a": "h",
		"d": encoded,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		logger.Debugf(tag, "detect half duplex: create request failed: %v", err)
		return ModeClassic
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		logger.Debugf(tag, "detect half duplex: request failed: %v", err)
		return ModeClassic
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Debugf(tag, "detect half duplex: status %d", resp.StatusCode)
		return ModeClassic
	}

	ct := resp.Header.Get("Content-Type")
	logger.Debugf(tag, "detect half duplex: content-type=%s", ct)

	if ct == "application/octet-stream" {
		lenBuf := make([]byte, 4)
		readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer readCancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			resp.Body.Read(lenBuf)
		}()

		select {
		case <-done:
			logger.Debugf(tag, "detect: half duplex confirmed (octet-stream + data)")
			return ModeHalfDuplex
		case <-readCtx.Done():
			logger.Debugf(tag, "detect: octet-stream but no data → classic")
			return ModeClassic
		}
	}

	elapsed := time.Since(start)
	logger.Debugf(tag, "detect half duplex: elapsed=%v ct=%s", elapsed, ct)
	if elapsed < 3*time.Second {
		logger.Debugf(tag, "detect: half duplex (fast response)")
		return ModeHalfDuplex
	}
	logger.Debugf(tag, "detect: classic (slow response %v)", elapsed)
	return ModeClassic
}
