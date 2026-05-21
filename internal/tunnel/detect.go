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
)

// Probe 验证 payload URL 是否可达且 key 正确。
// 发送握手请求，验证服务端能正确加密回显测试数据。
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

	// 读取响应
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

	// 验证解密
	enc, _ := base64.StdEncoding.DecodeString(ackResp.D)
	plain, err := cipher.Decrypt(enc)
	if err != nil {
		return fmt.Errorf("decrypt failed — key mismatch")
	}

	if string(plain) != "YSOCK_PING" {
		return fmt.Errorf("echo mismatch — payload returned unexpected data")
	}

	return nil
}

// DetectMode 自动检测服务端支持的最优模式。
// 调用方应确保 Probe 已通过。
func DetectMode(url string, cipher *ycrypto.Cipher, client *http.Client) Mode {
	// 1. 尝试 Full Duplex（原始 TCP + application/octet-stream）
	if DetectFullDuplex(url, cipher) {
		return ModeFullDuplex
	}

	// 2. 检测 Half Duplex（标准 HTTP 流式响应）
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
		return ModeClassic
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return ModeClassic
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ModeClassic
	}

	ct := resp.Header.Get("Content-Type")
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
			return ModeHalfDuplex
		case <-readCtx.Done():
			return ModeClassic
		}
	}

	elapsed := time.Since(start)
	if elapsed < 3*time.Second {
		return ModeHalfDuplex
	}
	return ModeClassic
}
