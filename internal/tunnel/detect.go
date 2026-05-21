package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	ycrypto "github.com/y5neko/ysock/internal/crypto"
)

func DetectMode(url string, cipher *ycrypto.Cipher, client *http.Client) Mode {
	// 尝试 Half Duplex 流式检测
	mode := detectStream(url, cipher, client)
	return mode
}

func detectStream(url string, cipher *ycrypto.Cipher, client *http.Client) Mode {
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

	// 检查是否为流式响应（Content-Type: application/octet-stream）
	ct := resp.Header.Get("Content-Type")
	if ct == "application/octet-stream" {
		// 尝试读取流式帧
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
			elapsed := time.Since(start)
			if elapsed < 3*time.Second {
				return ModeHalfDuplex
			}
			return ModeHalfDuplex
		case <-readCtx.Done():
			return ModeClassic
		}
	}

	// JSON 响应，说明握手成功但非流式
	elapsed := time.Since(start)
	if elapsed < 3*time.Second {
		return ModeHalfDuplex
	}
	return ModeClassic
}
