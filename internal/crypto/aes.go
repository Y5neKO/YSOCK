package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	nonceSize = 12
	tagSize   = 16
)

type Cipher struct {
	encKey  [32]byte
	authKey [32]byte
	counter uint64
	mu      sync.Mutex
}

func NewCipher(key string) *Cipher {
	c := &Cipher{}
	master := sha256.Sum256([]byte(key))

	h1 := sha256.New()
	h1.Write(master[:])
	h1.Write([]byte("enc"))
	var ek [32]byte
	copy(ek[:], h1.Sum(nil))
	c.encKey = ek

	h2 := sha256.New()
	h2.Write(master[:])
	h2.Write([]byte("auth"))
	var ak [32]byte
	copy(ak[:], h2.Sum(nil))
	c.authKey = ak
	return c
}

func (c *Cipher) nextNonce() [nonceSize]byte {
	c.mu.Lock()
	c.counter++
	n := c.counter
	c.mu.Unlock()

	h := sha256.New()
	h.Write(c.encKey[:])
	_ = binary.Write(h, binary.BigEndian, n)
	var nonce [nonceSize]byte
	copy(nonce[:], h.Sum(nil)[:nonceSize])
	return nonce
}

func (c *Cipher) generateKeystream(nonce [nonceSize]byte, length int) []byte {
	stream := make([]byte, 0, length)
	var counter uint32
	for len(stream) < length {
		h := sha256.New()
		h.Write(c.encKey[:])
		h.Write(nonce[:])
		_ = binary.Write(h, binary.BigEndian, counter)
		block := h.Sum(nil)
		remaining := length - len(stream)
		if remaining > len(block) {
			remaining = len(block)
		}
		stream = append(stream, block[:remaining]...)
		counter++
	}
	return stream
}

func (c *Cipher) computeTag(nonce [nonceSize]byte, ciphertext []byte) [tagSize]byte {
	mac := hmac.New(sha256.New, c.authKey[:])
	mac.Write(nonce[:])
	mac.Write(ciphertext)
	var tag [tagSize]byte
	copy(tag[:], mac.Sum(nil)[:tagSize])
	return tag
}

func (c *Cipher) Encrypt(plaintext []byte) []byte {
	nonce := c.nextNonce()
	keystream := c.generateKeystream(nonce, len(plaintext))

	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ keystream[i]
	}

	tag := c.computeTag(nonce, ciphertext)

	// output: nonce(12) + ciphertext + tag(16)
	out := make([]byte, nonceSize+len(ciphertext)+tagSize)
	copy(out[:nonceSize], nonce[:])
	copy(out[nonceSize:nonceSize+len(ciphertext)], ciphertext)
	copy(out[nonceSize+len(ciphertext):], tag[:])
	return out
}

func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	if len(data) < nonceSize+tagSize {
		return nil, fmt.Errorf("ciphertext too short: %d", len(data))
	}

	var nonce [nonceSize]byte
	copy(nonce[:], data[:nonceSize])

	ciphertext := data[nonceSize : len(data)-tagSize]
	gotTag := data[len(data)-tagSize:]

	// verify tag
	expectedTag := c.computeTag(nonce, ciphertext)
	if !hmac.Equal(gotTag, expectedTag[:]) {
		return nil, fmt.Errorf("authentication failed")
	}

	keystream := c.generateKeystream(nonce, len(ciphertext))
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ keystream[i]
	}

	return plaintext, nil
}
