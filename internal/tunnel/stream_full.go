package tunnel

import "io"

type FullDuplexFactory struct {
	tunnel *Tunnel
	half   *HalfDuplexFactory
}

func NewFullDuplexFactory(t *Tunnel) *FullDuplexFactory {
	return &FullDuplexFactory{
		tunnel: t,
		half:   NewHalfDuplexFactory(t),
	}
}

func (f *FullDuplexFactory) Close() error { return nil }

// OpenSession 在 PHP/JSP 上 Full Duplex 退化为 Half Duplex
func (f *FullDuplexFactory) OpenSession(target string) (io.ReadWriteCloser, error) {
	return f.half.OpenSession(target)
}
