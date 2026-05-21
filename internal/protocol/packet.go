package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidPacket   = errors.New("invalid packet")
	ErrPacketTooLarge  = errors.New("packet too large")
	ErrFrameTooLarge   = errors.New("frame too large")
	ErrInvalidFrame    = errors.New("invalid frame")
)

type Packet struct {
	Flag Flag
	SID  uint32
	SEQ  uint32
	ACK  uint32
	Data []byte
}

func (p *Packet) Marshal() []byte {
	buf := make([]byte, HeaderSize+len(p.Data))
	buf[0] = byte(p.Flag)
	binary.BigEndian.PutUint32(buf[1:5], p.SID)
	binary.BigEndian.PutUint32(buf[5:9], p.SEQ)
	binary.BigEndian.PutUint32(buf[9:13], p.ACK)
	binary.BigEndian.PutUint32(buf[13:17], uint32(len(p.Data)))
	copy(buf[HeaderSize:], p.Data)
	return buf
}

func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("%w: need %d bytes, got %d", ErrInvalidPacket, HeaderSize, len(data))
	}

	dlen := binary.BigEndian.Uint32(data[13:17])
	if len(data) < HeaderSize+int(dlen) {
		return nil, fmt.Errorf("%w: data length mismatch", ErrInvalidPacket)
	}

	p := &Packet{
		Flag: Flag(data[0]),
		SID:  binary.BigEndian.Uint32(data[1:5]),
		SEQ:  binary.BigEndian.Uint32(data[5:9]),
		ACK:  binary.BigEndian.Uint32(data[9:13]),
	}

	if dlen > 0 {
		p.Data = make([]byte, dlen)
		copy(p.Data, data[HeaderSize:HeaderSize+dlen])
	}

	return p, nil
}

func (p *Packet) Size() int {
	return HeaderSize + len(p.Data)
}

func (p *Packet) IsCompressed() bool {
	return byte(p.Flag)&CompFlag != 0
}

func (p *Packet) Type() Flag {
	return Flag(byte(p.Flag) & FlagMask)
}

type Frame struct {
	Packets []*Packet
}

func (f *Frame) Marshal() []byte {
	total := FrameCountSize
	for _, p := range f.Packets {
		total += p.Size()
	}

	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(f.Packets)))

	offset := FrameCountSize
	for _, p := range f.Packets {
		n := copy(buf[offset:], p.Marshal())
		offset += n
	}

	return buf
}

func UnmarshalFrame(data []byte) (*Frame, error) {
	if len(data) < FrameCountSize {
		return nil, fmt.Errorf("%w: too short", ErrInvalidFrame)
	}

	count := binary.BigEndian.Uint16(data[0:2])
	frame := &Frame{Packets: make([]*Packet, 0, count)}

	offset := FrameCountSize
	for i := 0; i < int(count); i++ {
		if offset+HeaderSize > len(data) {
			return nil, fmt.Errorf("%w: truncated packet header at index %d", ErrInvalidFrame, i)
		}

		dlen := binary.BigEndian.Uint32(data[offset+13 : offset+17])
		pktSize := HeaderSize + int(dlen)

		if offset+pktSize > len(data) {
			return nil, fmt.Errorf("%w: truncated packet data at index %d", ErrInvalidFrame, i)
		}

		pkt, err := UnmarshalPacket(data[offset : offset+pktSize])
		if err != nil {
			return nil, err
		}

		frame.Packets = append(frame.Packets, pkt)
		offset += pktSize
	}

	return frame, nil
}

func ReadFrameFromReader(r io.Reader) (*Frame, error) {
	countBuf := make([]byte, FrameCountSize)
	if _, err := io.ReadFull(r, countBuf); err != nil {
		return nil, fmt.Errorf("reading frame count: %w", err)
	}

	count := binary.BigEndian.Uint16(countBuf)
	frame := &Frame{Packets: make([]*Packet, 0, count)}

	for i := 0; i < int(count); i++ {
		headerBuf := make([]byte, HeaderSize)
		if _, err := io.ReadFull(r, headerBuf); err != nil {
			return nil, fmt.Errorf("reading packet header %d: %w", i, err)
		}

		dlen := binary.BigEndian.Uint32(headerBuf[13:17])
		totalSize := HeaderSize + int(dlen)

		pktBuf := make([]byte, totalSize)
		copy(pktBuf, headerBuf)

		if dlen > 0 {
			if _, err := io.ReadFull(r, pktBuf[HeaderSize:]); err != nil {
				return nil, fmt.Errorf("reading packet data %d: %w", i, err)
			}
		}

		pkt, err := UnmarshalPacket(pktBuf)
		if err != nil {
			return nil, err
		}
		frame.Packets = append(frame.Packets, pkt)
	}

	return frame, nil
}
