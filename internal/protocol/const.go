package protocol

type Flag byte

const (
	FlagRST  Flag = 0x0
	FlagSYN  Flag = 0x1
	FlagDATA Flag = 0x2
	FlagACK  Flag = 0x4
	FlagFIN  Flag = 0x8
	FlagPING Flag = 0x3
	FlagPONG Flag = 0x5
)

const (
	FlagMask byte = 0x0F
	CompFlag byte = 0x10
)

const (
	HeaderSize = 17 // 1(flag) + 4(sid) + 4(seq) + 4(ack) + 4(dlen)
	FrameCountSize = 2
	MaxPacketSize  = 65535
	MaxFrameSize   = 1 << 20 // 1MB
)
