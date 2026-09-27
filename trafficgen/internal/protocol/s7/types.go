package s7

import "github.com/trafficgen/trafficgen/internal/core"

type S7Config = core.S7Config
type S7Command = core.S7Command
type S7Item = core.S7Item

const (
	transportTCP   = "tcp"
	rosctrJob      = 1
	rosctrAckData  = 3
	rosctrUserdata = 7

	// maxSessions is the session-count ceiling (21-s7 §8.9: 1–16，防爆炸——
	// sessions 按会话线性展开包序列)。
	maxSessions = 16
	// kindRead is the default command kind (empty kind also routes here).
	kindRead = "read"
)
