package s7

import "github.com/trafficgen/trafficgen/internal/core"

type S7Config = core.S7Config
type S7Command = core.S7Command
type S7Item = core.S7Item

const (
	transportTCP  = "tcp"
	rosctrJob     = 1
	rosctrAckData = 3
)
