package opcua

import (
	"encoding/binary"
	"fmt"
)

func uaFrame(kind string, body []byte) ([]byte, error) {
	if len(kind) != 4 {
		return nil, fmt.Errorf("opcua: invalid message kind")
	}
	if len(body)+8 > 0xffff {
		return nil, fmt.Errorf("opcua: MessageSize %d exceeds UInt16", len(body)+8)
	}
	out := make([]byte, 8+len(body))
	copy(out, kind)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	copy(out[8:], body)
	return out, nil
}

func BuildHEL(endpointLen uint32) ([]byte, error) {
	body := make([]byte, 20+4)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint32(body[4:8], 0)
	binary.LittleEndian.PutUint32(body[8:12], 65536)
	binary.LittleEndian.PutUint32(body[12:16], 65536)
	binary.LittleEndian.PutUint32(body[16:20], 0)
	binary.LittleEndian.PutUint32(body[20:24], endpointLen)
	return uaFrame("HELF", body)
}

func BuildACK() ([]byte, error) {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint32(body[4:8], 65536)
	binary.LittleEndian.PutUint32(body[8:12], 65536)
	binary.LittleEndian.PutUint32(body[12:16], 0)
	binary.LittleEndian.PutUint32(body[16:20], 0)
	return uaFrame("ACKF", body)
}

func BuildOPN(response bool, mode string) ([]byte, error) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint32(body[0:4], secureChannelID)
	if response {
		binary.LittleEndian.PutUint32(body[4:8], 1)
	}
	binary.LittleEndian.PutUint32(body[8:12], 1)
	binary.LittleEndian.PutUint32(body[12:16], 600000)
	binary.LittleEndian.PutUint32(body[16:20], 3600000)
	if mode == "sign" {
		body[20] = 1
	}
	return uaFrame("OPNF", body)
}

func BuildMSG(response bool) ([]byte, error) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint32(body[0:4], tokenID)
	binary.LittleEndian.PutUint32(body[4:8], 1)
	binary.LittleEndian.PutUint32(body[8:12], 1001)
	binary.LittleEndian.PutUint32(body[12:16], 13)
	if response {
		binary.LittleEndian.PutUint32(body[16:20], 0)
	}
	return uaFrame("MSGF", body)
}

func BuildCLO(response bool) ([]byte, error) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], secureChannelID)
	binary.LittleEndian.PutUint32(body[4:8], tokenID)
	return uaFrame("CLOF", body)
}
