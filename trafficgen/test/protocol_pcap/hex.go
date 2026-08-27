package protocolpcap

import (
	"github.com/trafficgen/trafficgen/internal/pcaptest"
)

// 本文件是 internal/pcaptest 帧 hex 解析逻辑的薄转发层。既有测试
//（hex_test.go / verify_test.go）按原符号名调用，全部委托给共享包。

// hexInfo is one frame's parsed hex dump (tshark -x output).
type hexInfo = pcaptest.HexInfo

// parseTsharkHex delegates to pcaptest.ParseTsharkHex.
func parseTsharkHex(out string) []hexInfo {
	return pcaptest.ParseTsharkHex(out)
}

// hexDumpAll returns one hexInfo per frame in the pcap.
func hexDumpAll(path string, decodeAs []string) ([]hexInfo, error) {
	return pcaptest.HexDumpAll(path, decodeAs)
}

// parseHexBytes converts a hex dump string into bytes.
func parseHexBytes(s string) ([]byte, error) {
	return pcaptest.ParseHexBytes(s)
}

// matchHexPrefix reports whether frameBytes starts with the wanted prefix.
func matchHexPrefix(frameBytes, want []byte) (bool, int) {
	return pcaptest.MatchHexPrefix(frameBytes, want)
}

// matchHexOffset reports whether frameBytes[offset:] starts with want.
func matchHexOffset(frameBytes []byte, offset int, want []byte) (bool, int) {
	return pcaptest.MatchHexOffset(frameBytes, offset, want)
}