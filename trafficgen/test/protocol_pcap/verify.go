package protocolpcap

import (
	"github.com/trafficgen/trafficgen/internal/pcaptest"
)

// 本文件是 internal/pcaptest 校验逻辑的薄转发层：既有测试（verify_test.go /
// run_all_test.go / verify_all_test.go / nic_drive_test.go）按原符号名调用，
// 全部委托给共享包，保证 MCP 工具与 go test 跑同一套断言（CLAUDE.md
// "所有测试经 MCP 执行"）。不在此处复制任何校验逻辑。

// VerifyPcap checks a generated pcap against the case's expectations using
// tshark. Returns a list of problems (empty = pass).
func VerifyPcap(pcapPath string, c Case) []string {
	return pcaptest.VerifyPcap(pcapPath, c)
}

// checkExpertInfo 委托给 pcaptest.CheckExpertInfo（深度 pcap 审计：
// Expert Info + checksum ILLEGAL）。
func checkExpertInfo(pcapPath, caseID string, decodeAs []string) []string {
	return pcaptest.CheckExpertInfo(pcapPath, caseID, decodeAs)
}

// isMalformedWhitelisted 委托给 pcaptest（tshark dissector 伪影 whitelist）。
func isMalformedWhitelisted(caseID, flag string) bool {
	return pcaptest.IsMalformedWhitelisted(caseID, flag)
}

// isZeroValue reports whether a tshark field value is the numeric zero.
func isZeroValue(s string) bool {
	return pcaptest.IsZeroValue(s)
}

// pcapPacketCount counts frames via tshark -T fields.
func pcapPacketCount(path string) (int, error) {
	return pcaptest.PacketCount(path)
}

// tsharkFieldValues returns one value per packet for the given field.
func tsharkFieldValues(path, field string, decodeAs []string) ([]string, error) {
	return pcaptest.FieldValues(path, field, decodeAs)
}

func runTshark(path string, args []string, decodeAs []string) (string, error) {
	return pcaptest.RunTshark(path, args, decodeAs)
}

// tcpFlagBits maps tshark tcp.flags values (e.g. "0x0002") to semantic flags.
func tcpFlagBits(s string) (uint16, error) {
	return pcaptest.TCPFlagBits(s)
}

func hasTCPFlag(s string, bit uint16) bool {
	return pcaptest.HasTCPFlag(s, bit)
}

// expectFirstFlag checks that the first TCP packet has the given flag bit set.
func expectFirstFlag(path, flag string, decodeAs []string) error {
	return pcaptest.ExpectFirstFlag(path, flag, decodeAs)
}

// byteAt returns the byte at i, or 0xff (sentinel) if out of range.
func byteAt(b []byte, i int) byte {
	return pcaptest.ByteAt(b, i)
}

// wantAt returns the wanted byte at i, or 0xff if out of range.
func wantAt(w []byte, i int) byte {
	return pcaptest.WantAt(w, i)
}