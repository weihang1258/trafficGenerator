package redis

// Atomic test points for the Redis planner. Each test corresponds to one
// or more test cases in /tmp/l7_planner_design/testcases_redis.md (RESP2
// §2.1-§2.6, RESP3 §2.2, command framing, state machine, business
// scenarios, data scenarios). Tests assert observable PacketConfig field
// values, not just "no error".

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// --- helpers ---

// validRedisSpec returns a minimal valid Redis spec with TCP handshake
// and teardown enabled. Commands are set by each test as needed.
func validRedisSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1", DstIP: "192.0.2.2",
		SrcPort: 50000, DstPort: 6379,
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		Redis: &core.RedisConfig{SelectDB: -1},
	}
}

// redisSpecWithCmds returns a valid spec with the given commands and no
// auto-HELLO/AUTH/SELECT.
func redisSpecWithCmds(cmds ...core.RedisCommand) core.FlowSpec {
	spec := validRedisSpec()
	spec.Redis.Commands = cmds
	return spec
}

// findPacketsByDirection returns cfgs filtered by direction ("up" or "down")
// that have non-empty payloads (i.e. command/reply data segments, not
// handshake/teardown).
func findPacketsByDirection(cfgs []core.PacketConfig, dir string) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.Direction == dir && len(c.Payload) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// firstUpPayload returns the first up-direction payload, or fails the test.
func firstUpPayload(t *testing.T, cfgs []core.PacketConfig) []byte {
	t.Helper()
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 {
			return c.Payload
		}
	}
	t.Fatalf("no up payload found in %d cfgs", len(cfgs))
	return nil
}

// firstDownPayload returns the first down-direction payload, or fails.
func firstDownPayload(t *testing.T, cfgs []core.PacketConfig) []byte {
	t.Helper()
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 {
			return c.Payload
		}
	}
	t.Fatalf("no down payload found in %d cfgs", len(cfgs))
	return nil
}

// allDownPayloads returns all down-direction non-empty payloads concatenated.
func allDownPayloads(cfgs []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 {
			out = append(out, c.Payload)
		}
	}
	return out
}

// allUpPayloads returns all up-direction non-empty payloads.
func allUpPayloads(cfgs []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 {
			out = append(out, c.Payload)
		}
	}
	return out
}

// ===================================================================
// §1.1 RESP2 Simple String (+)
// ===================================================================

// 1.1.1.1: PING + AutoReply=pong -> "+PONG\r\n"
func TestRedis_1_1_1_1_PingPong(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+PONG\r\n" {
		t.Errorf("reply=%q, want '+PONG\\r\\n'", reply)
	}
	if len(reply) != 7 {
		t.Errorf("reply len=%d, want 7", len(reply))
	}
}

// 1.1.1.2: PING hi + AutoReply=ok -> "+OK\r\n"
func TestRedis_1_1_1_2_PingHiAutoOK(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"PING", "hi"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+OK\r\n" {
		t.Errorf("reply=%q, want '+OK\\r\\n'", reply)
	}
}

// 1.1.1.3: PING + explicit Reply="+PONG\r\n"
func TestRedis_1_1_1_3_PingExplicitReply(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"PING"}, Reply: "+PONG\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+PONG\r\n" {
		t.Errorf("reply=%q, want '+PONG\\r\\n'", reply)
	}
	if len(reply) != 7 {
		t.Errorf("reply len=%d, want 7", len(reply))
	}
}

// 1.1.1.4: MULTI + AutoReply=ok -> "+OK\r\n"
func TestRedis_1_1_1_4_MultiOK(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"MULTI"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+OK\r\n" {
		t.Errorf("reply=%q, want '+OK\\r\\n'", reply)
	}
}

// 1.1.1.5: DISCARD + AutoReply=ok
func TestRedis_1_1_1_5_DiscardOK(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"DISCARD"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+OK\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.1.1.6: EXEC + AutoReply=ok
func TestRedis_1_1_1_6_ExecOK(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"EXEC"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+OK\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.1.2.1: +QUEUED\r\n explicit. "+QUEUED\r\n" = 9 bytes (+ Q U E U E D \r \n).
func TestRedis_1_1_2_1_QueuedReply(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"SET", "k", "v"}, Reply: "+QUEUED\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+QUEUED\r\n" {
		t.Errorf("reply=%q, want '+QUEUED\\r\\n'", reply)
	}
	if len(reply) != 9 {
		t.Errorf("len=%d, want 9", len(reply))
	}
}

// 1.1.2.2: empty simple string "+\r\n"
func TestRedis_1_1_2_2_EmptySimpleString(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"PING"}, Reply: "+\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+\r\n" {
		t.Errorf("reply=%q, want '+\\r\\n'", reply)
	}
	if len(reply) != 3 {
		t.Errorf("len=%d, want 3", len(reply))
	}
}

// 1.1.2.4: large simple string > MSS -> 2 segments. Total = 1 + 1500 + 2 =
// 1503 bytes; seg1=1460, seg2=43 (1503-1460).
func TestRedis_1_1_2_4_LargeSimpleStringMSS(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).MSS = 1460
	big := "+" + strings.Repeat("a", 1500) + "\r\n"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, Reply: big}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	down := findPacketsByDirection(cfgs, "down")
	if len(down) != 2 {
		t.Fatalf("down segments=%d, want 2", len(down))
	}
	if len(down[0].Payload) != 1460 {
		t.Errorf("seg1 len=%d, want 1460", len(down[0].Payload))
	}
	if len(down[1].Payload) != 43 {
		t.Errorf("seg2 len=%d, want 43", len(down[1].Payload))
	}
}

// ===================================================================
// §1.2 RESP2 Error (-)
// ===================================================================

// 1.2.1.1: -ERR unknown command. Reply string "-ERR unknown command 'foobar'\r\n"
// is 31 bytes (- E R R space u n k n o w n ... = 29 chars + \r\n = 31).
func TestRedis_1_2_1_1_ErrUnknownCommand(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"FOO"}, Reply: "-ERR unknown command 'foobar'\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 31 {
		t.Errorf("len=%d, want 31", len(reply))
	}
}

// 1.2.2.1: -WRONGTYPE. Reply "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"
// = 68 bytes.
func TestRedis_1_2_2_1_WrongType(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"LPUSH", "str", "x"}, Reply: "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 68 {
		t.Errorf("len=%d, want 68", len(reply))
	}
}

// 1.2.3.1: -NOAUTH
func TestRedis_1_2_3_1_NoAuth(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "k"}, Reply: "-NOAUTH Authentication required.\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 34 {
		t.Errorf("len=%d, want 34", len(reply))
	}
}

// 1.2.4.1: -NOSCRIPT
func TestRedis_1_2_4_1_NoScript(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"EVALSHA", "abc", "0"}, Reply: "-NOSCRIPT No matching script. Please use EVAL or SCRIPT LOAD.\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 63 {
		t.Errorf("len=%d, want 63", len(reply))
	}
}

// 1.2.5.1: -OOM
func TestRedis_1_2_5_1_OOM(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"SET", "k", "v"}, Reply: "-OOM command not allowed when used memory > 'maxmemory'\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 57 {
		t.Errorf("len=%d, want 57", len(reply))
	}
}

// 1.2.5.3: -CLUSTERDOWN
func TestRedis_1_2_5_3_ClusterDown(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "k"}, Reply: "-CLUSTERDOWN Hash slot not served\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 35 {
		t.Errorf("len=%d, want 35", len(reply))
	}
}

// 1.2.6.1: -MOVED
func TestRedis_1_2_6_1_MovedRedirect(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "k"}, Reply: "-MOVED 3999 127.0.0.1:6381\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 28 {
		t.Errorf("len=%d, want 28", len(reply))
	}
}

// 1.2.6.2: -ASK
func TestRedis_1_2_6_2_AskRedirect(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "k"}, Reply: "-ASK 3999 127.0.0.1:6381\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 26 {
		t.Errorf("len=%d, want 26", len(reply))
	}
}

// ===================================================================
// §1.3 RESP2 Integer (:)
// ===================================================================

// 1.3.1: :0\r\n
func TestRedis_1_3_1_IntegerZero(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"EXISTS", "nokey"}, Reply: ":0\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":0\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.3.3: :-1\r\n (negative)
func TestRedis_1_3_3_IntegerNegOne(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"TTL", "k"}, Reply: ":-1\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.3.4: int64 max
func TestRedis_1_3_4_Int64Max(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"INCR", "k"}, Reply: ":9223372036854775807\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 22 {
		t.Errorf("len=%d, want 22", len(reply))
	}
}

// 1.3.6: INCR + AutoReply=integer-1
func TestRedis_1_3_6_IncrAutoInt1(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"INCR", "counter"}, AutoReply: "integer-1"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":1\r\n" {
		t.Errorf("reply=%q, want ':1\\r\\n'", reply)
	}
}

// 1.3.7: INCR + AutoReply=integer-0
func TestRedis_1_3_7_IncrAutoInt0(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"INCR", "counter"}, AutoReply: "integer-0"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":0\r\n" {
		t.Errorf("reply=%q, want ':0\\r\\n'", reply)
	}
}

// 1.3.11: TTL -2 (key not exist)
func TestRedis_1_3_11_TTLNeg2(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"TTL", "k"}, Reply: ":-2\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":-2\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// ===================================================================
// §1.4 RESP2 Bulk String ($)
// ===================================================================

// 1.4.1.1: $3\r\nbar\r\n
func TestRedis_1_4_1_1_BulkBar(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "foo"}, Reply: "$3\r\nbar\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$3\r\nbar\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 9 {
		t.Errorf("len=%d, want 9", len(reply))
	}
}

// 1.4.1.2: $0\r\n\r\n (empty bulk). Total = 6 bytes ($ 0 \r \n \r \n).
func TestRedis_1_4_1_2_BulkEmpty(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "k"}, Reply: "$0\r\n\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$0\r\n\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 6 {
		t.Errorf("len=%d, want 6", len(reply))
	}
}

// 1.4.2.1: $-1\r\n (NIL bulk)
func TestRedis_1_4_2_1_NILBulk(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "nokey"}, Reply: "$-1\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 5 {
		t.Errorf("len=%d, want 5", len(reply))
	}
}

// 1.4.2.2: AutoReply=nil
func TestRedis_1_4_2_2_AutoNil(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "nokey"}, AutoReply: core.RedisAutoReplyNilBulk})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.4.3.3: ArgsBase64 binary safe. SET and k are plain strings in Args;
// only the binary value uses ArgsBase64. "AAAD" decodes to 0x00 0x00 0x03
// (A=0, A=0, A=0, D=3 in base64 alphabet). Result:
// *3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\n\x00\x00\x03\r\n = 29 bytes.
func TestRedis_1_4_3_3_BinarySafeArgsBase64(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:       []string{"SET", "k"},
		ArgsBase64: []string{"AAAD"},
		AutoReply:  core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\n\x00\x00\x03\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 29 {
		t.Errorf("len=%d, want 29", len(cmd))
	}
}

// 1.4.3.4: UTF-8 emoji value
func TestRedis_1_4_3_4_EmojiValue(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"SET", "k", "🚀"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// $4\r\n🚀\r\n = 8 bytes (🚀 is 4 UTF-8 bytes)
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$4\r\n🚀\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.4.3.5: value containing CRLF is binary-safe. Value "a\r\nb" is 4 bytes,
// so the bulk is "$4\r\na\r\nb\r\n" and total cmd is 30 bytes:
// *3\r\n(4) $3\r\nSET\r\n(9) $1\r\nk\r\n(7) $4\r\n + a + \r\n + b + \r\n (10) = 30.
func TestRedis_1_4_3_5_ValueWithCRLF(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"SET", "k", "a\r\nb"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$4\r\na\r\nb\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 30 {
		t.Errorf("len=%d, want 23", len(cmd))
	}
}

// 1.4.4.1: 1MB value -> MSS segmentation
func TestRedis_1_4_4_1_LargeValueMSS(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).MSS = 1460
	big := strings.Repeat("x", 1048576) // 1MB
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"SET", "big", big}, AutoReply: core.RedisAutoReplyOK}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := findPacketsByDirection(cfgs, "up")
	// command frame: header + 1MB data. Header = *3\r\n$3\r\nSET\r\n$3\r\nbig\r\n$1048576\r\n = 22+9 = 31 bytes.
	// Total up payload = 31 + 1048576 + 2 (trailing \r\n) = 1048609.
	// Segments: ceil(1048609/1460) = 719. Plus handshake(1 SYN) + ACK(1) = 2 non-data up.
	// But handshake SYN/ACK have nil payload, so findPacketsByDirection skips them.
	// So ups should be 719 data segments.
	if len(ups) < 719 {
		t.Errorf("up data segments=%d, want >= 719", len(ups))
	}
	// First segment is 1460.
	if len(ups[0].Payload) != 1460 {
		t.Errorf("seg1 len=%d, want 1460", len(ups[0].Payload))
	}
}

// ===================================================================
// §1.5 RESP2 Array (*)
// ===================================================================

// 1.5.1.1: *0\r\n (empty array)
func TestRedis_1_5_1_1_EmptyArray(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"HGETALL", "empty"}, Reply: "*0\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*0\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 4 {
		t.Errorf("len=%d, want 4", len(reply))
	}
}

// 1.5.1.2: AutoReply=empty-arr
func TestRedis_1_5_1_2_AutoEmptyArr(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"HGETALL", "empty_hash"}, AutoReply: core.RedisAutoReplyEmpty})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*0\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.5.2.1: *-1\r\n (NIL array)
func TestRedis_1_5_2_1_NILArray(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"BLPOP", "q", "1"}, Reply: "*-1\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 5 {
		t.Errorf("len=%d, want 5", len(reply))
	}
}

// 1.5.2.2: AutoReply=nil-array
func TestRedis_1_5_2_2_AutoNILArray(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"BLPOP", "empty_list", "0.5"}, AutoReply: core.RedisAutoReplyNilArr})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.5.3.1: 2-element array
func TestRedis_1_5_3_1_TwoElementArray(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"LRANGE", "l", "0", "-1"}, Reply: "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 22 {
		t.Errorf("len=%d, want 22", len(reply))
	}
}

// 1.5.3.3: HGETALL 4-element array
func TestRedis_1_5_3_3_HGETALLArray(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"HGETALL", "u:1"}, Reply: "*4\r\n$4\r\nname\r\n$5\r\nalice\r\n$3\r\nage\r\n$2\r\n30\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 42 {
		t.Errorf("len=%d, want 42", len(reply))
	}
}

// 1.5.4.1: nested array
func TestRedis_1_5_4_1_NestedArray(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"EXEC"}, Reply: "*2\r\n*3\r\n:1\r\n:2\r\n:3\r\n*2\r\n+OK\r\n+OK\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 34 {
		t.Errorf("len=%d, want 34", len(reply))
	}
}

// 1.5.5.1: array with NIL bulk element
func TestRedis_1_5_5_1_ArrayWithNIL(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"MGET", "k1", "nokey"}, Reply: "*2\r\n$3\r\nfoo\r\n$-1\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*2\r\n$3\r\nfoo\r\n$-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
	if len(reply) != 18 {
		t.Errorf("len=%d, want 18", len(reply))
	}
}

// ===================================================================
// §1.6-1.15 RESP3 types
// ===================================================================

// 1.6.1: RESP3 Null _\r\n
func TestRedis_1_6_1_RESP3Null(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"GET", "nokey"}, Reply: "_\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	// HELLO 3 reply (%0\r\n) + _\r\n
	last := string(downs[len(downs)-1])
	if last != "_\r\n" {
		t.Errorf("last reply=%q, want '_\\r\\n'", last)
	}
	if len(last) != 3 {
		t.Errorf("len=%d, want 3", len(last))
	}
}

// 1.7.1: RESP3 Boolean #t
func TestRedis_1_7_1_RESP3BoolTrue(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"EXISTS", "k"}, Reply: "#t\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if last != "#t\r\n" {
		t.Errorf("last=%q, want '#t\\r\\n'", last)
	}
	if len(last) != 4 {
		t.Errorf("len=%d, want 4", len(last))
	}
}

// 1.7.2: RESP3 Boolean #f
func TestRedis_1_7_2_RESP3BoolFalse(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"EXISTS", "k"}, Reply: "#f\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if last != "#f\r\n" {
		t.Errorf("last=%q, want '#f\\r\\n'", last)
	}
}

// 1.8.1: RESP3 Double 3.14
func TestRedis_1_8_1_RESP3Double(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"ZSCORE", "z", "m"}, Reply: ",3.14\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if last != ",3.14\r\n" {
		t.Errorf("last=%q", last)
	}
	if len(last) != 7 {
		t.Errorf("len=%d, want 7", len(last))
	}
}

// 1.8.4: RESP3 Double inf
func TestRedis_1_8_4_RESP3DoubleInf(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"ZSCORE", "z", "m"}, Reply: ",inf\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if last != ",inf\r\n" {
		t.Errorf("last=%q", last)
	}
}

// 1.9.1: RESP3 Big Number
func TestRedis_1_9_1_RESP3BigNumber(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"GET", "big"}, Reply: "(123456789012345678901234567890\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if len(last) != 33 {
		t.Errorf("len=%d, want 33", len(last))
	}
}

// 1.10.1: RESP3 Blob Error
func TestRedis_1_10_1_RESP3BlobError(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"FOO"}, Reply: "!21\r\nSYNTAX invalid syntax\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if len(last) != 28 {
		t.Errorf("len=%d, want 28", len(last))
	}
}

// 1.11.1: RESP3 Verbatim String txt
func TestRedis_1_11_1_RESP3VerbatimTxt(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"GET", "v"}, Reply: "=15\r\ntxt:Hello World\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if len(last) != 22 {
		t.Errorf("len=%d, want 22", len(last))
	}
}

// 1.12.1: RESP3 Map
func TestRedis_1_12_1_RESP3Map(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"HGETALL", "h"}, Reply: "%2\r\n$3\r\nkey\r\n:1\r\n$3\r\nbar\r\n:2\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if len(last) != 30 {
		t.Errorf("len=%d, want 30", len(last))
	}
}

// 1.12.2: HELLO 3 full map reply
func TestRedis_1_12_2_Hello3MapReply(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.SkipHello = true
	reply := "%7\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n7.2.0\r\n$5\r\nproto\r\n:3\r\n$2\r\nid\r\n:42\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"HELLO", "3"}, Reply: reply}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if last != reply {
		t.Errorf("last=%q, want HELLO 3 map reply", last)
	}
}

// 1.13.1: RESP3 Set
func TestRedis_1_13_1_RESP3Set(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"SMEMBERS", "s"}, Reply: "~3\r\n$3\r\nfoo\r\n$3\r\nbar\r\n$3\r\nbaz\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if len(last) != 31 {
		t.Errorf("len=%d, want 31", len(last))
	}
}

// 1.14.1: RESP3 Push (pub/sub message)
func TestRedis_1_14_1_RESP3Push(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		{Args: []string{"PUBLISH", "news1", "hello"}, EmitAsPush: true, Reply: ">4\r\n$7\r\nmessage\r\n$5\r\nnews1\r\n$5\r\nhello\r\n:1\r\n"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	pushReply := string(downs[len(downs)-1])
	if len(pushReply) != 43 {
		t.Errorf("push reply len=%d, want 43", len(pushReply))
	}
}

// 1.15.1: RESP3 Attribute
func TestRedis_1_15_1_RESP3Attribute(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"GET", "k"}, Reply: "|1\r\n$11\r\npushed-from\r\n:5\r\n"}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if len(last) != 26 {
		t.Errorf("len=%d, want 26", len(last))
	}
}

// ===================================================================
// §1.16 Command frame structure
// ===================================================================

// 1.16.1.1: PING command frame
func TestRedis_1_16_1_1_PingFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*1\r\n$4\r\nPING\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 14 {
		t.Errorf("len=%d, want 14", len(cmd))
	}
}

// 1.16.1.2: SET foo bar command frame
func TestRedis_1_16_1_2_SetFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"SET", "foo", "bar"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 31 {
		t.Errorf("len=%d, want 31", len(cmd))
	}
}

// 1.16.1.3: LPUSH list a b c (5 args)
func TestRedis_1_16_1_3_LpushFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"LPUSH", "list", "a", "b", "c"}, AutoReply: "integer-3"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$5\r\nLPUSH\r\n$4\r\nlist\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 46 {
		t.Errorf("len=%d, want 46", len(cmd))
	}
}

// 1.16.1.4: EVAL frame
func TestRedis_1_16_1_4_EvalFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"EVAL", "return 1", "0"}, Reply: ":1\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nEVAL\r\n$8\r\nreturn 1\r\n$1\r\n0\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.16.1.5: HELLO 3 AUTH frame
func TestRedis_1_16_1_5_HelloAuthFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"HELLO", "3", "AUTH", "myuser", "mypass"}, Reply: "%0\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.16.2.1: large value MSS segmentation for command
func TestRedis_1_16_2_1_CommandMSSSegmentation(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).MSS = 1460
	big := strings.Repeat("x", 2000)
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"SET", "k", big}, AutoReply: core.RedisAutoReplyOK}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := findPacketsByDirection(cfgs, "up")
	// Frame: *3\r\n + $3\r\nSET\r\n + $1\r\nk\r\n + $4\r\n (2000 chars) \r\n
	// Total = 4 + 8 + 5 + 5 + 2000 + 2 = 2024 bytes -> 2 segments (1460 + 564)
	if len(ups) != 2 {
		t.Fatalf("up segments=%d, want 2", len(ups))
	}
	if len(ups[0].Payload) != 1460 {
		t.Errorf("seg1 len=%d, want 1460", len(ups[0].Payload))
	}
	if len(ups[1].Payload) != 569 {
		t.Errorf("seg2 len=%d, want 569", len(ups[1].Payload))
	}
}

// 1.16.2.2: small command fits in 1 segment
func TestRedis_1_16_2_2_SmallCommandOneSegment(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"SET", "k", "v"}, AutoReply: core.RedisAutoReplyOK})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := findPacketsByDirection(cfgs, "up")
	if len(ups) != 1 {
		t.Errorf("up segments=%d, want 1", len(ups))
	}
}

// ===================================================================
// §1.17 CRLF terminator
// ===================================================================

// 1.17.1: Simple String ends with CRLF
func TestRedis_1_17_1_SimpleStringCRLF(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"PING"}, Reply: "+OK\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) < 2 || reply[len(reply)-2] != '\r' || reply[len(reply)-1] != '\n' {
		t.Errorf("reply %q does not end with CRLF", reply)
	}
}

// 1.17.4: Bulk String has CRLF after size and after data
func TestRedis_1_17_4_BulkCRLF(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"GET", "k"}, Reply: "$3\r\nbar\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	// $3\r\nbar\r\n - size line ends at index 3 (\r\n), data line ends at 8
	if reply[2] != '\r' || reply[3] != '\n' {
		t.Errorf("size line not CRLF-terminated: %q", reply)
	}
	if reply[7] != '\r' || reply[8] != '\n' {
		t.Errorf("data line not CRLF-terminated: %q", reply)
	}
}

// 1.17.5: Array count line ends with CRLF
func TestRedis_1_17_5_ArrayCRLF(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{Args: []string{"LRANGE", "l", "0", "-1"}, Reply: "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if reply[2] != '\r' || reply[3] != '\n' {
		t.Errorf("array count line not CRLF-terminated: %q", reply)
	}
}

// ===================================================================
// §1.18 Advanced command clusters (Stream/BitMap/HLL/Geo)
// ===================================================================

// 1.18.1.1: XADD with MAXLEN ~ 1000
func TestRedis_1_18_1_1_XAddFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"XADD", "mystream", "MAXLEN", "~", "1000", "*", "sensor-id", "1234", "temperature", "19.8"},
		Reply: "$15\r\n1526919030474-0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=10
	if !strings.HasPrefix(string(cmd), "*10\r\n") {
		t.Errorf("argc prefix=%q, want '*10\\r\\n'", cmd[:5])
	}
	// Must contain MAXLEN, ~, 1000, *
	wantFragments := []string{"MAXLEN", "~", "1000", "*", "sensor-id", "1234", "temperature", "19.8"}
	for _, f := range wantFragments {
		if !strings.Contains(string(cmd), "$"+itoa(len(f))+"\r\n"+f+"\r\n") {
			t.Errorf("cmd missing fragment %q: %q", f, cmd)
		}
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$15\r\n1526919030474-0\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 1.18.1.2: XREAD with COUNT/BLOCK/STREAMS
func TestRedis_1_18_1_2_XReadFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"XREAD", "COUNT", "2", "BLOCK", "1000", "STREAMS", "mystream", "0-0"},
		Reply: "*1\r\n*2\r\n$8\r\nmystream\r\n*1\r\n*2\r\n$15\r\n1526919030474-0\r\n*2\r\n$9\r\nsensor-id\r\n$4\r\n1234\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=8
	if !strings.HasPrefix(string(cmd), "*8\r\n") {
		t.Errorf("argc=%q, want '*8\\r\\n'", cmd[:4])
	}
	// STREAMS must come before streams keys; key count = id count = 1
	if !strings.Contains(string(cmd), "STREAMS") {
		t.Errorf("cmd missing STREAMS: %q", cmd)
	}
}

// 1.18.1.3: XLEN
func TestRedis_1_18_1_3_XLenFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"XLEN", "mystream"},
		Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nXLEN\r\n$8\r\nmystream\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.18.2.1: SETBIT
func TestRedis_1_18_2_1_SetBitFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"SETBIT", "bits", "7", "1"},
		Reply: ":0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=4
	if !strings.HasPrefix(string(cmd), "*4\r\n") {
		t.Errorf("argc=%q, want '*4\\r\\n'", cmd[:4])
	}
	want := "*4\r\n$6\r\nSETBIT\r\n$4\r\nbits\r\n$1\r\n7\r\n$1\r\n1\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.18.2.2: GETBIT
func TestRedis_1_18_2_2_GetBitFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"GETBIT", "bits", "7"},
		Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nGETBIT\r\n$4\r\nbits\r\n$1\r\n7\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.18.2.3: BITCOUNT with BYTE
func TestRedis_1_18_2_3_BitCountFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"BITCOUNT", "bits", "0", "3", "BYTE"},
		Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=5
	if !strings.HasPrefix(string(cmd), "*5\r\n") {
		t.Errorf("argc=%q, want '*5\\r\\n'", cmd[:4])
	}
	want := "*5\r\n$8\r\nBITCOUNT\r\n$4\r\nbits\r\n$1\r\n0\r\n$1\r\n3\r\n$4\r\nBYTE\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.18.3.1: PFADD
func TestRedis_1_18_3_1_PfAddFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"PFADD", "hll", "a", "b", "c"},
		Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=5
	if !strings.HasPrefix(string(cmd), "*5\r\n") {
		t.Errorf("argc=%q, want '*5\\r\\n'", cmd[:4])
	}
	want := "*5\r\n$5\r\nPFADD\r\n$3\r\nhll\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.18.3.2: PFCOUNT multi-key
func TestRedis_1_18_3_2_PfCountFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args:  []string{"PFCOUNT", "hll", "hll2"},
		Reply: ":5\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$7\r\nPFCOUNT\r\n$3\r\nhll\r\n$4\r\nhll2\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 1.18.4.1: GEOADD with 2 members
func TestRedis_1_18_4_1_GeoAddFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"GEOADD", "Sicily", "13.361389", "38.115556", "Palermo", "15.087269", "37.502669", "Catania"},
		Reply: ":2\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=8
	if !strings.HasPrefix(string(cmd), "*8\r\n") {
		t.Errorf("argc=%q, want '*8\\r\\n'", cmd[:4])
	}
	// Verify both members present
	if !strings.Contains(string(cmd), "Palermo") || !strings.Contains(string(cmd), "Catania") {
		t.Errorf("cmd missing member names: %q", cmd)
	}
}

// 1.18.4.2: GEOSEARCH with FROMMEMBER/BYRADIUS/ASC/COUNT/WITHDIST
func TestRedis_1_18_4_2_GeoSearchFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"GEOSEARCH", "Sicily", "FROMMEMBER", "Palermo", "BYRADIUS", "200", "km", "ASC", "COUNT", "2", "WITHDIST"},
		Reply: "*2\r\n*2\r\n$7\r\nPalermo\r\n$6\r\n0.0000\r\n*2\r\n$7\r\nCatania\r\n$8\r\n166.2742\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// argc=11
	if !strings.HasPrefix(string(cmd), "*11\r\n") {
		t.Errorf("argc=%q, want '*11\\r\\n'", cmd[:5])
	}
	// Verify key parameters preserved
	checks := []string{"FROMMEMBER", "Palermo", "BYRADIUS", "200", "km", "ASC", "COUNT", "2", "WITHDIST"}
	for _, c := range checks {
		if !strings.Contains(string(cmd), c) {
			t.Errorf("cmd missing %q: %q", c, cmd)
		}
	}
}

// ===================================================================
// §2.1 INIT -> AUTH-FREE
// ===================================================================

// 2.1.1: No auth, Version=2 -> no HELLO/AUTH
func TestRedis_2_1_1_NoAuthRESP2(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	if !strings.HasPrefix(string(firstCmd), "*1\r\n$4\r\nPING") {
		t.Errorf("first cmd=%q, want PING (no HELLO/AUTH prefix)", firstCmd)
	}
}

// 2.1.2: No auth, Version=3, SkipHello=false -> HELLO 3 first
func TestRedis_2_1_2_Hello3First(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q (HELLO 3)", firstCmd, want)
	}
}

// ===================================================================
// §2.2 INIT -> AUTH-REQ -> AUTH-ED (RESP2 AUTH)
// ===================================================================

// 2.2.1: RESP2 AUTH user pass
func TestRedis_2_2_1_RESP2Auth(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Username = "myuser"
	spec.Redis.Password = "mypass"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q (AUTH)", firstCmd, want)
	}
}

// 2.2.2: RESP2 AUTH with empty username (legacy single-arg)
func TestRedis_2_2_2_RESP2AuthNoUser(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Password = "mypass"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nAUTH\r\n$6\r\nmypass\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q (legacy AUTH)", firstCmd, want)
	}
}

// ===================================================================
// §2.3 INIT -> ACL HELLO + AUTH (RESP3)
// ===================================================================

// 2.3.1: RESP3 HELLO 3 AUTH user pass
func TestRedis_2_3_1_RESP3HelloAuth(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Username = "myuser"
	spec.Redis.Password = "mypass"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q (HELLO 3 AUTH)", firstCmd, want)
	}
}

// 2.3.2: SkipHello=true suppresses auto HELLO
func TestRedis_2_3_2_SkipHello(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.SkipHello = true
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"HELLO", "3", "AUTH", "myuser", "mypass"}, Reply: "%0\r\n"},
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q", firstCmd, want)
	}
}

// ===================================================================
// §2.4 SELECT database
// ===================================================================

// 2.4.1: SelectDB=1
func TestRedis_2_4_1_SelectDB1(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SelectDB = 1
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$6\r\nSELECT\r\n$1\r\n1\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q (SELECT 1)", firstCmd, want)
	}
}

// 2.4.2: SelectDB=-1 (default) -> no SELECT
func TestRedis_2_4_2_NoSelect(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SelectDB = -1
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	if strings.HasPrefix(string(firstCmd), "*2\r\n$6\r\nSELECT") {
		t.Errorf("first cmd=%q, should NOT be SELECT", firstCmd)
	}
}

// 2.4.3: SelectDB=15
func TestRedis_2_4_3_SelectDB15(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SelectDB = 15
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$6\r\nSELECT\r\n$2\r\n15\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q", firstCmd, want)
	}
}

// 2.4.4: SelectDB=16 -> Validate error
func TestRedis_2_4_4_SelectDB16Rejected(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SelectDB = 16
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SelectDB") {
		t.Errorf("err=%v, want SelectDB error", err)
	}
}

// ===================================================================
// §2.5 CLIENT SETNAME
// ===================================================================

// 2.5.1: ClientName set
func TestRedis_2_5_1_ClientName(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.ClientName = "myclient"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$8\r\nmyclient\r\n"
	if string(firstCmd) != want {
		t.Errorf("first cmd=%q, want %q (CLIENT SETNAME)", firstCmd, want)
	}
}

// 2.5.2: ClientName empty -> no CLIENT SETNAME
func TestRedis_2_5_2_NoClientName(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.ClientName = ""
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	firstCmd := firstUpPayload(t, cfgs)
	if strings.HasPrefix(string(firstCmd), "*3\r\n$6\r\nCLIENT") {
		t.Errorf("first cmd=%q, should NOT be CLIENT SETNAME", firstCmd)
	}
}

// ===================================================================
// §2.6 Transaction MULTI -> EXEC
// ===================================================================

// 2.6.1: MULTI, SET, SET, EXEC with +QUEUED replies
func TestRedis_2_6_1_MultiExecQueued(t *testing.T) {
	spec := redisSpecWithCmds(
		core.RedisCommand{Args: []string{"MULTI"}, AutoReply: core.RedisAutoReplyOK},
		core.RedisCommand{Args: []string{"SET", "k1", "v1"}, AutoReply: core.RedisAutoReplyQueued},
		core.RedisCommand{Args: []string{"SET", "k2", "v2"}, AutoReply: core.RedisAutoReplyQueued},
		core.RedisCommand{Args: []string{"EXEC"}, Reply: "*2\r\n+OK\r\n+OK\r\n"},
	)
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	// +OK (MULTI), +QUEUED, +QUEUED, *2\r\n+OK\r\n+OK\r\n (EXEC)
	if len(downs) != 4 {
		t.Fatalf("downs=%d, want 4", len(downs))
	}
	if string(downs[0]) != "+OK\r\n" {
		t.Errorf("downs[0]=%q, want +OK", downs[0])
	}
	if string(downs[1]) != "+QUEUED\r\n" {
		t.Errorf("downs[1]=%q, want +QUEUED", downs[1])
	}
	if string(downs[2]) != "+QUEUED\r\n" {
		t.Errorf("downs[2]=%q, want +QUEUED", downs[2])
	}
	if string(downs[3]) != "*2\r\n+OK\r\n+OK\r\n" {
		t.Errorf("downs[3]=%q, want EXEC array", downs[3])
	}
}

// 2.6.2: MULTI, DISCARD
func TestRedis_2_6_2_MultiDiscard(t *testing.T) {
	spec := redisSpecWithCmds(
		core.RedisCommand{Args: []string{"MULTI"}, AutoReply: core.RedisAutoReplyOK},
		core.RedisCommand{Args: []string{"DISCARD"}, AutoReply: core.RedisAutoReplyOK},
	)
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	if len(downs) != 2 {
		t.Fatalf("downs=%d, want 2", len(downs))
	}
	if string(downs[0]) != "+OK\r\n" || string(downs[1]) != "+OK\r\n" {
		t.Errorf("downs=%q %q, want +OK +OK", downs[0], downs[1])
	}
}

// 2.6.4: EXEC returns NIL (WATCH abort)
func TestRedis_2_6_4_ExecNILAbort(t *testing.T) {
	spec := redisSpecWithCmds(
		core.RedisCommand{Args: []string{"WATCH", "k1"}, AutoReply: core.RedisAutoReplyOK},
		core.RedisCommand{Args: []string{"MULTI"}, AutoReply: core.RedisAutoReplyOK},
		core.RedisCommand{Args: []string{"SET", "k1", "v1"}, AutoReply: core.RedisAutoReplyQueued},
		core.RedisCommand{Args: []string{"EXEC"}, AutoReply: core.RedisAutoReplyNilBulk},
	)
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	last := string(downs[len(downs)-1])
	if last != "$-1\r\n" {
		t.Errorf("EXEC reply=%q, want $-1\\r\\n (NIL abort)", last)
	}
}

// ===================================================================
// §2.7 Pub/Sub state machine
// ===================================================================

// 2.7.1.1: SUBSCRIBE news -> confirmation with integer count
func TestRedis_2_7_1_1_SubscribeNews(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribeTo = []string{"news"}
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := allUpPayloads(cfgs)
	firstCmd := string(ups[0])
	want := "*2\r\n$9\r\nSUBSCRIBE\r\n$4\r\nnews\r\n"
	if firstCmd != want {
		t.Errorf("SUBSCRIBE cmd=%q, want %q", firstCmd, want)
	}
	// First down should be the subscribe confirmation
	downs := allDownPayloads(cfgs)
	confirm := string(downs[0])
	wantConfirm := "*3\r\n$9\r\nsubscribe\r\n$4\r\nnews\r\n:1\r\n"
	if confirm != wantConfirm {
		t.Errorf("confirm=%q, want %q", confirm, wantConfirm)
	}
}

// 2.7.1.2: SUBSCRIBE news sports -> 2 confirmations
func TestRedis_2_7_1_2_SubscribeTwoChannels(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribeTo = []string{"news", "sports"}
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	// First 2 downs are subscribe confirmations
	if string(downs[0]) != "*3\r\n$9\r\nsubscribe\r\n$4\r\nnews\r\n:1\r\n" {
		t.Errorf("confirm1=%q", downs[0])
	}
	if string(downs[1]) != "*3\r\n$9\r\nsubscribe\r\n$6\r\nsports\r\n:2\r\n" {
		t.Errorf("confirm2=%q", downs[1])
	}
}

// 2.7.2.1: PSUBSCRIBE news.*
func TestRedis_2_7_2_1_PSubscribePattern(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribePatterns = []string{"news.*"}
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := allUpPayloads(cfgs)
	firstCmd := string(ups[0])
	want := "*2\r\n$10\r\nPSUBSCRIBE\r\n$6\r\nnews.*\r\n"
	if firstCmd != want {
		t.Errorf("PSUBSCRIBE cmd=%q, want %q", firstCmd, want)
	}
	downs := allDownPayloads(cfgs)
	confirm := string(downs[0])
	wantConfirm := "*3\r\n$10\r\npsubscribe\r\n$6\r\nnews.*\r\n:1\r\n"
	if confirm != wantConfirm {
		t.Errorf("pconfirm=%q, want %q", confirm, wantConfirm)
	}
}

// 2.7.4.1: PUBLISH news hello -> :1
func TestRedis_2_7_4_1_PublishInteger1(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"PUBLISH", "news", "hello"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$7\r\nPUBLISH\r\n$4\r\nnews\r\n$5\r\nhello\r\n"
	if string(cmd) != want {
		t.Errorf("PUBLISH cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":1\r\n" {
		t.Errorf("PUBLISH reply=%q, want :1\\r\\n", reply)
	}
}

// 2.7.4.2: PUBLISH with integer-0 (no subscribers)
func TestRedis_2_7_4_2_PublishInteger0(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"PUBLISH", "news", "hello"}, AutoReply: "integer-0",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":0\r\n" {
		t.Errorf("reply=%q, want :0\\r\\n", reply)
	}
}

// 2.7.5.1: RESP3 Push frame for pub/sub message
func TestRedis_2_7_5_1_RESP3PushMessage(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 3
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		{Args: []string{"PUBLISH", "news", "hello"}, EmitAsPush: true, Reply: ">3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	pushFrame := string(downs[len(downs)-1])
	if !strings.HasPrefix(pushFrame, ">3\r\n") {
		t.Errorf("push frame=%q, want '>3\\r\\n...' prefix", pushFrame)
	}
}

// 2.7.6.1: SUBSCRIBED state rejects SET (user provides error reply)
func TestRedis_2_7_6_1_SubscribedRejectsSET(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribeTo = []string{"news"}
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"SET", "foo", "bar"}, Reply: "-ERR Can't execute 'set': only (P)SUBSCRIBE / (P)UNSUBSCRIBE / PING / RESET / QUIT are allowed in this context\r\n"},
		{Args: []string{"UNSUBSCRIBE", "news"}, Reply: "*3\r\n$11\r\nunsubscribe\r\n$4\r\nnews\r\n:0\r\n"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// Verify SET command frame still emitted
	ups := allUpPayloads(cfgs)
	setFound := false
	for _, u := range ups {
		if strings.Contains(string(u), "SET") && strings.Contains(string(u), "foo") {
			setFound = true
			break
		}
	}
	if !setFound {
		t.Error("SET command frame not emitted in SUBSCRIBED state")
	}
	// Verify error reply emitted
	downs := allDownPayloads(cfgs)
	errFound := false
	for _, d := range downs {
		if strings.HasPrefix(string(d), "-ERR Can't execute 'set'") {
			errFound = true
			break
		}
	}
	if !errFound {
		t.Error("SET rejection error reply not emitted")
	}
	// Verify unsubscribe confirmation still works after rejection
	unsubFound := false
	for _, d := range downs {
		if strings.Contains(string(d), "unsubscribe") {
			unsubFound = true
			break
		}
	}
	if !unsubFound {
		t.Error("unsubscribe confirmation not emitted after SET rejection")
	}
}

// 2.7.6.5: PING is whitelisted in SUBSCRIBED state
func TestRedis_2_7_6_5_PingWhitelistedInSubscribed(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribeTo = []string{"news"}
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	// First down is subscribe confirmation, second should be +PONG
	if len(downs) < 2 {
		t.Fatalf("downs=%d, want >= 2", len(downs))
	}
	if string(downs[1]) != "+PONG\r\n" {
		t.Errorf("PING reply in SUBSCRIBED=%q, want +PONG\\r\\n", downs[1])
	}
}

// ===================================================================
// §2.8 Pipeline mode
// ===================================================================

// 2.8.1: PipelineSize=4, 4 commands -> 4 cmds then 4 replies
func TestRedis_2_8_1_PipelineBatch(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.PipelineSize = 4
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"SET", "a", "1"}, AutoReply: core.RedisAutoReplyOK},
		{Args: []string{"GET", "a"}, Reply: "$1\r\n1\r\n"},
		{Args: []string{"INCR", "b"}, AutoReply: "integer-0"},
		{Args: []string{"EXISTS", "c"}, AutoReply: "integer-1"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// Extract data-carrying packets in order. Pipeline should emit 4 up
	// then 4 down.
	var ups, downs [][]byte
	for _, c := range cfgs {
		if len(c.Payload) == 0 {
			continue
		}
		if c.Direction == "up" {
			ups = append(ups, c.Payload)
		} else {
			downs = append(downs, c.Payload)
		}
	}
	if len(ups) != 4 {
		t.Errorf("up data packets=%d, want 4", len(ups))
	}
	if len(downs) != 4 {
		t.Errorf("down data packets=%d, want 4", len(downs))
	}
	// Verify replies are in order: +OK, $1\r\n1\r\n, :0\r\n, :1\r\n
	if string(downs[0]) != "+OK\r\n" {
		t.Errorf("reply[0]=%q, want +OK", downs[0])
	}
	if string(downs[1]) != "$1\r\n1\r\n" {
		t.Errorf("reply[1]=%q, want $1\\r\\n1", downs[1])
	}
	if string(downs[2]) != ":0\r\n" {
		t.Errorf("reply[2]=%q, want :0", downs[2])
	}
	if string(downs[3]) != ":1\r\n" {
		t.Errorf("reply[3]=%q, want :1", downs[3])
	}
}

// 2.8.2: PipelineSize=0 (default 1) -> strict 1:1
func TestRedis_2_8_2_DefaultPipeline1to1(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.PipelineSize = 0
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// In 1:1 mode, each cmd is immediately followed by its reply.
	// Pattern: up, down, up, down, up, down
	var dataSeq []string
	for _, c := range cfgs {
		if len(c.Payload) > 0 {
			dataSeq = append(dataSeq, c.Direction)
		}
	}
	wantSeq := []string{"up", "down", "up", "down", "up", "down"}
	if len(dataSeq) != len(wantSeq) {
		t.Fatalf("seq len=%d, want %d", len(dataSeq), len(wantSeq))
	}
	for i, s := range wantSeq {
		if dataSeq[i] != s {
			t.Errorf("seq[%d]=%s, want %s", i, dataSeq[i], s)
		}
	}
}

// 2.8.4: Pipeline with empty reply + AutoReply=none -> Validate error
func TestRedis_2_8_4_PipelineEmptyReplyError(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.PipelineSize = 4
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyNone},
	}
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Error("Validate should reject empty Reply + AutoReply=none")
	}
}

// ===================================================================
// §2.9 Cluster MOVED/ASK
// ===================================================================

// 2.9.1: -MOVED reply
func TestRedis_2_9_1_MovedReply(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"GET", "key_in_slot_3999"}, Reply: "-MOVED 3999 127.0.0.1:6381\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 28 {
		t.Errorf("len=%d, want 28", len(reply))
	}
}

// 2.9.2: ASKING command
func TestRedis_2_9_2_AskingCommand(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ASKING"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*1\r\n$6\r\nASKING\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// ===================================================================
// §2.10 QUIT and connection close
// ===================================================================

// 2.10.1: User adds QUIT at end
func TestRedis_2_10_1_QuitCommand(t *testing.T) {
	spec := redisSpecWithCmds(
		core.RedisCommand{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		core.RedisCommand{Args: []string{"QUIT"}, AutoReply: core.RedisAutoReplyOK},
	)
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := allUpPayloads(cfgs)
	quitFound := false
	for _, u := range ups {
		if strings.Contains(string(u), "QUIT") {
			quitFound = true
			break
		}
	}
	if !quitFound {
		t.Error("QUIT command not found in up payloads")
	}
}

// 2.10.2: Termination=true -> FIN-ACK/ACK/FIN-ACK/ACK
func TestRedis_2_10_2_TerminationFIN(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).Termination = true
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// handshake(3) + cmd(1) + reply(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Errorf("total packets=%d, want 9", len(cfgs))
	}
	// Last 4 are teardown: FIN-ACK(up), ACK(down), FIN-ACK(down), ACK(up)
	teardown := cfgs[len(cfgs)-4:]
	if teardown[0].Direction != "up" || teardown[0].L4.Flags != flagFINACK {
		t.Errorf("teardown[0]: dir=%s flags=%02x, want up/FIN-ACK", teardown[0].Direction, teardown[0].L4.Flags)
	}
	if teardown[1].Direction != "down" || teardown[1].L4.Flags != flagACK {
		t.Errorf("teardown[1]: dir=%s flags=%02x, want down/ACK", teardown[1].Direction, teardown[1].L4.Flags)
	}
	if teardown[2].Direction != "down" || teardown[2].L4.Flags != flagFINACK {
		t.Errorf("teardown[2]: dir=%s flags=%02x, want down/FIN-ACK", teardown[2].Direction, teardown[2].L4.Flags)
	}
	if teardown[3].Direction != "up" || teardown[3].L4.Flags != flagACK {
		t.Errorf("teardown[3]: dir=%s flags=%02x, want up/ACK", teardown[3].Direction, teardown[3].L4.Flags)
	}
}

// 2.10.3: RST=true -> single RST, no FIN
func TestRedis_2_10_3_RST(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).RST = true
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	// handshake(3) + cmd(1) + reply(1) + RST(1) = 6
	if len(cfgs) != 6 {
		t.Errorf("total packets=%d, want 6 (RST replaces teardown)", len(cfgs))
	}
	rst := cfgs[len(cfgs)-1]
	if rst.Direction != "up" || rst.L4.Flags != flagRSTACK {
		t.Errorf("last packet: dir=%s flags=%02x, want up/RST-ACK", rst.Direction, rst.L4.Flags)
	}
}

// ===================================================================
// §3.2 SET / GET scenarios
// ===================================================================

// 3.2.1: SET foo bar EX 60
func TestRedis_3_2_1_SetWithEX(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "foo", "bar", "EX", "60"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n$2\r\nEX\r\n$2\r\n60\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 3.2.4: GET foo -> $3\r\nbar\r\n
func TestRedis_3_2_4_GetFoo(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"GET", "foo"}, Reply: "$3\r\nbar\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$3\r\nbar\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 3.2.7: MGET with NIL bulk element
func TestRedis_3_2_7_MgetWithNIL(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"MGET", "k1", "k2", "nokey"}, Reply: "*3\r\n$2\r\nv1\r\n$2\r\nv2\r\n$-1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if !strings.Contains(string(reply), "$-1\r\n") {
		t.Errorf("reply should contain NIL bulk: %q", reply)
	}
}

// ===================================================================
// §3.4 HSET / HGETALL
// ===================================================================

// 3.4.1: HSET user:1 name alice age 30
func TestRedis_3_4_1_HSetMulti(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HSET", "user:1", "name", "alice", "age", "30"}, AutoReply: "integer-2",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*6\r\n$4\r\nHSET\r\n$6\r\nuser:1\r\n$4\r\nname\r\n$5\r\nalice\r\n$3\r\nage\r\n$2\r\n30\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":2\r\n" {
		t.Errorf("reply=%q, want :2\\r\\n", reply)
	}
}

// 3.4.3: HGETALL 4-element array
func TestRedis_3_4_3_HGetAll(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HGETALL", "user:1"}, Reply: "*4\r\n$4\r\nname\r\n$5\r\nalice\r\n$3\r\nage\r\n$2\r\n30\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 42 {
		t.Errorf("reply len=%d, want 42", len(reply))
	}
}

// ===================================================================
// §3.5 LPUSH / LRANGE
// ===================================================================

// 3.5.3: LRANGE 4 elements
func TestRedis_3_5_3_LRange(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LRANGE", "list", "0", "-1"}, Reply: "*4\r\n$1\r\nc\r\n$1\r\nb\r\n$1\r\na\r\n$1\r\nd\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "*4\r\n") {
		t.Errorf("reply=%q, want '*4\\r\\n...'", reply)
	}
}

// ===================================================================
// §3.6 ZADD / ZRANGE WITHSCORES
// ===================================================================

// 3.6.2: ZRANGE WITHSCORES
func TestRedis_3_6_2_ZRangeWithScores(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZRANGE", "rank", "0", "-1", "WITHSCORES"},
		Reply: "*4\r\n$5\r\nalice\r\n$3\r\n100\r\n$3\r\nbob\r\n$3\r\n200\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$6\r\nZRANGE\r\n$4\r\nrank\r\n$1\r\n0\r\n$2\r\n-1\r\n$10\r\nWITHSCORES\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// ===================================================================
// §3.7 SUBSCRIBE / PUBLISH
// ===================================================================

// 3.7.1: SUBSCRIBE then PUBLISH
func TestRedis_3_7_1_SubscribeThenPublish(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribeTo = []string{"news"}
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PUBLISH", "news", "hello"}, AutoReply: "integer-1"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := allUpPayloads(cfgs)
	// First up = SUBSCRIBE, second up = PUBLISH
	if !strings.HasPrefix(string(ups[0]), "*2\r\n$9\r\nSUBSCRIBE") {
		t.Errorf("ups[0]=%q, want SUBSCRIBE", ups[0])
	}
	if !strings.HasPrefix(string(ups[1]), "*3\r\n$7\r\nPUBLISH") {
		t.Errorf("ups[1]=%q, want PUBLISH", ups[1])
	}
}

// ===================================================================
// §3.10 BLPOP blocking
// ===================================================================

// 3.10.1: BLPOP success
func TestRedis_3_10_1_BLPOPSuccess(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"BLPOP", "queue", "5"}, Reply: "*2\r\n$5\r\nqueue\r\n$5\r\nhello\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "*2\r\n") {
		t.Errorf("reply=%q, want array", reply)
	}
}

// 3.10.2: BLPOP timeout -> *-1\r\n
func TestRedis_3_10_2_BLPOPTimeout(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"BLPOP", "queue", "0.5"}, AutoReply: core.RedisAutoReplyNilArr,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*-1\r\n" {
		t.Errorf("reply=%q, want *-1\\r\\n", reply)
	}
}

// ===================================================================
// §3.11 EVAL Lua
// ===================================================================

// 3.11.1: EVAL return 1 0
func TestRedis_3_11_1_EvalSimple(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"EVAL", "return 1", "0"}, Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nEVAL\r\n$8\r\nreturn 1\r\n$1\r\n0\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 3.11.4: SCRIPT LOAD
func TestRedis_3_11_4_ScriptLoad(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SCRIPT", "LOAD", "return 1"}, Reply: "$40\r\ne0e1f9fabfc9d4800c877a703b823ac0578ff839\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nSCRIPT\r\n$4\r\nLOAD\r\n$8\r\nreturn 1\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// ===================================================================
// §4.1 Empty values
// ===================================================================

// 4.1.1.1: SET k "" (empty value)
func TestRedis_4_1_1_1_SetEmptyValue(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "k", ""}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$0\r\n\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 26 {
		t.Errorf("len=%d, want 26", len(cmd))
	}
}

// 4.1.2.2: AutoReply=nil -> $-1\r\n
func TestRedis_4_1_2_2_AutoNil(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"GET", "nokey"}, AutoReply: core.RedisAutoReplyNilBulk,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$-1\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// 4.1.5.1: *0\r\n empty array
func TestRedis_4_1_5_1_EmptyArrayReply(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HGETALL", "eh"}, Reply: "*0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "*0\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// ===================================================================
// §4.2 Boundary values
// ===================================================================

// 4.2.3.1: single-char key
func TestRedis_4_2_3_1_SingleCharKey(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"GET", "a"}, Reply: "$1\r\nv\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$3\r\nGET\r\n$1\r\na\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
	if len(cmd) != 20 {
		t.Errorf("len=%d, want 20", len(cmd))
	}
}

// 4.2.4.1: int64 max
func TestRedis_4_2_4_1_Int64Max(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"INCR", "k"}, Reply: ":9223372036854775807\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 22 {
		t.Errorf("len=%d, want 22", len(reply))
	}
}

// 4.2.4.2: int64 min
func TestRedis_4_2_4_2_Int64Min(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"INCR", "k"}, Reply: ":-9223372036854775808\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 23 {
		t.Errorf("len=%d, want 23", len(reply))
	}
}

// ===================================================================
// §4.3 Abnormal values
// ===================================================================

// 4.3.1.1: binary-safe \x00\x01\x02
func TestRedis_4_3_1_1_BinarySafe(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "k", "\x00\x01\x02"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\n\x00\x01\x02\r\n"
	if string(cmd) != want {
		t.Errorf("cmd=%q, want %q", cmd, want)
	}
}

// 4.3.1.4: value with embedded CRLF
func TestRedis_4_3_1_4_ValueWithCRLF(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "k", "a\r\nb"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	// Value "a\r\nb" is 4 bytes. Size line says $4. Data is a\r\nb. Then trailing CRLF.
	// $4\r\na\r\nb\r\n - 9 bytes total for this bulk string portion
	if !strings.Contains(string(cmd), "$4\r\na\r\nb\r\n") {
		t.Errorf("cmd=%q should contain $4\\r\\na\\r\\nb\\r\\n", cmd)
	}
}

// 4.3.2.1: GARBAGE reply -> Validate error
func TestRedis_4_3_2_1_GarbageReplyRejected(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"PING"}, Reply: "GARBAGE",
	})
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Error("Validate should reject GARBAGE reply")
	}
}

// 4.3.2.2: $abc\r\n -> Validate error (non-numeric size)
func TestRedis_4_3_2_2_NonNumericSizeRejected(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"PING"}, Reply: "$abc\r\n",
	})
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Error("Validate should reject $abc (non-numeric size)")
	}
}

// 4.3.2.3: $3\r\nfoo (no trailing CRLF) -> Validate error
func TestRedis_4_3_2_3_MissingCRLFRejected(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"PING"}, Reply: "$3\r\nfoo",
	})
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Error("Validate should reject $3\\r\\nfoo (missing trailing CRLF)")
	}
}

// 4.3.2.4: empty Args -> Validate error
func TestRedis_4_3_2_4_EmptyArgsRejected(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Reply: "+OK\r\n",
	})
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Error("Validate should reject empty Args")
	}
}

// ===================================================================
// §4.4 Large data
// ===================================================================

// 4.4.1.1: 10MB bulk reply -> multiple segments
func TestRedis_4_4_1_1_LargeBulkReply(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).MSS = 1460
	big := strings.Repeat("x", 10485760) // 10MB
	reply := "$10485760\r\n" + big + "\r\n"
	spec.Redis.Commands = []core.RedisCommand{{Args: []string{"GET", "big"}, Reply: reply}}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := findPacketsByDirection(cfgs, "down")
	// Header (12) + 10MB + 2 = 10485774 bytes -> ceil/1460 = 7183 segments
	if len(downs) < 7180 {
		t.Errorf("down segments=%d, want >= 7180", len(downs))
	}
}

// ===================================================================
// §4.5 Small data
// ===================================================================

// 4.5.1.1: single PING
func TestRedis_4_5_1_1_SinglePing(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	if len(cmd) != 14 {
		t.Errorf("cmd len=%d, want 14", len(cmd))
	}
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 7 {
		t.Errorf("reply len=%d, want 7", len(reply))
	}
}

// 4.5.2.1: short SET k v
func TestRedis_4_5_2_1_ShortSet(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "k", "v"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	if len(cmd) != 27 {
		t.Errorf("cmd len=%d, want 27", len(cmd))
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+OK\r\n" {
		t.Errorf("reply=%q", reply)
	}
}

// ===================================================================
// §5 Concurrency
// ===================================================================

// 5.1.1: N=10 concurrent flows
func TestRedis_5_1_1_ConcurrentFlows(t *testing.T) {
	p := NewPlanner()
	const N = 10
	done := make(chan int, N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			spec := validRedisSpec()
			spec.SrcPort = uint16(50000 + idx)
			spec.Redis.Commands = []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Errorf("flow %d: %v", idx, err)
				done <- 0
				return
			}
			n := len(drain(ch))
			done <- n
		}(i)
	}
	total := 0
	for i := 0; i < N; i++ {
		total += <-done
	}
	// Each flow: handshake(3) + cmd(1) + reply(1) + teardown(4) = 9
	expected := N * 9
	if total != expected {
		t.Errorf("total packets=%d, want %d", total, expected)
	}
}

// 5.2.1: Pipeline 4 commands in order
func TestRedis_5_2_1_PipelineOrdering(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.PipelineSize = 4
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"SET", "a", "1"}, AutoReply: core.RedisAutoReplyOK},
		{Args: []string{"SET", "b", "2"}, AutoReply: core.RedisAutoReplyOK},
		{Args: []string{"SET", "c", "3"}, AutoReply: core.RedisAutoReplyOK},
		{Args: []string{"SET", "d", "4"}, AutoReply: core.RedisAutoReplyOK},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := findPacketsByDirection(cfgs, "up")
	if len(ups) != 4 {
		t.Fatalf("ups=%d, want 4", len(ups))
	}
	// Verify PacketIndex ascending
	for i := 1; i < len(ups); i++ {
		if ups[i].PacketIndex <= ups[i-1].PacketIndex {
			t.Errorf("PacketIndex not ascending at %d", i)
		}
	}
	// Verify commands in order: SET a, SET b, SET c, SET d
	for i, want := range []string{"a", "b", "c", "d"} {
		if !strings.Contains(string(ups[i].Payload), want) {
			t.Errorf("ups[%d]=%q, want to contain %q", i, ups[i].Payload, want)
		}
	}
}

// ===================================================================
// §6 Resource exhaustion / ctx cancellation
// ===================================================================

// 6.3.1: ctx cancellation stops planner
func TestRedis_6_3_1_CtxCancellation(t *testing.T) {
	p := NewPlanner()
	spec := validRedisSpec()
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Drain; should complete (channel closed) even with cancelled ctx.
	n := 0
	for range ch {
		n++
	}
	// With cancelled ctx, the planner may emit 0 or a few packets before
	// noticing. The key assertion is that the channel is closed (range
	// terminates) and no goroutine leak.
	if n > 9 {
		t.Errorf("packets=%d, expected <= 9 with cancelled ctx", n)
	}
}

// ===================================================================
// Validate tests
// ===================================================================

func TestRedisValidate_VersionInvalid(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.Version = 5
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Version") {
		t.Errorf("err=%v, want Version error", err)
	}
}

func TestRedisValidate_PipelineSizeNegative(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.PipelineSize = -1
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PipelineSize") {
		t.Errorf("err=%v, want PipelineSize error", err)
	}
}

func TestRedisValidate_InvalidSrcIP(t *testing.T) {
	spec := validRedisSpec()
	spec.SrcIP = "bad"
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want SrcIP error", err)
	}
}

func TestRedisValidate_MSSTooSmall(t *testing.T) {
	spec := validRedisSpec()
	testutil.EnsureTCP(&spec).MSS = 100
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want MSS error", err)
	}
}

func TestRedisValidate_NilRedis(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis = nil
	if err := NewPlanner().Validate(spec); err != nil {
		t.Errorf("nil Redis should be valid: %v", err)
	}
}

func TestRedisValidate_ArgsBase64Invalid(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		ArgsBase64: []string{"!!!"},
		AutoReply:  core.RedisAutoReplyOK,
	})
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ArgsBase64") {
		t.Errorf("err=%v, want ArgsBase64 error", err)
	}
}

func TestRedisValidate_PublishMessageB64Invalid(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.PublishMessages = []core.RedisPublish{{Channel: "ch", MessageB64: "!!!"}}
	err := NewPlanner().Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MessageB64") {
		t.Errorf("err=%v, want MessageB64 error", err)
	}
}

// itoa is a local helper to avoid strconv import in test assertions.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
