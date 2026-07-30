package redis

// Coverage gap tests for the Redis planner. These tests fill the spec-driven
// coverage gaps identified by crossverify_redis.md residuals (Q3 AUTH-fail,
// WATCH success branch) and by testcases_redis.md rows that had no
// corresponding Go test (Set/ZSet command frames, SET options, Hash/List
// read commands, SCAN family, INFO/CONFIG GET, complete business session,
// RESP2 pub/sub message push).
//
// Each test is spec-driven (mapped to a testcases_redis.md row or a
// crossverify residual) and asserts OBSERVABLE values: the client->server
// command frame argc/bulk-sizes/field bytes AND the server->client reply
// RESP type/bytes. The planner is a generic RESP frame emitter, so these
// tests verify it serializes each command family correctly.

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// ===================================================================
// §3.5 Set data structure (SADD / SREM / SMEMBERS / SISMEMBER / SCARD)
// crossverify §1.4.5 flagged Set coverage at 7.1%.
// ===================================================================

// 3.5.S1: SADD key member member -> :2 (added 2 new members)
func TestRedis_3_5_S1_SAddFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SADD", "myset", "a", "b"}, AutoReply: "integer-2",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*4\r\n$4\r\nSADD\r\n$5\r\nmyset\r\n$1\r\na\r\n$1\r\nb\r\n"
	if string(cmd) != want {
		t.Errorf("SADD cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":2\r\n" {
		t.Errorf("SADD reply=%q, want :2\\r\\n", reply)
	}
}

// 3.5.S2: SREM key member -> :1
func TestRedis_3_5_S2_SRemFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SREM", "myset", "a"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nSREM\r\n$5\r\nmyset\r\n$1\r\na\r\n"
	if string(cmd) != want {
		t.Errorf("SREM cmd=%q, want %q", cmd, want)
	}
}

// 3.5.S3: SMEMBERS key -> *2 array (RESP2) of bulk strings
func TestRedis_3_5_S3_SMembersFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SMEMBERS", "myset"}, Reply: "*2\r\n$1\r\na\r\n$1\r\nb\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$8\r\nSMEMBERS\r\n$5\r\nmyset\r\n"
	if string(cmd) != want {
		t.Errorf("SMEMBERS cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "*2\r\n") {
		t.Errorf("SMEMBERS reply=%q, want '*2\\r\\n...'", reply)
	}
}

// 3.5.S4: SISMEMBER key member -> :1
func TestRedis_3_5_S4_SIsMemberFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SISMEMBER", "myset", "a"}, Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$9\r\nSISMEMBER\r\n$5\r\nmyset\r\n$1\r\na\r\n"
	if string(cmd) != want {
		t.Errorf("SISMEMBER cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":1\r\n" {
		t.Errorf("SISMEMBER reply=%q, want :1\\r\\n", reply)
	}
}

// 3.5.S5: SCARD key -> :2
func TestRedis_3_5_S5_SCardFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SCARD", "myset"}, Reply: ":2\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$5\r\nSCARD\r\n$5\r\nmyset\r\n"
	if string(cmd) != want {
		t.Errorf("SCARD cmd=%q, want %q", cmd, want)
	}
}

// ===================================================================
// §3.6 Sorted Set command frames (ZADD/ZSCORE/ZRANK/ZCARD/ZINCRBY/
// ZREM/ZPOPMIN). Only ZRANGE WITHSCORES had a test before.
// ===================================================================

// 3.6.1: ZADD rank 100 alice 200 bob -> :2
func TestRedis_3_6_1_ZAddFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZADD", "rank", "100", "alice", "200", "bob"}, AutoReply: "integer-2",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*6\r\n$4\r\nZADD\r\n$4\r\nrank\r\n$3\r\n100\r\n$5\r\nalice\r\n$3\r\n200\r\n$3\r\nbob\r\n"
	if string(cmd) != want {
		t.Errorf("ZADD cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":2\r\n" {
		t.Errorf("ZADD reply=%q, want :2\\r\\n", reply)
	}
}

// 3.6.3: ZSCORE rank alice -> $3\r\n100\r\n
func TestRedis_3_6_3_ZScoreFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZSCORE", "rank", "alice"}, Reply: "$3\r\n100\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nZSCORE\r\n$4\r\nrank\r\n$5\r\nalice\r\n"
	if string(cmd) != want {
		t.Errorf("ZSCORE cmd=%q, want %q", cmd, want)
	}
}

// 3.6.4: ZRANK rank alice -> :0
func TestRedis_3_6_4_ZRankFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZRANK", "rank", "alice"}, Reply: ":0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$5\r\nZRANK\r\n$4\r\nrank\r\n$5\r\nalice\r\n"
	if string(cmd) != want {
		t.Errorf("ZRANK cmd=%q, want %q", cmd, want)
	}
}

// 3.6.5: ZCARD rank -> :2
func TestRedis_3_6_5_ZCardFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZCARD", "rank"}, Reply: ":2\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$5\r\nZCARD\r\n$4\r\nrank\r\n"
	if string(cmd) != want {
		t.Errorf("ZCARD cmd=%q, want %q", cmd, want)
	}
}

// 3.6.6: ZINCRBY rank 50 alice -> $3\r\n150\r\n
func TestRedis_3_6_6_ZIncrByFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZINCRBY", "rank", "50", "alice"}, Reply: "$3\r\n150\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*4\r\n$7\r\nZINCRBY\r\n$4\r\nrank\r\n$2\r\n50\r\n$5\r\nalice\r\n"
	if string(cmd) != want {
		t.Errorf("ZINCRBY cmd=%q, want %q", cmd, want)
	}
}

// 3.6.7: ZREM rank alice -> :1
func TestRedis_3_6_7_ZRemFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZREM", "rank", "alice"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nZREM\r\n$4\r\nrank\r\n$5\r\nalice\r\n"
	if string(cmd) != want {
		t.Errorf("ZREM cmd=%q, want %q", cmd, want)
	}
}

// 3.6.8: ZPOPMIN rank -> *2\r\n$3\r\nbob\r\n$3\r\n200\r\n
func TestRedis_3_6_8_ZPopMinFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZPOPMIN", "rank"}, Reply: "*2\r\n$3\r\nbob\r\n$3\r\n200\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$7\r\nZPOPMIN\r\n$4\r\nrank\r\n"
	if string(cmd) != want {
		t.Errorf("ZPOPMIN cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "*2\r\n") {
		t.Errorf("ZPOPMIN reply=%q, want '*2\\r\\n...'", reply)
	}
}

// ===================================================================
// §2.6.3 WATCH success branch (only abort branch 2.6.4 had a test).
// ===================================================================

// 2.6.3: WATCH k1 -> MULTI -> SET k1 v1 -> EXEC -> *1\r\n+OK\r\n
// (watched key unchanged, transaction commits)
func TestRedis_2_6_3_WatchMultiExecSuccess(t *testing.T) {
	spec := redisSpecWithCmds(
		core.RedisCommand{Args: []string{"WATCH", "k1"}, AutoReply: core.RedisAutoReplyOK},
		core.RedisCommand{Args: []string{"MULTI"}, AutoReply: core.RedisAutoReplyOK},
		core.RedisCommand{Args: []string{"SET", "k1", "v1"}, AutoReply: core.RedisAutoReplyQueued},
		core.RedisCommand{Args: []string{"EXEC"}, Reply: "*1\r\n+OK\r\n"},
	)
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	// +OK (WATCH), +OK (MULTI), +QUEUED, *1\r\n+OK\r\n (EXEC)
	if len(downs) != 4 {
		t.Fatalf("downs=%d, want 4", len(downs))
	}
	wantReplies := []string{"+OK\r\n", "+OK\r\n", "+QUEUED\r\n", "*1\r\n+OK\r\n"}
	for i, want := range wantReplies {
		if string(downs[i]) != want {
			t.Errorf("downs[%d]=%q, want %q", i, downs[i], want)
		}
	}
	// EXEC reply is a non-NIL array (transaction committed, not aborted).
	last := string(downs[3])
	if strings.HasPrefix(last, "$-1") {
		t.Errorf("EXEC reply is NIL bulk (abort); want committed array %q", last)
	}
}

// ===================================================================
// Q3 residual: AUTH failure / WRONGPASS state-keeping.
// crossverify_redis.md Q3: AUTH returns -WRONGPASS, connection stays in
// AUTH-REQ; client retries AUTH with correct password -> +OK.
// ===================================================================

func TestRedis_Q3_AuthWrongpassThenRetry(t *testing.T) {
	spec := validRedisSpec()
	// Do NOT set Username/Password on the config (which would auto-prepend
	// AUTH); instead control the AUTH frames via Commands to model a failed
	// AUTH followed by a successful retry. This matches crossverify Q3:
	// after -WRONGPASS the connection stays in AUTH-REQ and the client
	// retries AUTH with the correct password.
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"AUTH", "myuser", "wrongpass"}, Reply: "-WRONGPASS invalid username-password pair or user is disabled.\r\n"},
		{Args: []string{"AUTH", "myuser", "mypass"}, AutoReply: core.RedisAutoReplyOK},
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := allUpPayloads(cfgs)
	if len(ups) != 3 {
		t.Fatalf("ups=%d, want 3 (AUTH-wrong, AUTH-correct, PING)", len(ups))
	}
	// First up: AUTH with wrong password.
	wantAuth1 := "*3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$9\r\nwrongpass\r\n"
	if string(ups[0]) != wantAuth1 {
		t.Errorf("AUTH-wrong cmd=%q, want %q", ups[0], wantAuth1)
	}
	// Second up: AUTH with correct password (retry after WRONGPASS).
	wantAuth2 := "*3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n"
	if string(ups[1]) != wantAuth2 {
		t.Errorf("AUTH-retry cmd=%q, want %q", ups[1], wantAuth2)
	}
	// Replies: -WRONGPASS, +OK, +PONG.
	downs := allDownPayloads(cfgs)
	if len(downs) != 3 {
		t.Fatalf("downs=%d, want 3", len(downs))
	}
	if !strings.HasPrefix(string(downs[0]), "-WRONGPASS") {
		t.Errorf("reply[0]=%q, want -WRONGPASS prefix", downs[0])
	}
	if string(downs[1]) != "+OK\r\n" {
		t.Errorf("reply[1]=%q, want +OK (retry succeeded)", downs[1])
	}
	if string(downs[2]) != "+PONG\r\n" {
		t.Errorf("reply[2]=%q, want +PONG (post-auth PING)", downs[2])
	}
}

// ===================================================================
// §3.2 SET options + key ops (NX / NX-fail / MSET / DEL / EXPIRE / TTL /
// EXISTS / TYPE / INCR / INCRBY / DECR).
// ===================================================================

// 3.2.2: SET foo bar NX -> +OK
func TestRedis_3_2_2_SetNX(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "foo", "bar", "NX"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*4\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n$2\r\nNX\r\n"
	if string(cmd) != want {
		t.Errorf("SET NX cmd=%q, want %q", cmd, want)
	}
}

// 3.2.3: SET foo bar NX -> $-1 (key already exists, NX fails)
func TestRedis_3_2_3_SetNXFail(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SET", "foo", "bar", "NX"}, Reply: "$-1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "$-1\r\n" {
		t.Errorf("SET NX fail reply=%q, want $-1\\r\\n", reply)
	}
}

// 3.2.6: MSET k1 v1 k2 v2 -> +OK
func TestRedis_3_2_6_MSetFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"MSET", "k1", "v1", "k2", "v2"}, AutoReply: core.RedisAutoReplyOK,
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$4\r\nMSET\r\n$2\r\nk1\r\n$2\r\nv1\r\n$2\r\nk2\r\n$2\r\nv2\r\n"
	if string(cmd) != want {
		t.Errorf("MSET cmd=%q, want %q", cmd, want)
	}
}

// 3.2.8: DEL k1 k2 -> :2
func TestRedis_3_2_8_DelFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"DEL", "k1", "k2"}, AutoReply: "integer-2",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$3\r\nDEL\r\n$2\r\nk1\r\n$2\r\nk2\r\n"
	if string(cmd) != want {
		t.Errorf("DEL cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":2\r\n" {
		t.Errorf("DEL reply=%q, want :2\\r\\n", reply)
	}
}

// 3.2.9: INCR counter -> :1
func TestRedis_3_2_9_IncrFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"INCR", "counter"}, Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n"
	if string(cmd) != want {
		t.Errorf("INCR cmd=%q, want %q", cmd, want)
	}
}

// 3.2.10: INCRBY counter 10 -> :11
func TestRedis_3_2_10_IncrByFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"INCRBY", "counter", "10"}, Reply: ":11\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nINCRBY\r\n$7\r\ncounter\r\n$2\r\n10\r\n"
	if string(cmd) != want {
		t.Errorf("INCRBY cmd=%q, want %q", cmd, want)
	}
}

// 3.2.11: DECR counter -> :10
func TestRedis_3_2_11_DecrFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"DECR", "counter"}, Reply: ":10\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nDECR\r\n$7\r\ncounter\r\n"
	if string(cmd) != want {
		t.Errorf("DECR cmd=%q, want %q", cmd, want)
	}
}

// 3.2.12: EXPIRE foo 60 -> :1
func TestRedis_3_2_12_ExpireFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"EXPIRE", "foo", "60"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nEXPIRE\r\n$3\r\nfoo\r\n$2\r\n60\r\n"
	if string(cmd) != want {
		t.Errorf("EXPIRE cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":1\r\n" {
		t.Errorf("EXPIRE reply=%q, want :1\\r\\n", reply)
	}
}

// 3.2.13: TTL foo -> :60
func TestRedis_3_2_13_TTLFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"TTL", "foo"}, Reply: ":60\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$3\r\nTTL\r\n$3\r\nfoo\r\n"
	if string(cmd) != want {
		t.Errorf("TTL cmd=%q, want %q", cmd, want)
	}
}

// 3.2.14: EXISTS foo -> :1
func TestRedis_3_2_14_ExistsFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"EXISTS", "foo"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$6\r\nEXISTS\r\n$3\r\nfoo\r\n"
	if string(cmd) != want {
		t.Errorf("EXISTS cmd=%q, want %q", cmd, want)
	}
}

// 3.2.15: TYPE foo -> +string
func TestRedis_3_2_15_TypeFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"TYPE", "foo"}, Reply: "+string\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nTYPE\r\n$3\r\nfoo\r\n"
	if string(cmd) != want {
		t.Errorf("TYPE cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != "+string\r\n" {
		t.Errorf("TYPE reply=%q, want +string\\r\\n", reply)
	}
}

// ===================================================================
// §3.4 Hash read commands (HGET / HDEL / HLEN / HEXISTS / HKEYS /
// HVALS / HINCRBY). HSET/HGETALL had tests before.
// ===================================================================

// 3.4.2: HGET user:1 name -> $5\r\nalice\r\n
func TestRedis_3_4_2_HGetFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HGET", "user:1", "name"}, Reply: "$5\r\nalice\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nHGET\r\n$6\r\nuser:1\r\n$4\r\nname\r\n"
	if string(cmd) != want {
		t.Errorf("HGET cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if len(reply) != 11 {
		t.Errorf("HGET reply len=%d, want 11", len(reply))
	}
}

// 3.4.5: HDEL user:1 name -> :1
func TestRedis_3_4_5_HDelFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HDEL", "user:1", "name"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nHDEL\r\n$6\r\nuser:1\r\n$4\r\nname\r\n"
	if string(cmd) != want {
		t.Errorf("HDEL cmd=%q, want %q", cmd, want)
	}
}

// 3.4.6: HLEN user:1 -> :1
func TestRedis_3_4_6_HLenFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HLEN", "user:1"}, Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nHLEN\r\n$6\r\nuser:1\r\n"
	if string(cmd) != want {
		t.Errorf("HLEN cmd=%q, want %q", cmd, want)
	}
}

// 3.4.7: HEXISTS user:1 age -> :1
func TestRedis_3_4_7_HExistsFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HEXISTS", "user:1", "age"}, Reply: ":1\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$7\r\nHEXISTS\r\n$6\r\nuser:1\r\n$3\r\nage\r\n"
	if string(cmd) != want {
		t.Errorf("HEXISTS cmd=%q, want %q", cmd, want)
	}
}

// 3.4.8: HKEYS user:1 -> *1\r\n$3\r\nage\r\n
func TestRedis_3_4_8_HKeysFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HKEYS", "user:1"}, Reply: "*1\r\n$3\r\nage\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$5\r\nHKEYS\r\n$6\r\nuser:1\r\n"
	if string(cmd) != want {
		t.Errorf("HKEYS cmd=%q, want %q", cmd, want)
	}
}

// 3.4.9: HVALS user:1 -> *1\r\n$2\r\n30\r\n
func TestRedis_3_4_9_HValsFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HVALS", "user:1"}, Reply: "*1\r\n$2\r\n30\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$5\r\nHVALS\r\n$6\r\nuser:1\r\n"
	if string(cmd) != want {
		t.Errorf("HVALS cmd=%q, want %q", cmd, want)
	}
}

// 3.4.10: HINCRBY user:1 age 5 -> :35
func TestRedis_3_4_10_HIncrByFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HINCRBY", "user:1", "age", "5"}, Reply: ":35\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*4\r\n$7\r\nHINCRBY\r\n$6\r\nuser:1\r\n$3\r\nage\r\n$1\r\n5\r\n"
	if string(cmd) != want {
		t.Errorf("HINCRBY cmd=%q, want %q", cmd, want)
	}
}

// ===================================================================
// §3.5 List read commands (RPUSH / LLEN / LPOP / RPOP / LINDEX / LREM).
// LPUSH/LRANGE had tests before.
// ===================================================================

// 3.5.1: LPUSH list a b c -> :3
func TestRedis_3_5_1_LPushFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LPUSH", "list", "a", "b", "c"}, AutoReply: "integer-3",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*5\r\n$5\r\nLPUSH\r\n$4\r\nlist\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n"
	if string(cmd) != want {
		t.Errorf("LPUSH cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":3\r\n" {
		t.Errorf("LPUSH reply=%q, want :3\\r\\n", reply)
	}
}

// 3.5.2: RPUSH list d -> :4
func TestRedis_3_5_2_RPushFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"RPUSH", "list", "d"}, AutoReply: "integer-4",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$5\r\nRPUSH\r\n$4\r\nlist\r\n$1\r\nd\r\n"
	if string(cmd) != want {
		t.Errorf("RPUSH cmd=%q, want %q", cmd, want)
	}
}

// 3.5.4: LLEN list -> :4
func TestRedis_3_5_4_LLenFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LLEN", "list"}, Reply: ":4\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nLLEN\r\n$4\r\nlist\r\n"
	if string(cmd) != want {
		t.Errorf("LLEN cmd=%q, want %q", cmd, want)
	}
}

// 3.5.5: LPOP list -> $1\r\nc\r\n
func TestRedis_3_5_5_LPopFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LPOP", "list"}, Reply: "$1\r\nc\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nLPOP\r\n$4\r\nlist\r\n"
	if string(cmd) != want {
		t.Errorf("LPOP cmd=%q, want %q", cmd, want)
	}
}

// 3.5.6: RPOP list 2 -> *2\r\n$1\r\nd\r\n$1\r\na\r\n
func TestRedis_3_5_6_RPopFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"RPOP", "list", "2"}, Reply: "*2\r\n$1\r\nd\r\n$1\r\na\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$4\r\nRPOP\r\n$4\r\nlist\r\n$1\r\n2\r\n"
	if string(cmd) != want {
		t.Errorf("RPOP cmd=%q, want %q", cmd, want)
	}
}

// 3.5.7: LINDEX list 0 -> $1\r\nb\r\n
func TestRedis_3_5_7_LIndexFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LINDEX", "list", "0"}, Reply: "$1\r\nb\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nLINDEX\r\n$4\r\nlist\r\n$1\r\n0\r\n"
	if string(cmd) != want {
		t.Errorf("LINDEX cmd=%q, want %q", cmd, want)
	}
}

// 3.5.8: LREM list 1 b -> :1
func TestRedis_3_5_8_LRemFrame(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LREM", "list", "1", "b"}, AutoReply: "integer-1",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*4\r\n$4\r\nLREM\r\n$4\r\nlist\r\n$1\r\n1\r\n$1\r\nb\r\n"
	if string(cmd) != want {
		t.Errorf("LREM cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if string(reply) != ":1\r\n" {
		t.Errorf("LREM reply=%q, want :1\\r\\n", reply)
	}
}

// ===================================================================
// §3.7 SCAN family (SCAN / HSCAN / SSCAN / ZSCAN). Cursor iteration.
// Not in testcases_redis.md but in design §3.7 key-ops + brief gap #8.
// ===================================================================

// SCAN 0 MATCH user:* COUNT 10 -> *2\r\n$1\r\n0\r\n*0\r\n (cursor + empty)
func TestRedis_3_7_SCAN(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SCAN", "0", "MATCH", "user:*", "COUNT", "10"},
		Reply: "*2\r\n$1\r\n0\r\n*0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*6\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nMATCH\r\n$6\r\nuser:*\r\n$5\r\nCOUNT\r\n$2\r\n10\r\n"
	if string(cmd) != want {
		t.Errorf("SCAN cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	// Reply is *2 array: [cursor-bulk, element-array]
	if !strings.HasPrefix(string(reply), "*2\r\n") {
		t.Errorf("SCAN reply=%q, want '*2\\r\\n...'", reply)
	}
}

// HSCAN myhash 0 -> *2\r\n$1\r\n0\r\n*0\r\n
func TestRedis_3_7_HSCAN(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"HSCAN", "myhash", "0"}, Reply: "*2\r\n$1\r\n0\r\n*0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$5\r\nHSCAN\r\n$6\r\nmyhash\r\n$1\r\n0\r\n"
	if string(cmd) != want {
		t.Errorf("HSCAN cmd=%q, want %q", cmd, want)
	}
}

// SSCAN myset 0 -> *2\r\n$1\r\n0\r\n*0\r\n
func TestRedis_3_7_SSCAN(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"SSCAN", "myset", "0"}, Reply: "*2\r\n$1\r\n0\r\n*0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$5\r\nSSCAN\r\n$5\r\nmyset\r\n$1\r\n0\r\n"
	if string(cmd) != want {
		t.Errorf("SSCAN cmd=%q, want %q", cmd, want)
	}
}

// ZSCAN rank 0 -> *2\r\n$1\r\n0\r\n*0\r\n
func TestRedis_3_7_ZSCAN(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"ZSCAN", "rank", "0"}, Reply: "*2\r\n$1\r\n0\r\n*0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$5\r\nZSCAN\r\n$4\r\nrank\r\n$1\r\n0\r\n"
	if string(cmd) != want {
		t.Errorf("ZSCAN cmd=%q, want %q", cmd, want)
	}
}

// ===================================================================
// §3.12 Server management (INFO / CONFIG GET). Not previously covered.
// ===================================================================

// INFO server -> bulk string reply
func TestRedis_3_12_INFO(t *testing.T) {
	info := "# Server\r\nredis_version:7.2.0\r\n"
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"INFO", "server"}, Reply: "$" + itoa(len(info)) + "\r\n" + info + "\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"
	if string(cmd) != want {
		t.Errorf("INFO cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "$") {
		t.Errorf("INFO reply=%q, want bulk string '$...'", reply)
	}
	if !strings.Contains(string(reply), "redis_version") {
		t.Errorf("INFO reply should contain redis_version: %q", reply)
	}
}

// CONFIG GET maxmemory -> *2\r\n$10\r\nmaxmemory\r\n$1\r\n0\r\n
func TestRedis_3_12_ConfigGet(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"CONFIG", "GET", "maxmemory"},
		Reply: "*2\r\n$10\r\nmaxmemory\r\n$1\r\n0\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$9\r\nmaxmemory\r\n"
	if string(cmd) != want {
		t.Errorf("CONFIG GET cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "*2\r\n") {
		t.Errorf("CONFIG GET reply=%q, want '*2\\r\\n...'", reply)
	}
}

// ===================================================================
// Complete business session: AUTH -> SELECT db -> SET -> GET -> INCR ->
// LPUSH -> LRANGE -> QUIT. End-to-end multi-command flow covering
// multiple data structures (String/INCR/List) in one TCP session.
// ===================================================================

func TestRedis_BusinessSession_AuthSelectSetGetIncrLpushLrangeQuit(t *testing.T) {
	p := NewPlanner()
	spec := validRedisSpec()
	spec.Redis.Username = "app"
	spec.Redis.Password = "secret"
	spec.Redis.SelectDB = 3
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"SET", "counter", "0"}, AutoReply: core.RedisAutoReplyOK},
		{Args: []string{"GET", "counter"}, Reply: "$1\r\n0\r\n"},
		{Args: []string{"INCR", "counter"}, Reply: ":1\r\n"},
		{Args: []string{"LPUSH", "tasks", "t1", "t2"}, AutoReply: "integer-2"},
		{Args: []string{"LRANGE", "tasks", "0", "-1"}, Reply: "*2\r\n$2\r\nt2\r\n$2\r\nt1\r\n"},
		{Args: []string{"QUIT"}, AutoReply: core.RedisAutoReplyOK},
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Extract up commands in order (skipping handshake/teardown).
	var ups []string
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 {
			ups = append(ups, string(c.Payload))
		}
	}
	// Expected up sequence: AUTH, SELECT 3, SET, GET, INCR, LPUSH, LRANGE, QUIT
	wantCmds := []string{
		"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$6\r\nsecret\r\n",
		"*2\r\n$6\r\nSELECT\r\n$1\r\n3\r\n",
		"*3\r\n$3\r\nSET\r\n$7\r\ncounter\r\n$1\r\n0\r\n",
		"*2\r\n$3\r\nGET\r\n$7\r\ncounter\r\n",
		"*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n",
		"*4\r\n$5\r\nLPUSH\r\n$5\r\ntasks\r\n$2\r\nt1\r\n$2\r\nt2\r\n",
		"*4\r\n$6\r\nLRANGE\r\n$5\r\ntasks\r\n$1\r\n0\r\n$2\r\n-1\r\n",
		"*1\r\n$4\r\nQUIT\r\n",
	}
	if len(ups) != len(wantCmds) {
		t.Fatalf("up commands=%d, want %d\n%s", len(ups), len(wantCmds), strings.Join(ups, "\n"))
	}
	for i, want := range wantCmds {
		if ups[i] != want {
			t.Errorf("ups[%d]=%q, want %q", i, ups[i], want)
		}
	}

	// Extract down replies in order.
	var downs []string
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 {
			downs = append(downs, string(c.Payload))
		}
	}
	// Expected replies: +OK (AUTH), +OK (SELECT), +OK (SET), $1\r\n0, :1, :2, *2..., +OK (QUIT)
	wantReplies := []string{
		"+OK\r\n", "+OK\r\n", "+OK\r\n", "$1\r\n0\r\n", ":1\r\n",
		":2\r\n", "*2\r\n$2\r\nt2\r\n$2\r\nt1\r\n", "+OK\r\n",
	}
	if len(downs) != len(wantReplies) {
		t.Fatalf("down replies=%d, want %d\n%s", len(downs), len(wantReplies), strings.Join(downs, "\n"))
	}
	for i, want := range wantReplies {
		if downs[i] != want {
			t.Errorf("downs[%d]=%q, want %q", i, downs[i], want)
		}
	}

	// Verify the TCP teardown (FIN-ACK/ACK/FIN-ACK/ACK) follows QUIT reply.
	// Total: handshake(3) + AUTH(2) + SELECT(2) + 6 commands(12) + teardown(4) = 23
	if len(cfgs) != 23 {
		t.Errorf("total packets=%d, want 23", len(cfgs))
	}
	teardown := cfgs[len(cfgs)-4:]
	if teardown[0].Direction != "up" || teardown[0].L4.Flags != flagFINACK {
		t.Errorf("teardown[0]: dir=%s flags=%02x, want up/FIN-ACK", teardown[0].Direction, teardown[0].L4.Flags)
	}
	if teardown[2].Direction != "down" || teardown[2].L4.Flags != flagFINACK {
		t.Errorf("teardown[2]: dir=%s flags=%02x, want down/FIN-ACK", teardown[2].Direction, teardown[2].L4.Flags)
	}
}

// ===================================================================
// RESP2 Pub/Sub message push: subscriber receives a server-initiated
// "message" multi-bulk frame after another client PUBLISHes. In RESP2
// the push is a normal *3 array (not the RESP3 ">" push type).
// ===================================================================

func TestRedis_PubSub_RESP2_MessagePush(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribeTo = []string{"news"}
	// After SUBSCRIBE confirmation, the server pushes a "message" frame.
	// We model the push as a user command whose reply is the message frame
	// (the planner emits it as a down PSH-ACK). In RESP2 a message push is
	// *3\r\n$7\r\nmessage\r\n$<chlen>\r\n<channel>\r\n$<msglen>\r\n<msg>\r\n
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
		{Args: []string{"PING"}, Reply: "*3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	downs := allDownPayloads(cfgs)
	// downs[0] = subscribe confirmation, downs[1] = +PONG, downs[2] = message push
	if len(downs) < 3 {
		t.Fatalf("downs=%d, want >= 3", len(downs))
	}
	// Verify subscribe confirmation.
	wantConfirm := "*3\r\n$9\r\nsubscribe\r\n$4\r\nnews\r\n:1\r\n"
	if string(downs[0]) != wantConfirm {
		t.Errorf("subscribe confirm=%q, want %q", downs[0], wantConfirm)
	}
	// Verify the message push frame (RESP2 multi-bulk, NOT RESP3 ">").
	msgPush := string(downs[2])
	wantMsg := "*3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n"
	if msgPush != wantMsg {
		t.Errorf("message push=%q, want %q", msgPush, wantMsg)
	}
	// Confirm it is a RESP2 array (starts with '*'), not a RESP3 push ('>').
	if msgPush[0] != '*' {
		t.Errorf("RESP2 message push should start with '*', got %q", msgPush[0])
	}
}

// PSUBSCRIBE pattern then pmessage push (RESP2): subscriber gets
// ["pmessage", pattern, channel, payload].
func TestRedis_PubSub_RESP2_PSubscribePMessage(t *testing.T) {
	spec := validRedisSpec()
	spec.Redis.SubscribePatterns = []string{"news.*"}
	spec.Redis.Commands = []core.RedisCommand{
		{Args: []string{"PING"}, Reply: "*4\r\n$8\r\npmessage\r\n$6\r\nnews.*\r\n$5\r\nnews1\r\n$5\r\nhello\r\n"},
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	ups := allUpPayloads(cfgs)
	// First up = PSUBSCRIBE news.*
	if !strings.HasPrefix(string(ups[0]), "*2\r\n$10\r\nPSUBSCRIBE") {
		t.Errorf("ups[0]=%q, want PSUBSCRIBE", ups[0])
	}
	downs := allDownPayloads(cfgs)
	// downs[0] = psubscribe confirmation, downs[1] = pmessage push
	if len(downs) < 2 {
		t.Fatalf("downs=%d, want >= 2", len(downs))
	}
	wantPConfirm := "*3\r\n$10\r\npsubscribe\r\n$6\r\nnews.*\r\n:1\r\n"
	if string(downs[0]) != wantPConfirm {
		t.Errorf("psubscribe confirm=%q, want %q", downs[0], wantPConfirm)
	}
	wantPMsg := "*4\r\n$8\r\npmessage\r\n$6\r\nnews.*\r\n$5\r\nnews1\r\n$5\r\nhello\r\n"
	if string(downs[1]) != wantPMsg {
		t.Errorf("pmessage push=%q, want %q", downs[1], wantPMsg)
	}
}

// ===================================================================
// Error paths: unknown command, WRONGTYPE (operation against wrong type).
// ===================================================================

// Unknown command -> -ERR unknown command 'foobar'
func TestRedis_Err_UnknownCommand(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"FOOBAR"}, Reply: "-ERR unknown command 'foobar', with args beginning with:\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "-ERR") {
		t.Errorf("reply=%q, want -ERR prefix", reply)
	}
	if !strings.Contains(string(reply), "unknown command") {
		t.Errorf("reply=%q, want 'unknown command'", reply)
	}
}

// WRONGTYPE: LPUSH on a string key -> -WRONGTYPE Operation against a key
// holding the wrong kind of value
func TestRedis_Err_WrongType(t *testing.T) {
	spec := redisSpecWithCmds(core.RedisCommand{
		Args: []string{"LPUSH", "str", "x"},
		Reply: "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n",
	})
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	cmd := firstUpPayload(t, cfgs)
	want := "*3\r\n$5\r\nLPUSH\r\n$3\r\nstr\r\n$1\r\nx\r\n"
	if string(cmd) != want {
		t.Errorf("LPUSH cmd=%q, want %q", cmd, want)
	}
	reply := firstDownPayload(t, cfgs)
	if !strings.HasPrefix(string(reply), "-WRONGTYPE") {
		t.Errorf("reply=%q, want -WRONGTYPE prefix", reply)
	}
}

// Large value: 10MB bulk reply triggers MSS segmentation (server->client).
func TestRedis_LargeValue_10MB_BulkReply(t *testing.T) {
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
	// First segment contains the RESP bulk header "$10485760\r\n".
	if !strings.HasPrefix(string(downs[0].Payload), "$10485760\r\n") {
		t.Errorf("first down segment=%q, want bulk header", downs[0].Payload[:20])
	}
}
