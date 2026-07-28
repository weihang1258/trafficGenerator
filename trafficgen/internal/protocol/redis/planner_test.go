package redis

import (
    "context"
    "strings"
    "testing"

    "github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all PacketConfig values from ch and returns them as a slice.
// Used by tests that need to assert on the full Plan() output.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
    var out []core.PacketConfig
    for cfg := range ch {
        out = append(out, cfg)
    }
    return out
}

// mustPlan calls Plan and fails the test on error. Returns the channel for
// the caller to drain. Used by atomic testpoints and integration tests.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
    t.Helper()
    ch, err := p.Plan(context.Background(), spec)
    if err != nil {
        t.Fatalf("Plan returned error: %v", err)
    }
    return ch
}

func TestPlanPINGAutoReplyPong(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{SelectDB: -1, Commands: []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}}},
    }
    ch, err := p.Plan(context.Background(), spec)
    if err != nil { t.Fatal(err) }
    packets := drain(ch)
    if len(packets) != 9 { t.Fatalf("packet count = %d, want 9", len(packets)) }
    if got := string(packets[3].Payload); got != "*1\r\n$4\r\nPING\r\n" { t.Fatalf("command = %q", got) }
    if got := string(packets[4].Payload); got != "+PONG\r\n" { t.Fatalf("reply = %q", got) }
}

// ===================================================================
// Integration tests: full Plan() output capture and end-to-end asserts.
// ===================================================================

// Integration 1: RESP3 HELLO 3 + PING + teardown verifies the full packet
// sequence for a RESP3 session. handshake(3) + HELLO(1) + HELLO-reply(1) +
// PING(1) + PONG(1) + teardown(4) = 11 packets.
func TestRedis_Integration_RESP3HelloPingTeardown(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{
            Version:  3,
            SelectDB: -1,
            Commands: []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}},
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    if len(cfgs) != 11 {
        t.Fatalf("packet count = %d, want 11 (3 hs + 2 HELLO + 2 PING + 4 teardown)", len(cfgs))
    }
    // Packet 0: SYN up, 1: SYN-ACK down, 2: ACK up
    if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != flagSYN {
        t.Errorf("cfgs[0]: dir=%s flags=%02x, want up/SYN", cfgs[0].Direction, cfgs[0].L4.Flags)
    }
    if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != flagSYNACK {
        t.Errorf("cfgs[1]: dir=%s flags=%02x, want down/SYN-ACK", cfgs[1].Direction, cfgs[1].L4.Flags)
    }
    if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != flagACK {
        t.Errorf("cfgs[2]: dir=%s flags=%02x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
    }
    // Packet 3: HELLO 3 command up
    if cfgs[3].Direction != "up" {
        t.Errorf("cfgs[3].Direction=%s, want up", cfgs[3].Direction)
    }
    if got := string(cfgs[3].Payload); got != "*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n" {
        t.Errorf("HELLO cmd = %q", got)
    }
    // Packet 4: HELLO reply down (%0\r\n = empty map)
    if cfgs[4].Direction != "down" {
        t.Errorf("cfgs[4].Direction=%s, want down", cfgs[4].Direction)
    }
    if got := string(cfgs[4].Payload); got != "%0\r\n" {
        t.Errorf("HELLO reply = %q", got)
    }
    // Packet 5: PING up
    if got := string(cfgs[5].Payload); got != "*1\r\n$4\r\nPING\r\n" {
        t.Errorf("PING cmd = %q", got)
    }
    // Packet 6: +PONG down
    if got := string(cfgs[6].Payload); got != "+PONG\r\n" {
        t.Errorf("PONG reply = %q", got)
    }
    // Packets 7-10: teardown (FIN-ACK up, ACK down, FIN-ACK down, ACK up)
    teardown := cfgs[7:11]
    if teardown[0].Direction != "up" || teardown[0].L4.Flags != flagFINACK {
        t.Errorf("teardown[0]: dir=%s flags=%02x", teardown[0].Direction, teardown[0].L4.Flags)
    }
    if teardown[1].Direction != "down" || teardown[1].L4.Flags != flagACK {
        t.Errorf("teardown[1]: dir=%s flags=%02x", teardown[1].Direction, teardown[1].L4.Flags)
    }
    if teardown[2].Direction != "down" || teardown[2].L4.Flags != flagFINACK {
        t.Errorf("teardown[2]: dir=%s flags=%02x", teardown[2].Direction, teardown[2].L4.Flags)
    }
    if teardown[3].Direction != "up" || teardown[3].L4.Flags != flagACK {
        t.Errorf("teardown[3]: dir=%s flags=%02x", teardown[3].Direction, teardown[3].L4.Flags)
    }
    // Verify sequence numbers advance correctly.
    // After SYN (ISN) clientSeq = ISN+1; after HELLO (22 bytes) clientSeq = ISN+1+22;
    // after PING (14 bytes) clientSeq = ISN+1+22+14.
    // Server seq: after SYN-ACK (ISN_s) serverSeq = ISN_s+1; after HELLO reply (4 bytes)
    // serverSeq = ISN_s+1+4; after PONG (7 bytes) serverSeq = ISN_s+1+4+7.
    // ACK numbers track the OTHER side's seq.
    // cfgs[2] (ACK up) should ack serverSeq = ISN_s+1 (after SYN-ACK).
    // cfgs[3] (HELLO up) has Ack = ISN_s+1.
    if cfgs[3].L4.Ack != cfgs[1].L4.Seq+1 {
        t.Errorf("HELLO Ack=%d, want SYN-ACK Seq+1=%d", cfgs[3].L4.Ack, cfgs[1].L4.Seq+1)
    }
    // cfgs[6] (PONG down) should ack all client bytes received so far:
    // ISN_c + 1 (SYN) + 22 (HELLO) + 14 (PING) = ISN_c + 37.
    if cfgs[6].L4.Ack != cfgs[0].L4.Seq+37 {
        t.Errorf("PONG Ack=%d, want client ISN+37=%d", cfgs[6].L4.Ack, cfgs[0].L4.Seq+37)
    }
}

// Integration 2: AUTH + SELECT + CLIENT SETNAME + PING verifies bootstrap
// chain ordering. handshake(3) + AUTH(2) + SELECT(2) + CLIENT SETNAME(2) +
// PING(2) + teardown(4) = 15 packets.
func TestRedis_Integration_AuthSelectSetnameChain(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{
            Version:    2,
            Username:   "myuser",
            Password:   "mypass",
            SelectDB:   1,
            ClientName: "myclient",
            Commands:   []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}},
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    if len(cfgs) != 15 {
        t.Fatalf("packet count = %d, want 15", len(cfgs))
    }
    // Extract the up-direction payloads (commands) in order.
    var ups []string
    for _, c := range cfgs {
        if c.Direction == "up" && len(c.Payload) > 0 {
            ups = append(ups, string(c.Payload))
        }
    }
    if len(ups) != 4 {
        t.Fatalf("up commands = %d, want 4 (AUTH, SELECT, CLIENT SETNAME, PING)", len(ups))
    }
    wantCmds := []string{
        "*3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n",
        "*2\r\n$6\r\nSELECT\r\n$1\r\n1\r\n",
        "*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$8\r\nmyclient\r\n",
        "*1\r\n$4\r\nPING\r\n",
    }
    for i, want := range wantCmds {
        if ups[i] != want {
            t.Errorf("ups[%d] = %q, want %q", i, ups[i], want)
        }
    }
    // Extract down-direction payloads (replies) in order.
    var downs []string
    for _, c := range cfgs {
        if c.Direction == "down" && len(c.Payload) > 0 {
            downs = append(downs, string(c.Payload))
        }
    }
    if len(downs) != 4 {
        t.Fatalf("down replies = %d, want 4", len(downs))
    }
    wantReplies := []string{"+OK\r\n", "+OK\r\n", "+OK\r\n", "+PONG\r\n"}
    for i, want := range wantReplies {
        if downs[i] != want {
            t.Errorf("downs[%d] = %q, want %q", i, downs[i], want)
        }
    }
}

// Integration 3: SUBSCRIBE + PUBLISH + PING flow verifies pub/sub bootstrap
// and confirmation count.
func TestRedis_Integration_SubscribePublishPing(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{
            SelectDB: -1,
            SubscribeTo: []string{"news", "sports"},
            Commands: []core.RedisCommand{
                {Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
            },
            PublishMessages: []core.RedisPublish{
                {Channel: "news", Message: "hello"},
            },
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    // handshake(3) + SUBSCRIBE(1) + 2 confirmations(2) + PING(1) + PONG(1) +
    // PUBLISH(1) + :1(1) + teardown(4) = 14 packets.
    if len(cfgs) != 14 {
        t.Fatalf("packet count = %d, want 14", len(cfgs))
    }
    // Verify SUBSCRIBE command frame.
    subCmd := cfgs[3]
    if subCmd.Direction != "up" {
        t.Errorf("SUBSCRIBE direction=%s, want up", subCmd.Direction)
    }
    wantSub := "*3\r\n$9\r\nSUBSCRIBE\r\n$4\r\nnews\r\n$6\r\nsports\r\n"
    if string(subCmd.Payload) != wantSub {
        t.Errorf("SUBSCRIBE cmd = %q, want %q", subCmd.Payload, wantSub)
    }
    // Verify 2 subscribe confirmations.
    conf1 := cfgs[4]
    conf2 := cfgs[5]
    if conf1.Direction != "down" {
        t.Errorf("conf1 direction=%s, want down", conf1.Direction)
    }
    wantConf1 := "*3\r\n$9\r\nsubscribe\r\n$4\r\nnews\r\n:1\r\n"
    if string(conf1.Payload) != wantConf1 {
        t.Errorf("conf1 = %q, want %q", conf1.Payload, wantConf1)
    }
    wantConf2 := "*3\r\n$9\r\nsubscribe\r\n$6\r\nsports\r\n:2\r\n"
    if string(conf2.Payload) != wantConf2 {
        t.Errorf("conf2 = %q, want %q", conf2.Payload, wantConf2)
    }
    // Verify PING and PONG.
    if string(cfgs[6].Payload) != "*1\r\n$4\r\nPING\r\n" {
        t.Errorf("PING = %q", cfgs[6].Payload)
    }
    if string(cfgs[7].Payload) != "+PONG\r\n" {
        t.Errorf("PONG = %q", cfgs[7].Payload)
    }
    // Verify PUBLISH.
    pubCmd := cfgs[8]
    if pubCmd.Direction != "up" {
        t.Errorf("PUBLISH direction=%s, want up", pubCmd.Direction)
    }
    wantPub := "*3\r\n$7\r\nPUBLISH\r\n$4\r\nnews\r\n$5\r\nhello\r\n"
    if string(pubCmd.Payload) != wantPub {
        t.Errorf("PUBLISH = %q, want %q", pubCmd.Payload, wantPub)
    }
    if string(cfgs[9].Payload) != ":1\r\n" {
        t.Errorf("PUBLISH reply = %q, want :1\\r\\n", cfgs[9].Payload)
    }
}

// Integration 4: Pipeline 4 commands verifies batched emit (4 ups then 4 downs).
func TestRedis_Integration_PipelineBatch(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{
            SelectDB:    -1,
            PipelineSize: 4,
            Commands: []core.RedisCommand{
                {Args: []string{"SET", "a", "1"}, AutoReply: core.RedisAutoReplyOK},
                {Args: []string{"SET", "b", "2"}, AutoReply: core.RedisAutoReplyOK},
                {Args: []string{"GET", "a"}, Reply: "$1\r\n1\r\n"},
                {Args: []string{"INCR", "c"}, AutoReply: "integer-1"},
            },
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    // handshake(3) + 4 commands(4) + 4 replies(4) + teardown(4) = 15 packets.
    if len(cfgs) != 15 {
        t.Fatalf("packet count = %d, want 15", len(cfgs))
    }
    // Pattern after handshake: 4 ups (commands) then 4 downs (replies).
    // cfgs[3..6] are ups, cfgs[7..10] are downs.
    for i := 3; i <= 6; i++ {
        if cfgs[i].Direction != "up" {
            t.Errorf("cfgs[%d].Direction=%s, want up (pipelined command)", i, cfgs[i].Direction)
        }
    }
    for i := 7; i <= 10; i++ {
        if cfgs[i].Direction != "down" {
            t.Errorf("cfgs[%d].Direction=%s, want down (pipelined reply)", i, cfgs[i].Direction)
        }
    }
    // Verify commands in order.
    wantCmds := []string{
        "*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\n1\r\n",
        "*3\r\n$3\r\nSET\r\n$1\r\nb\r\n$1\r\n2\r\n",
        "*2\r\n$3\r\nGET\r\n$1\r\na\r\n",
        "*2\r\n$4\r\nINCR\r\n$1\r\nc\r\n",
    }
    for i, want := range wantCmds {
        if got := string(cfgs[3+i].Payload); got != want {
            t.Errorf("cmd[%d] = %q, want %q", i, got, want)
        }
    }
    // Verify replies in order.
    wantReplies := []string{"+OK\r\n", "+OK\r\n", "$1\r\n1\r\n", ":1\r\n"}
    for i, want := range wantReplies {
        if got := string(cfgs[7+i].Payload); got != want {
            t.Errorf("reply[%d] = %q, want %q", i, got, want)
        }
    }
    // Verify all packet indices are strictly ascending.
    for i := 1; i < len(cfgs); i++ {
        if cfgs[i].PacketIndex <= cfgs[i-1].PacketIndex {
            t.Errorf("PacketIndex[%d]=%d not > prev=%d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex)
        }
    }
    // Verify all packets share the same FlowID.
    for i, c := range cfgs {
        if c.FlowID != cfgs[0].FlowID {
            t.Errorf("cfgs[%d].FlowID=%q, want %q", i, c.FlowID, cfgs[0].FlowID)
        }
    }
}

// Integration 5: MULTI/EXEC transaction with +QUEUED replies verifies the
// transactional dialog end-to-end.
func TestRedis_Integration_MultiExecTransaction(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{
            SelectDB: -1,
            Commands: []core.RedisCommand{
                {Args: []string{"MULTI"}, AutoReply: core.RedisAutoReplyOK},
                {Args: []string{"SET", "k1", "v1"}, AutoReply: core.RedisAutoReplyQueued},
                {Args: []string{"SET", "k2", "v2"}, AutoReply: core.RedisAutoReplyQueued},
                {Args: []string{"GET", "k1"}, AutoReply: core.RedisAutoReplyQueued},
                {Args: []string{"EXEC"}, Reply: "*3\r\n+OK\r\n+OK\r\n$2\r\nv1\r\n"},
            },
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    // handshake(3) + 5 commands(5) + 5 replies(5) + teardown(4) = 17 packets.
    if len(cfgs) != 17 {
        t.Fatalf("packet count = %d, want 17", len(cfgs))
    }
    // Walk commands and replies in order.
    var ups, downs []string
    for _, c := range cfgs {
        if len(c.Payload) == 0 {
            continue
        }
        if c.Direction == "up" {
            ups = append(ups, string(c.Payload))
        } else {
            downs = append(downs, string(c.Payload))
        }
    }
    if len(ups) != 5 || len(downs) != 5 {
        t.Fatalf("ups=%d downs=%d, want 5 each", len(ups), len(downs))
    }
    // Replies: +OK (MULTI), +QUEUED, +QUEUED, +QUEUED, *3\r\n+OK\r\n+OK\r\n$2\r\nv1\r\n
    wantReplies := []string{
        "+OK\r\n",
        "+QUEUED\r\n",
        "+QUEUED\r\n",
        "+QUEUED\r\n",
        "*3\r\n+OK\r\n+OK\r\n$2\r\nv1\r\n",
    }
    for i, want := range wantReplies {
        if downs[i] != want {
            t.Errorf("downs[%d] = %q, want %q", i, downs[i], want)
        }
    }
    // Verify EXEC command frame.
    execCmd := ups[4]
    if !strings.HasPrefix(execCmd, "*1\r\n$4\r\nEXEC\r\n") {
        t.Errorf("EXEC cmd = %q", execCmd)
    }
    // Verify the EXEC reply is a 3-element array (one per queued command).
    if !strings.HasPrefix(downs[4], "*3\r\n") {
        t.Errorf("EXEC reply should be *3 array, got %q", downs[4])
    }
}

// Integration 6: Binary-safe ArgsBase64 command + reply verifies that base64
// args are decoded and framed as binary-safe bulk strings.
func TestRedis_Integration_BinarySafeArgsBase64(t *testing.T) {
    p := NewPlanner()
    // ArgsBase64 "AAAD" decodes to bytes 0x00 0x00 0x03. SET and k are plain
    // strings (Args); only the binary value uses ArgsBase64.
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{
            SelectDB: -1,
            Commands: []core.RedisCommand{
                {Args: []string{"SET", "k"}, ArgsBase64: []string{"AAAD"}, AutoReply: core.RedisAutoReplyOK},
            },
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    // handshake(3) + cmd(1) + reply(1) + teardown(4) = 9 packets.
    if len(cfgs) != 9 {
        t.Fatalf("packet count = %d, want 9", len(cfgs))
    }
    cmd := cfgs[3].Payload
    want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\n\x00\x00\x03\r\n"
    if string(cmd) != want {
        t.Errorf("cmd = %q, want %q", cmd, want)
    }
    if len(cmd) != 29 {
        t.Errorf("cmd len = %d, want 29", len(cmd))
    }
    // Verify reply.
    if string(cfgs[4].Payload) != "+OK\r\n" {
        t.Errorf("reply = %q, want +OK\\r\\n", cfgs[4].Payload)
    }
}

// Integration 7: Default commands (no Commands, no Subscribe, no Publish)
// emits a single PING and verifies the planner doesn't produce an empty flow.
func TestRedis_Integration_DefaultCommands(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP:   &core.TCPConfig{Handshake: true, Termination: true},
        Redis: &core.RedisConfig{SelectDB: -1},
    }
    cfgs := drain(mustPlan(t, p, spec))
    // handshake(3) + default PING(1) + PONG(1) + teardown(4) = 9 packets.
    if len(cfgs) != 9 {
        t.Fatalf("packet count = %d, want 9 (default PING)", len(cfgs))
    }
    if string(cfgs[3].Payload) != "*1\r\n$4\r\nPING\r\n" {
        t.Errorf("default cmd = %q, want PING", cfgs[3].Payload)
    }
    if string(cfgs[4].Payload) != "+PONG\r\n" {
        t.Errorf("default reply = %q, want +PONG", cfgs[4].Payload)
    }
}

// Integration 8: RST termination replaces 4-way teardown with a single RST.
func TestRedis_Integration_RSTTermination(t *testing.T) {
    p := NewPlanner()
    spec := core.FlowSpec{
        SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
        SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 6379,
        TCP: &core.TCPConfig{Handshake: true, Termination: true, RST: true},
        Redis: &core.RedisConfig{
            SelectDB: -1,
            Commands: []core.RedisCommand{{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong}},
        },
    }
    cfgs := drain(mustPlan(t, p, spec))
    // handshake(3) + cmd(1) + reply(1) + RST(1) = 6 packets.
    if len(cfgs) != 6 {
        t.Fatalf("packet count = %d, want 6", len(cfgs))
    }
    rst := cfgs[5]
    if rst.Direction != "up" {
        t.Errorf("RST direction = %s, want up", rst.Direction)
    }
    if rst.L4.Flags != flagRSTACK {
        t.Errorf("RST flags = %02x, want %02x", rst.L4.Flags, flagRSTACK)
    }
    if len(rst.Payload) != 0 {
        t.Errorf("RST payload should be empty, got %d bytes", len(rst.Payload))
    }
}
