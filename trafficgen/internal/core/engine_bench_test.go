package core

import (
	"context"
	"testing"
)

// benchConfig builds a PacketConfig for a given protocol and payload size.
func benchConfig(protocol string, payloadSize int) PacketConfig {
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, DSCP: 46},
		L4: L4Config{Protocol: protocol, SrcPort: 12345, DstPort: 80, Seq: 1000, Flags: 0x10},
	}
	cfg.Payload = make([]byte, payloadSize)
	if protocol == "udp" {
		cfg.L3.Protocol = 17
	}
	return cfg
}

func BenchmarkBuilder_TCP_64(b *testing.B) {
	benchBuild(b, "tcp", 64-54) // 64 total - 14 eth - 20 ip - 20 tcp
}
func BenchmarkBuilder_TCP_512(b *testing.B) {
	benchBuild(b, "tcp", 512-54)
}
func BenchmarkBuilder_TCP_1500(b *testing.B) {
	benchBuild(b, "tcp", 1500-54)
}
func BenchmarkBuilder_UDP_512(b *testing.B) {
	benchBuild(b, "udp", 512-42) // 14 eth + 20 ip + 8 udp
}
func BenchmarkBuilder_UDP_1500(b *testing.B) {
	benchBuild(b, "udp", 1500-42)
}

func benchBuild(b *testing.B, protocol string, payloadSize int) {
	builder := NewBuilder()
	cfg := benchConfig(protocol, payloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := builder.Build(cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTupleGenerator_Next measures 4-tuple generation for an inc-IP config.
func BenchmarkTupleGenerator_Next(b *testing.B) {
	tc := TupleConfig{
		SrcIP:   StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.254"}, Step: 1},
		DstIP:   StrategyConfig{Strategy: "fixed", Value: "192.168.1.1"},
		SrcPort: StrategyConfig{Strategy: "rand", Range: []interface{}{float64(1024), float64(65535)}, Seed: 42},
		DstPort: StrategyConfig{Strategy: "list", List: []string{"80", "443"}},
	}
	g := NewTupleGenerator(tc)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Next(i)
	}
}

// benchPlanner is a planner that yields count configs with a fixed payload,
// for pipeline throughput benchmarks.
type benchPlanner struct{}

func (benchPlanner) Name() string                 { return "tcp" }
func (benchPlanner) Validate(spec FlowSpec) error { return nil }
func (benchPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, 256)
	go func() {
		defer close(ch)
		for i := 0; i < spec.Count; i++ {
			ch <- PacketConfig{
				FlowID: "f", PacketIndex: uint64(i),
				L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
				L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
				L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: uint32(i), Flags: 0x10},
				Payload: make([]byte, 500),
			}
		}
	}()
	return ch, nil
}

// BenchmarkEngine_Pipeline measures end-to-end packets/sec through the engine
// (config -> build -> buffer) for a 5000-packet task. Reports ns/packet.
func BenchmarkEngine_Pipeline(b *testing.B) {
	const packetsPerTask = 5000
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: packetsPerTask + 100, QueueSize: 1024,
	})
	e.RegisterPlanner(benchPlanner{})
	e.SetBuildFunc(NewBuilder().Build)
	if err := e.Start(); err != nil {
		b.Fatal(err)
	}
	defer e.Stop()

	done := make(chan string, 1)
	e.OnTaskComplete = func(id string) { done <- id }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		task := Task{
			ID: "bench", Name: "bench", Protocol: "tcp", ClassID: "bench",
			Spec: FlowSpec{Count: packetsPerTask},
		}
		if err := e.SubmitTask(task); err != nil {
			b.Fatal(err)
		}
		<-done
		// Drain the buffer so the next iteration doesn't overflow.
		e.buffer.Get(packetsPerTask, "combined")
	}
	b.ReportMetric(float64(packetsPerTask), "packets/op")
}
