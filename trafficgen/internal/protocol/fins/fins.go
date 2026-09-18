package fins

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func NewPlanner() *Planner      { return &Planner{} }
func (p *Planner) Name() string { return "fins" }

var memoryAreas = map[string]uint8{"cio": 0xB0, "wr": 0xB1, "hr": 0xB2, "tc_pv": 0x89, "tc_bit": 0x09, "dm": 0x82, "ir": 0xDC}

func memoryAreaCode(name string, bit uint8, bitAccess bool) (uint8, bool) {
	if bitAccess {
		switch name {
		case "cio":
			return 0x30, true
		case "wr":
			return 0x31, true
		case "hr":
			return 0x32, true
		case "tc_bit":
			return 0x09, true
		default:
			return 0, false
		}
	}
	return memoryAreas[name], memoryAreas[name] != 0
}

func (p *Planner) Validate(spec core.FlowSpec) error {
	cfg := GetConfig(spec)
	if cfg == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （udp + dm read）。允许 nil。
		return nil
	}
	if cfg.Transport != "" && cfg.Transport != "udp" && cfg.Transport != "tcp" {
		return fmt.Errorf("fins: invalid transport %q", cfg.Transport)
	}
	if cfg.Sessions < 0 {
		return fmt.Errorf("fins: sessions must be >= 0")
	}
	if cfg.ICF != 0 && !validICF(cfg.ICF) {
		return fmt.Errorf("fins: invalid icf 0x%02X", cfg.ICF)
	}
	// D-FINS-1 E-06 cfg 级：cfg.ICF 是请求 ICF——bit6（响应位）必须清零、
	// bit0（不期望响应）必须清零；bit7/保留位由 validICF 查。命令级同款
	// 三规则见 commands 循环内。
	if cfg.ICF != 0 {
		if cfg.ICF&0x40 != 0 {
			return fmt.Errorf("fins: icf request direction bit must be clear")
		}
		if cfg.ICF&1 != 0 {
			return fmt.Errorf("fins: icf response-required bit must be clear")
		}
	}
	if cfg.GCT != 0 && cfg.GCT != 2 {
		return fmt.Errorf("fins: invalid gct %d", cfg.GCT)
	}
	if cfg.DNA != 0 {
		return fmt.Errorf("fins: invalid dna %d", cfg.DNA)
	}
	if cfg.SNA != 0 {
		return fmt.Errorf("fins: invalid sna %d", cfg.SNA)
	}
	for i, cmd := range cfg.Commands {
		if cmd.Command != CommandMemoryAreaRead && cmd.Command != CommandMemoryAreaWrite &&
			cmd.Command != CommandClockRead && cmd.Command != CommandMemoryAreaFill &&
			cmd.Command != CommandMultipleMemoryAreaRead {
			return fmt.Errorf("fins: commands[%d] unsupported command 0x%04X", i, cmd.Command)
		}
		// D-FINS-1 C1：read_areas 仅 0104 合法（语义校验在 ClockRead 之后
		// 的 0104 分支——保证 direction/ICF 校验先于 continue 执行）。
		if cmd.Command != CommandMultipleMemoryAreaRead && len(cmd.ReadAreas) > 0 {
			return fmt.Errorf("fins: commands[%d] read_areas is only valid for command 0x0104", i)
		}
		if cmd.Direction != "" && cmd.Direction != "up" && cmd.Direction != "down" {
			return fmt.Errorf("fins: commands[%d] invalid direction", i)
		}
		if cmd.ICF != 0 {
			if !validICF(cmd.ICF) {
				return fmt.Errorf("fins: commands[%d] invalid icf 0x%02X", i, cmd.ICF)
			}
			if cmd.Direction == "down" && cmd.ICF&0x40 == 0 {
				return fmt.Errorf("fins: commands[%d] icf response direction bit must be set", i)
			}
			if cmd.Direction != "down" && cmd.ICF&0x40 != 0 {
				return fmt.Errorf("fins: commands[%d] icf request direction bit must be clear", i)
			}
			if cmd.ICF&1 != 0 {
				return fmt.Errorf("fins: commands[%d] icf response-required bit must be clear", i)
			}
		}
		if cmd.Command == CommandClockRead {
			if err := validateClock(cmd.Clock); err != nil {
				return fmt.Errorf("fins: commands[%d] clock: %w", i, err)
			}
			continue
		}
		// D-FINS-1 C1/E-10：0104 组校验（1-16 组；组内逐组走
		// E-01/E-03/E-04/E-05 同款规则）。置于 direction/ICF 校验之后：
		// 命令级 ICF 规则对 0104 同样适用（顺序锁 TestMultipleReadCommandLevelICFStillChecked）。
		if cmd.Command == CommandMultipleMemoryAreaRead {
			if len(cmd.ReadAreas) == 0 || len(cmd.ReadAreas) > 16 {
				return fmt.Errorf("fins: commands[%d] read_areas must contain 1-16 areas", i)
			}
			for j, ra := range cmd.ReadAreas {
				raBit := ra.BitSet || ra.Bit != 0
				if _, ok := memoryAreaCode(ra.MemoryArea, ra.Bit, raBit); !ok {
					return fmt.Errorf("fins: commands[%d].read_areas[%d] invalid memory area %q", i, j, ra.MemoryArea)
				}
				if ra.MemoryArea == "dm" && raBit {
					return fmt.Errorf("fins: commands[%d].read_areas[%d] dm does not support bit access", i, j)
				}
				if ra.Address > areaAddressLimit(ra.MemoryArea) {
					return fmt.Errorf("fins: commands[%d].read_areas[%d] address exceeds range", i, j)
				}
				if ra.Items == 0 {
					return fmt.Errorf("fins: commands[%d].read_areas[%d] items must be > 0", i, j)
				}
				maxItems := uint16(960)
				if raBit {
					maxItems = 4096
				}
				if ra.Items > maxItems {
					return fmt.Errorf("fins: commands[%d].read_areas[%d] items exceeds range", i, j)
				}
			}
			continue
		}
		if cmd.Items == 0 {
			return fmt.Errorf("fins: commands[%d] items must be > 0", i)
		}
		if cmd.Bit > 15 {
			return fmt.Errorf("fins: commands[%d] bit must be 0-15", i)
		}
		bitAccess := cmd.BitSet || cmd.Bit != 0
		if _, ok := memoryAreaCode(cmd.MemoryArea, cmd.Bit, bitAccess); !ok {
			return fmt.Errorf("fins: commands[%d] invalid memory area %q", i, cmd.MemoryArea)
		}
		if cmd.MemoryArea == "dm" && bitAccess {
			return fmt.Errorf("fins: commands[%d] dm does not support bit access", i)
		}
		if cmd.Address > areaAddressLimit(cmd.MemoryArea) {
			return fmt.Errorf("fins: commands[%d] address exceeds range", i)
		}
		maxItems := uint16(960)
		if bitAccess {
			maxItems = 4096
		}
		if cmd.Items > maxItems {
			kind := "word"
			if bitAccess {
				kind = "bit"
			}
			return fmt.Errorf("fins: commands[%d] %s items exceeds range", i, kind)
		}
		want := int(cmd.Items) * 2
		if bitAccess {
			want = int(cmd.Items)
		}
		if cmd.Command == CommandMemoryAreaWrite && len(cmd.Data) != want {
			return fmt.Errorf("fins: commands[%d] data length %d, want %d", i, len(cmd.Data), want)
		}
		if cmd.Command == CommandMemoryAreaRead && len(cmd.Data) > 0 && len(cmd.Data) != want {
			return fmt.Errorf("fins: commands[%d] data length %d, want %d", i, len(cmd.Data), want)
		}
		// D-FINS-1 C1：0103 Fill 仅字口径（设计 §3.8：位口径非 W342 字义），
		// 填充模板恒 2 字节（剩余长度恒 8）。
		if cmd.Command == CommandMemoryAreaFill {
			if bitAccess {
				return fmt.Errorf("fins: commands[%d] fill does not support bit access", i)
			}
			if len(cmd.Data) != 2 {
				return fmt.Errorf("fins: commands[%d] fill data must be 2 bytes", i)
			}
		}
	}
	return nil
}

func areaAddressLimit(name string) uint16 {
	switch name {
	case "cio", "wr", "hr":
		return 6143
	default:
		return 32767
	}
}

func validateClock(c *FINSClock) error {
	if c == nil {
		return nil
	}
	if c.Century > 99 || c.Year > 99 || c.Month < 1 || c.Month > 12 || c.Day < 1 || c.Day > 31 || c.Hour > 23 || c.Minute > 59 || c.Second > 59 || c.Weekday > 6 {
		return fmt.Errorf("clock field out of range")
	}
	return nil
}

func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := GetConfig(spec)
	if cfg == nil {
		// P0b-2：空配置默认化（Generate 同款：udp + dm read）。
		cfg = &FINSConfig{Transport: "udp", Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}, SIDAuto: true, SIDAutoSet: true}
	}
	if !cfg.SIDAutoSet {
		cfg = cloneConfig(cfg)
		cfg.SIDAuto = true
	}
	if cfg.Transport == "" {
		cfg = cloneConfig(cfg)
		cfg.Transport = "udp"
	}
	if len(cfg.Commands) == 0 {
		cfg = cloneConfig(cfg)
		cfg.Commands = []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 100, Items: 2}}
	}
	sessions := cfg.Sessions
	if sessions == 0 {
		sessions = 1
	}
	out := make(chan core.PacketConfig, 256)
	go func() {
		defer close(out)
		for session := 0; session < sessions; session++ {
			if !p.planSession(ctx, spec, cfg, session, out) {
				return
			}
		}
	}()
	return out, nil
}
func cloneConfig(c *FINSConfig) *FINSConfig {
	v := *c
	v.Commands = append([]FINSCommand(nil), c.Commands...)
	return &v
}

func (p *Planner) planSession(ctx context.Context, spec core.FlowSpec, cfg *FINSConfig, session int, out chan<- core.PacketConfig) bool {
	transport := cfg.Transport
	srcPort := spec.SrcPort + uint16(session)
	if srcPort == 0 {
		srcPort = 40000 + uint16(session)
	}
	dstPort := spec.DstPort
	if dstPort == 0 {
		dstPort = DefaultPort
	}
	flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, srcPort, dstPort)
	clientSeq, serverSeq := uint32(1), uint32(100)
	idx := uint64(0)
	emit := func(up bool, payload []byte, flags uint8) bool {
		sip, dip, smac, dmac := spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC
		sp, dp := srcPort, dstPort
		seq, ack := clientSeq, serverSeq
		if !up {
			sip, dip, smac, dmac, sp, dp = dip, sip, dmac, smac, dp, sp
			seq, ack = serverSeq, clientSeq
		}
		proto := uint8(17)
		l4proto := "udp"
		if transport == "tcp" {
			proto = 6
			l4proto = "tcp"
		}
		pc := core.PacketConfig{FlowID: flowID, PacketIndex: idx, Direction: map[bool]string{true: "up", false: "down"}[up], Timestamp: time.Now(), L2: core.L2Config{SrcMAC: smac, DstMAC: dmac, EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, proto, effectiveTTL(spec), uint16(idx), spec), L4: core.L4Config{Protocol: l4proto, SrcPort: sp, DstPort: dp, Seq: seq, Ack: ack, Flags: flags, WindowSize: 65535}, Payload: payload}
		select {
		case out <- pc:
			idx++
			if transport == "tcp" {
				if up {
					clientSeq += uint32(len(payload))
					if flags&(2|1) != 0 {
						clientSeq++
					}
				} else {
					serverSeq += uint32(len(payload))
					if flags&(2|1) != 0 {
						serverSeq++
					}
				}
			}
			return true
		case <-ctx.Done():
			return false
		}
	}
	if transport == "tcp" {
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return false
		}
	}
	sid := cfg.SID
	if sid == 0 {
		sid = 1
	}
	for _, cmd := range cfg.Commands {
		if cmd.Command == 0 {
			cmd.Command = CommandMemoryAreaRead
		}
		requestSID := sid
		if cmd.SID != 0 {
			requestSID = cmd.SID
		}
		if cmd.Direction == "down" {
			resp, e := BuildFrameWithConfig(cfg, cmd, true, requestSID)
			if e != nil {
				return false
			}
			if transport == "tcp" {
				resp = wrapTCP(resp)
			}
			if !emit(false, resp, 0x18) {
				return false
			}
		} else {
			req, e := BuildFrameWithConfig(cfg, cmd, false, requestSID)
			if e != nil {
				return false
			}
			if transport == "tcp" {
				req = wrapTCP(req)
			}
			if !emit(true, req, 0x18) {
				return false
			}
			if cmd.ExpectResponse == nil || *cmd.ExpectResponse {
				resp, e := BuildFrameWithConfig(cfg, cmd, true, requestSID)
				if e != nil {
					return false
				}
				if transport == "tcp" {
					resp = wrapTCP(resp)
				}
				if !emit(false, resp, 0x18) {
					return false
				}
			}
		}
		if cmd.Direction != "down" && cfg.SIDAuto {
			sid++
			if sid == 0 {
				sid = 1
			}
		}
	}
	if transport == "tcp" {
		return emit(true, nil, 0x11) && emit(false, nil, 0x10) && emit(false, nil, 0x11) && emit(true, nil, 0x10)
	}
	return true
}
func effectiveTTL(spec core.FlowSpec) uint8 {
	if spec.TTL == 0 {
		return 64
	}
	return spec.TTL
}
func validICF(v uint8) bool { return v&0x80 != 0 && v&0x20 == 0 && v&0x10 == 0 }
func wrapTCP(frame []byte) []byte {
	out := make([]byte, 16+len(frame))
	copy(out, []byte("FINS"))
	binary.BigEndian.PutUint32(out[4:8], uint32(8+len(frame)))
	binary.BigEndian.PutUint32(out[8:12], 2)
	copy(out[16:], frame)
	return out
}
func BuildFrame(cfg *FINSConfig, cmd FINSCommand, response bool) ([]byte, error) {
	sid := cmd.SID
	if sid == 0 {
		sid = cfg.SID
	}
	if sid == 0 {
		sid = 1
	}
	return BuildFrameWithConfig(cfg, cmd, response, sid)
}
func BuildFrameWithConfig(cfg *FINSConfig, cmd FINSCommand, response bool, sid uint8) ([]byte, error) {
	if cmd.Command == 0 {
		cmd.Command = CommandMemoryAreaRead
	}
	icf := cmd.ICF
	if icf == 0 {
		icf = cfg.ICF
	}
	if icf == 0 {
		if response {
			icf = 0xC1
		} else {
			icf = 0x81
		}
	}
	icf |= 0x80
	if response {
		icf |= 0x40
	} else {
		icf &^= 0x40
	}
	gct := cfg.GCT
	if gct == 0 {
		gct = 2
	}
	frame := []byte{icf, 0, gct, cfg.DNA, cfg.DA1, cfg.DA2, cfg.SNA, cfg.SA1, cfg.SA2, sid}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, cmd.Command)
	frame = append(frame, b...)
	if response {
		b = make([]byte, 2)
		binary.BigEndian.PutUint16(b, cmd.ResponseEndCode)
		frame = append(frame, b...)
		switch cmd.Command {
		case CommandMemoryAreaRead:
			data := cmd.Data
			if len(data) == 0 {
				if cmd.BitSet || cmd.Bit != 0 {
					data = make([]byte, int(cmd.Items))
					for i := range data {
						data[i] = byte(i % 2)
					}
				} else {
					data = make([]byte, int(cmd.Items)*2)
					for i := 0; i < int(cmd.Items); i++ {
						binary.BigEndian.PutUint16(data[i*2:], uint16(i+1))
					}
				}
			}
			frame = append(frame, data...)
		case CommandMultipleMemoryAreaRead:
			// D-FINS-1 C1：逐组数据，组内重起（字=uint16(i+1) BE、位=i%2），
			// 与 0101 单读合成模式同款。
			for _, ra := range cmd.ReadAreas {
				if ra.BitSet || ra.Bit != 0 {
					for i := 0; i < int(ra.Items); i++ {
						frame = append(frame, byte(i%2))
					}
				} else {
					for i := 0; i < int(ra.Items); i++ {
						b := make([]byte, 2)
						binary.BigEndian.PutUint16(b, uint16(i+1))
						frame = append(frame, b...)
					}
				}
			}
		case CommandClockRead:
			clock := cmd.Clock
			if clock == nil {
				clock = &FINSClock{Century: 20, Year: 26, Month: 8, Day: 18, Hour: 14, Minute: 30, Weekday: 2}
			}
			// Wireshark omron-fins dissector parses a 0x0701 clock-read response as
			// 7 clock bytes (year, month, date, hour, minute, second, weekday) with
			// NO century byte. Emitting a century byte leaves offset unconsumed and
			// tshark flags the frame malformed.
			frame = append(frame, bcd(clock.Year), bcd(clock.Month), bcd(clock.Day), bcd(clock.Hour), bcd(clock.Minute), bcd(clock.Second), bcd(clock.Weekday))
		}
		return frame, nil
	}
	switch cmd.Command {
	case CommandMemoryAreaRead, CommandMemoryAreaWrite, CommandMemoryAreaFill:
		bitAccess := cmd.BitSet || cmd.Bit != 0
		if cmd.Command == CommandMemoryAreaFill {
			// D-FINS-1 C1：0103 仅字口径（validate 已拒位口径，此处防御性
			// 强制），填充模板 2 字节直排，无 DC（剩余长度恒 8）。
			bitAccess = false
		}
		area, ok := memoryAreaCode(cmd.MemoryArea, cmd.Bit, bitAccess)
		if !ok {
			return nil, fmt.Errorf("fins: invalid memory area %q", cmd.MemoryArea)
		}
		frame = append(frame, area, byte(cmd.Address>>8), byte(cmd.Address), cmd.Bit, byte(cmd.Items>>8), byte(cmd.Items))
		if cmd.Command == CommandMemoryAreaWrite {
			dc := len(cmd.Data)
			frame = append(frame, byte(dc>>8), byte(dc))
			frame = append(frame, cmd.Data...)
		}
		if cmd.Command == CommandMemoryAreaFill {
			frame = append(frame, cmd.Data...)
		}
	case CommandMultipleMemoryAreaRead:
		// D-FINS-1 C1：组数 1B + N×[区码+地址2B+bit+NC2B]（每 6B/组）。
		frame = append(frame, byte(len(cmd.ReadAreas)))
		for _, ra := range cmd.ReadAreas {
			raBit := ra.BitSet || ra.Bit != 0
			area, ok := memoryAreaCode(ra.MemoryArea, ra.Bit, raBit)
			if !ok {
				return nil, fmt.Errorf("fins: invalid memory area %q", ra.MemoryArea)
			}
			frame = append(frame, area, byte(ra.Address>>8), byte(ra.Address), ra.Bit, byte(ra.Items>>8), byte(ra.Items))
		}
	case CommandClockRead:
	default:
		return nil, fmt.Errorf("fins: unsupported command 0x%04X", cmd.Command)
	}
	return frame, nil
}
func bcd(v uint8) byte { return (v/10)<<4 | (v % 10) }
