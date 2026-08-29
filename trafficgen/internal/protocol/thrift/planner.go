package thrift

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "thrift" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.Thrift
	if cfg == nil {
		// P0b-2：空配置不再报错——Plan 会默认化并产默认流（layers 数组路径
		// 下 layer config 为空/缺省时）。
		return nil
	}
	if len(cfg.Messages) == 0 {
		return fmt.Errorf("thrift: at least one message required")
	}
	for i, m := range cfg.Messages {
		// type_code override: raw message-type byte must stay in 1..4
		// (negative tests inject out-of-range codes).
		if m.TypeCode != 0 && (m.TypeCode < MCall || m.TypeCode > MOneway) {
			return fmt.Errorf("thrift: invalid message type %d (want 1..4)", m.TypeCode)
		}
		if _, ok := msgType(m.Type); !ok {
			return fmt.Errorf("thrift: invalid message type %q (want CALL|REPLY|EXCEPTION|ONEWAY)", m.Type)
		}
		if m.Method == "" {
			return fmt.Errorf("thrift: message %d method is required", i)
		}
		for _, f := range append(append([]core.ThriftField{}, m.Args...), m.Result...) {
			// type_code override: raw TType byte must be a known type
			// (negative tests inject e.g. 99).
			if f.TypeCode != 0 {
				if _, ok := knownTType(byte(f.TypeCode)); !ok {
					return fmt.Errorf("thrift: unknown field type %d", f.TypeCode)
				}
			} else if _, ok := typeCode(f.Type); !ok {
				return fmt.Errorf("thrift: unknown field type %q", f.Type)
			}
		}
	}
	if wf := cfg.WireFault; wf != nil {
		switch wf.Kind {
		case "truncate":
			if wf.At != "string_bytes" {
				return fmt.Errorf("thrift: truncate wire fault at %q unsupported (want string_bytes)", wf.At)
			}
			return fmt.Errorf("thrift: truncated string_bytes cannot be encoded (wire fault)")
		case "negative_length":
			return fmt.Errorf("thrift: negative length on field %d cannot be encoded (wire fault)", wf.FieldID)
		case "negative_container_count":
			return fmt.Errorf("thrift: negative container count on field %d cannot be encoded (wire fault)", wf.FieldID)
		default:
			return fmt.Errorf("thrift: unknown wire fault kind %q", wf.Kind)
		}
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("thrift: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("thrift: invalid destination IP")
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 9090
	}
	cfg := spec.Thrift
	if cfg == nil {
		cfg = &core.ThriftConfig{Messages: []core.ThriftMessage{{Type: "CALL", Method: "ping", SeqID: 1}}}
	}

	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{
				FlowID:      "thrift",
				PacketIndex: idx,
				Direction:   dir,
				L2:          core.L2Config{EtherType: core.EtherTypeFor(sip)},
				L3:          core.L3Base(sip, dip, 6, 64, uint16(idx), spec),
				L4:          core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535},
				Payload:     payload,
				Timestamp:   time.Now(),
			}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		// TCP handshake
		if !emit(true, nil, 0x02) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		// Messages
		for i, m := range cfg.Messages {
			mt, _ := msgType(m.Type)
			body, err := buildMessageBody(mt, m.Args, m.Result, m.Exception)
			if err != nil {
				return
			}
			payload := buildMessage(mt, m.Method, m.SeqID, body)
			up := mt == MCall || mt == MOneway
			if !emit(up, payload, 0x18) {
				return
			}
			// RPC 响应语义：无显式响应的 CALL 自动补空 REPLY。
			if mt == MCall && !hasMatchingResponse(cfg.Messages, i, m) {
				reply := buildMessage(MReply, m.Method, m.SeqID, []byte{TStop})
				if !emit(false, reply, 0x18) {
					return
				}
			}
		}
		// TCP teardown
		emit(true, nil, 0x11)
		emit(false, nil, 0x10)
		emit(false, nil, 0x11)
		emit(true, nil, 0x10)
	}()
	return out, nil
}

// buildMessageBody builds the message body struct for the message type.
func buildMessageBody(mt byte, args, result []core.ThriftField, exc *core.ThriftException) ([]byte, error) {
	var b []byte
	switch mt {
	case MCall, MOneway:
		for _, f := range args {
			t, ok := fieldTypeInfo(f)
			if !ok {
				return nil, fmt.Errorf("thrift: unknown field type %q", f.Type)
			}
			fb, err := buildField(f.ID, t, f)
			if err != nil {
				return nil, err
			}
			b = append(b, fb...)
		}
	case MReply:
		for _, f := range result {
			t, ok := fieldTypeInfo(f)
			if !ok {
				return nil, fmt.Errorf("thrift: unknown field type %q", f.Type)
			}
			fb, err := buildField(f.ID, t, f)
			if err != nil {
				return nil, err
			}
			b = append(b, fb...)
		}
	case MException:
		if exc == nil {
			b = append(b, 0x00) // STOP only
			return b, nil
		}
		if exc.Message != "" {
			f, _ := buildField(1, TString, core.ThriftField{Value: exc.Message})
			b = append(b, f...)
		}
		if exc.Type != 0 {
			f, _ := buildField(2, TI32, core.ThriftField{Value: exc.Type})
			b = append(b, f...)
		}
	}
	b = append(b, 0x00) // STOP
	return b, nil
}

// knownTType reports whether the raw byte is a defined TType (§2.1).
func knownTType(b byte) (byte, bool) {
	switch b {
	case TStop, TBool, TByte, TDouble, TI16, TI32, TI64, TString, TStruct, TMap, TSet, TList:
		return b, true
	}
	return 0, false
}
