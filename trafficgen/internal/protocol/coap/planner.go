package coap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const DefaultPort uint16 = 5683

type Planner struct{}

func NewPlanner() *Planner      { return &Planner{} }
func (p *Planner) Name() string { return "coap" }

func (p Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("coap: invalid source IP %q", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("coap: invalid destination IP %q", spec.DstIP)
	}
	if spec.SrcIP != "" && spec.DstIP != "" {
		src, dst := net.ParseIP(spec.SrcIP), net.ParseIP(spec.DstIP)
		if (src.To4() != nil) != (dst.To4() != nil) {
			return fmt.Errorf("coap: source and destination IP versions differ")
		}
	}
	if spec.SrcPort == 0 {
		return fmt.Errorf("coap: source port is required")
	}
	cfg := spec.CoAP
	if cfg == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （GET 请求 + 可选响应）。允许 nil，仅保留非 nil config 校验。
		return nil
	}
	if cfg.Version != 0 && cfg.Version != 1 {
		return fmt.Errorf("coap: version %d is invalid", cfg.Version)
	}
	if len(cfg.Token) > 8 {
		return fmt.Errorf("coap: token length %d exceeds 8", len(cfg.Token))
	}
	if cfg.TokenLength > 8 || (cfg.TokenLength != 0 && int(cfg.TokenLength) != len(cfg.Token)) {
		return fmt.Errorf("coap: token length is invalid")
	}
	if cfg.Method == "" && cfg.Code == 0 {
		return fmt.Errorf("coap: method or code is required")
	}
	if cfg.Code != 0 && !validRequestCode(cfg.Code) {
		return fmt.Errorf("coap: code %d is invalid", cfg.Code)
	}
	if cfg.Method != "" && methodCode(cfg.Method) == 0 && cfg.Code == 0 {
		return fmt.Errorf("coap: method %q is invalid", cfg.Method)
	}
	for _, part := range append(append([]string{}, cfg.Path...), cfg.Query...) {
		if strings.ContainsAny(part, "/\x00") {
			return fmt.Errorf("coap: URI component contains slash or NUL")
		}
	}
	if cfg.URIMaxLength > 0 {
		uriLen := 0
		for _, part := range cfg.Path {
			uriLen += len(part)
		}
		if len(cfg.Path) > 1 {
			uriLen += len(cfg.Path) - 1
		}
		if uint32(uriLen) > cfg.URIMaxLength {
			return fmt.Errorf("coap: URI exceeds maximum length")
		}
	}
	if cfg.ResponseCode != "" {
		if _, err := responseCode(cfg.ResponseCode); err != nil {
			return err
		}
	}
	if cfg.Retransmit != nil && cfg.Retransmit.Count < 0 {
		return fmt.Errorf("coap: retransmit count cannot be negative")
	}
	if cfg.Observe != nil && cfg.Observe.Notifications < 0 {
		return fmt.Errorf("coap: observe notifications cannot be negative")
	}
	for _, b := range append(responseBlocks(cfg), blockConfigValues(cfg)...) {
		if b.Size != 0 && (b.Size < 16 || b.Size > 1024 || b.Size&(b.Size-1) != 0) {
			return fmt.Errorf("coap: block size must be a power of two from 16 to 1024")
		}
	}
	return nil
}

func validRequestCode(c uint8) bool { return c >= 1 && c <= 4 }
func responseBlocks(cfg *CoAPConfig) []BlockConfig {
	out := make([]BlockConfig, 0, len(cfg.ResponseBlocks))
	for _, b := range cfg.ResponseBlocks {
		if b.Block2 != nil {
			out = append(out, *b.Block2)
		}
	}
	return out
}
func blockConfigValues(cfg *CoAPConfig) []BlockConfig {
	out := []BlockConfig{}
	if cfg.Block1 != nil {
		out = append(out, *cfg.Block1)
	}
	if cfg.Block2 != nil {
		out = append(out, *cfg.Block2)
	}
	return out
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	ch := make(chan core.PacketConfig, 16)
	go func() {
		defer close(ch)
		cfg := spec.CoAP
		if cfg == nil {
			// P0b-2：空配置默认化（Generate 同款：GET 请求，不自动响应）。
			falseVal := false
			cfg = &CoAPConfig{Method: "GET", Response: &falseVal}
		}
		emit := func(payload []byte, up bool, index uint64) bool {
			dir, srcIP, dstIP, srcPort, dstPort, srcMAC, dstMAC := "up", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, spec.SrcMAC, spec.DstMAC
			if !up {
				dir, srcIP, dstIP, srcPort, dstPort, srcMAC, dstMAC = "down", spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, spec.DstMAC, spec.SrcMAC
			}
			pkt := core.PacketConfig{FlowID: fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort), PacketIndex: index, Direction: dir, Timestamp: time.Now(), L2: core.L2Config{SrcMAC: srcMAC, DstMAC: dstMAC, EtherType: core.EtherTypeFor(srcIP)}, L3: core.L3Base(srcIP, dstIP, 17, coapTTL(spec), uint16(index), spec), L4: core.L4Config{Protocol: "udp", SrcPort: srcPort, DstPort: dstPort}, Payload: payload}
			select {
			case ch <- pkt:
				return true
			case <-ctx.Done():
				return false
			}
		}
		request, err := BuildMessage(cfg, false)
		if err != nil || !emit(request, true, 0) {
			return
		}
		if !shouldRespond(cfg) {
			return
		}
		response, err := BuildMessage(cfg, true)
		if err != nil {
			return
		}
		emit(response, false, 1)
	}()
	return ch, nil
}
func coapTTL(spec core.FlowSpec) uint8 {
	if spec.TTL != 0 {
		return spec.TTL
	}
	return 64
}
func shouldRespond(cfg *CoAPConfig) bool { return cfg.Response == nil || *cfg.Response }
