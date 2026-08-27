package drda

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "drda" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.DRDA
	if cfg == nil {
		// P0b-2：空配置不再报错——Plan 会默认化并产默认流（layers 数组路径
		// 下 layer config 为空/缺省时）。
		return nil
	}
	// V1: TCP transport only
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("drda: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("drda: invalid destination IP")
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 446
	}
	cfg := spec.DRDA
	if cfg == nil {
		cfg = &DRDAConfig{}
	}
	correlator := cfg.CorrelatorStart
	if correlator == 0 {
		correlator = 1
	}
	corrInc := cfg.CorrelatorInc
	if corrInc == 0 {
		corrInc = 1
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
				FlowID:      "drda",
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
		if !emit(true, nil, 0x02) {
			return
		}
		if !emit(false, nil, 0x12) {
			return
		}
		if !emit(true, nil, 0x10) {
			return
		}

		// DSS segments from config
		var segs []DRDASegment
		if len(cfg.DSSSegments) > 0 {
			segs = cfg.DSSSegments
		} else {
			segs = buildDefaultSegments(cfg, correlator, corrInc)
		}

		for _, s := range segs {
			params := make([][]byte, len(s.Parameters))
			for i, p := range s.Parameters {
				pp, err := param(p.CodePoint, p.Data)
				if err != nil {
					return
				}
				params[i] = pp
			}
			ddm, err := ddmBuild(byte(s.Format), s.Correlator, s.CodePoint, params, false)
			if err != nil {
				return
			}
			// up direction
			if !emit(true, ddm, 0x18) {
				return
			}
			// response (down) with same correlator
			respCP := respCodePoint(s.CodePoint)
			if respCP != 0 {
				resp, err := ddmBuild(0x01, s.Correlator, respCP, nil, false)
				if err != nil {
					return
				}
				if !emit(false, resp, 0x18) {
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

// buildDefaultSegments constructs the default DRDA session sequence based on
// the association config ("excsat", "security", "database", or "full").
func buildDefaultSegments(cfg *core.DRDAConfig, correlatorStart, corrInc uint16) []DRDASegment {
	corr := correlatorStart
	next := func() uint16 {
		v := corr
		corr += corrInc
		return v
	}
	var segs []DRDASegment

	// Always EXCSAT
	segs = append(segs, DRDASegment{CodePoint: CPEXCSAT, Correlator: next()})

	if cfg.Transport == "excsat" {
		return segs
	}

	// ACCSEC
	segs = append(segs, DRDASegment{
		CodePoint:  CPACCSEC,
		Correlator: next(),
		Parameters: []DRDAParam{
			{CodePoint: 0x2113, Data: u16enc(cfg.CCSID)},
		},
	})

	// SECCHK
	segs = append(segs, DRDASegment{
		CodePoint:  CPSECCHK,
		Correlator: next(),
		Parameters: []DRDAParam{
			{CodePoint: 0x11a0, Data: []byte(cfg.SecurityUser)},
		},
	})

	if cfg.Transport == "security" {
		return segs
	}

	// ACCRDB
	rdbName := cfg.RDBName
	if rdbName == "" {
		rdbName = "SAMPLE"
	}
	segs = append(segs, DRDASegment{
		CodePoint:  CPACCRDB,
		Correlator: next(),
		Parameters: []DRDAParam{
			{CodePoint: 0x2115, Data: []byte(rdbName)},
		},
	})

	// SQL (optional)
	if cfg.SQL != nil {
		segs = append(segs, DRDASegment{
			CodePoint:  CPSQLDTA,
			Correlator: next(),
			Parameters: []DRDAParam{
				{CodePoint: 0x2160, Data: cfg.SQL.Data},
			},
		})
	}
	return segs
}

// respCodePoint maps request code point to response code point (§3.3).
func respCodePoint(cp uint16) uint16 {
	switch cp {
	case CPEXCSAT:
		return CPEXCSATRD
	case CPACCSEC:
		return CPACCSECRD
	case CPSECCHK:
		return CPSECCHKRM
	case CPACCRDB:
		return CPACCRDBRM
	case CPSQLDTA:
		return CPSQLCARD
	}
	return 0
}