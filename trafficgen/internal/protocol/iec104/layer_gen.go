package iec104

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type IEC104Generator struct{}

func (*IEC104Generator) Name() string { return "iec104" }

func (g *IEC104Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("iec104 generator: EmitMsg is nil")
	}
	cfg := req.Meta.IEC104
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省
		// 时）。下方 len(cfg.Commands)==0 已有默认命令分支。
		cfg = &IEC104Config{}
	}
	emit := func(up bool, b []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return req.EmitMsg(layers.MessageEvent{Up: up, Bytes: b})
		}
	}
	if len(cfg.Events) > 0 {
		upTx, downTx := uint16(0), uint16(0)
		for _, event := range cfg.Events {
			eventTx, eventRx := upTx, downTx
			if event.Direction == "down" {
				eventTx, eventRx = downTx, upTx
			}
			b, err := buildEventWithSequence(event, eventTx, eventRx)
			if err != nil {
				return err
			}
			if err := emit(event.Direction != "down", b); err != nil {
				return err
			}
			if event.Kind == "i" {
				if event.Direction != "down" {
					upTx++
				} else {
					downTx++
				}
			}
		}
		return nil
	}
	if len(cfg.Commands) == 0 {
		c := *cfg
		c.Commands = []IEC104Command{{TypeID: TypeMSpNa, Cause: 3, CommonAddress: 1, InformationObjectAddress: 1, Value: 1}}
		cfg = &c
	}
	u, err := BuildUFrame(UStartDTAct)
	if err != nil {
		return err
	}
	if err = emit(true, u); err != nil {
		return err
	}
	u, err = BuildUFrame(UStartDTCon)
	if err != nil {
		return err
	}
	if err = emit(false, u); err != nil {
		return err
	}
	for _, c := range cfg.Commands {
		b, err := BuildInformation(&IEC104Config{TypeID: c.TypeID, Cause: c.Cause, CommonAddress: c.CommonAddress, InformationObjectAddress: c.InformationObjectAddress, Value: c.Value}, 0, 0)
		if err != nil {
			return err
		}
		if err = emit(true, b); err != nil {
			return err
		}
		if err = emit(false, b); err != nil {
			return err
		}
	}
	return nil
}

func buildEventWithSequence(event IEC104Event, tx, rx uint16) ([]byte, error) {
	if event.Kind == "i" {
		return BuildInformation(&IEC104Config{TypeID: event.TypeID, Cause: event.Cause, InformationObjectAddress: event.IOA, Value: event.Value, SIQ: event.SIQ, QDS: event.QDS, DIQ: event.DIQ, SCO: event.SCO, DCO: event.DCO, QOI: event.QOI, Select: event.Select, Time: event.Time}, tx, rx)
	}
	return buildEvent(event)
}

func buildEvent(event IEC104Event) ([]byte, error) {
	switch event.Kind {
	case "startdt_act":
		return BuildUFrame(UStartDTAct)
	case "startdt_con":
		return BuildUFrame(UStartDTCon)
	case "stopdt_act":
		return BuildUFrame(UStopDTAct)
	case "stopdt_con":
		return BuildUFrame(UStopDTCon)
	case "testfr_act":
		return BuildUFrame(UTestFRAct)
	case "testfr_con":
		return BuildUFrame(UTestFRCon)
	case "s":
		return BuildSFrame(event.RX)
	case "i":
		return BuildInformation(&IEC104Config{TypeID: event.TypeID, Cause: event.Cause, InformationObjectAddress: event.IOA, Value: event.Value, SIQ: event.SIQ, QDS: event.QDS, DIQ: event.DIQ, SCO: event.SCO, DCO: event.DCO, QOI: event.QOI, Select: event.Select, Time: event.Time}, 0, 0)
	default:
		return nil, fmt.Errorf("iec104 generator: unsupported event kind %q", event.Kind)
	}
}

func (*IEC104Generator) GenEvents() layers.EventGenerator { return &IEC104Generator{} }

func (*IEC104Generator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("iec104 generator: EmitEvent is not wired")
}

func init() {
	layers.RegisterLayerGenerator("iec104", func() (layers.LayerGenerator, error) { return &IEC104Generator{}, nil })
	layers.RegisterLayerValidator("iec104", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
