package fins

import (
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultPort            = 9600
	CommandMemoryAreaRead  = 0x0101
	CommandMemoryAreaWrite = 0x0102
	// D-FINS-1 C1：0103 Fill / 0104 Multiple Read 补齐（W342-E1 命令集，
	// 设计 G2 首版范围；此前代码缺实现=违反设计）。
	CommandMemoryAreaFill         = 0x0103
	CommandMultipleMemoryAreaRead = 0x0104
	CommandClockRead              = 0x0701
)

type FINSConfig struct {
	Transport   string        `json:"transport,omitempty"`
	Commands    []FINSCommand `json:"commands,omitempty"`
	Sessions    int           `json:"sessions,omitempty"`
	SID         uint8         `json:"sid,omitempty"`
	SIDAuto     bool          `json:"sid_auto,omitempty"`
	SIDAutoSet  bool          `json:"-"`
	ICF         uint8         `json:"icf,omitempty"`
	GCT         uint8         `json:"gct,omitempty"`
	DNA         uint8         `json:"dna,omitempty"`
	DA1         uint8         `json:"da1,omitempty"`
	DA2         uint8         `json:"da2,omitempty"`
	SNA         uint8         `json:"sna,omitempty"`
	SA1         uint8         `json:"sa1,omitempty"`
	SA2         uint8         `json:"sa2,omitempty"`
	Handshake   *bool         `json:"handshake,omitempty"`
	Termination *bool         `json:"termination,omitempty"`
}

type FINSCommand struct {
	Command         uint16     `json:"command,omitempty"`
	Direction       string     `json:"direction,omitempty"`
	SID             uint8      `json:"sid,omitempty"`
	ICF             uint8      `json:"icf,omitempty"`
	MemoryArea      string     `json:"memory_area,omitempty"`
	Address         uint16     `json:"address,omitempty"`
	Bit             uint8      `json:"bit,omitempty"`
	BitSet          bool       `json:"-"`
	Items           uint16     `json:"items,omitempty"`
	Data            []byte     `json:"data,omitempty"`
	ResponseEndCode uint16     `json:"response_end_code,omitempty"`
	ExpectResponse  *bool      `json:"expect_response,omitempty"`
	Clock           *FINSClock `json:"clock,omitempty"`
	// ReadAreas 是 0104 Multiple Memory Area Read 的读取组（仅 0104 合法，
	// 1-16 组；D-FINS-1 C1/E-10）。
	ReadAreas []FINSReadArea `json:"read_areas,omitempty"`
}

// FINSReadArea 是 0104 请求的单个读取组：[区码+地址2B+bit+NC2B]。
// Bit/BitSet 语义与 FINSCommand 同款（显式 "bit" 键即位口径，BitSet 由
// UnmarshalJSON 从键存在性派生）。
type FINSReadArea struct {
	MemoryArea string `json:"memory_area,omitempty"`
	Address    uint16 `json:"address,omitempty"`
	Bit        uint8  `json:"bit,omitempty"`
	BitSet     bool   `json:"-"`
	Items      uint16 `json:"items,omitempty"`
}

func (a *FINSReadArea) UnmarshalJSON(data []byte) error {
	var raw struct {
		MemoryArea string `json:"memory_area,omitempty"`
		Address    uint16 `json:"address,omitempty"`
		Bit        uint8  `json:"bit,omitempty"`
		Items      uint16 `json:"items,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*a = FINSReadArea{MemoryArea: raw.MemoryArea, Address: raw.Address, Bit: raw.Bit, BitSet: fields["bit"] != nil, Items: raw.Items}
	return nil
}

func (c *FINSConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Transport   string        `json:"transport,omitempty"`
		Commands    []FINSCommand `json:"commands,omitempty"`
		Sessions    int           `json:"sessions,omitempty"`
		SID         uint8         `json:"sid,omitempty"`
		SIDAuto     bool          `json:"sid_auto,omitempty"`
		ICF         uint8         `json:"icf,omitempty"`
		GCT         uint8         `json:"gct,omitempty"`
		DNA         uint8         `json:"dna,omitempty"`
		DA1         uint8         `json:"da1,omitempty"`
		DA2         uint8         `json:"da2,omitempty"`
		SNA         uint8         `json:"sna,omitempty"`
		SA1         uint8         `json:"sa1,omitempty"`
		SA2         uint8         `json:"sa2,omitempty"`
		Handshake   *bool         `json:"handshake,omitempty"`
		Termination *bool         `json:"termination,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*c = FINSConfig{
		Transport: raw.Transport, Commands: raw.Commands, Sessions: raw.Sessions,
		SID: raw.SID, SIDAuto: raw.SIDAuto, ICF: raw.ICF, GCT: raw.GCT,
		DNA: raw.DNA, DA1: raw.DA1, DA2: raw.DA2, SNA: raw.SNA, SA1: raw.SA1,
		SA2: raw.SA2, Handshake: raw.Handshake, Termination: raw.Termination,
	}
	_, c.SIDAutoSet = fields["sid_auto"]
	if !c.SIDAutoSet {
		c.SIDAuto = true
	}
	return nil
}

func (c *FINSCommand) UnmarshalJSON(data []byte) error {
	var raw struct {
		Command         uint16          `json:"command,omitempty"`
		Direction       string          `json:"direction,omitempty"`
		SID             uint8           `json:"sid,omitempty"`
		ICF             uint8           `json:"icf,omitempty"`
		MemoryArea      string          `json:"memory_area,omitempty"`
		Address         uint16          `json:"address,omitempty"`
		Bit             uint8           `json:"bit,omitempty"`
		Items           uint16          `json:"items,omitempty"`
		Data            json.RawMessage `json:"data,omitempty"`
		ResponseEndCode uint16          `json:"response_end_code,omitempty"`
		ExpectResponse  *bool           `json:"expect_response,omitempty"`
		Clock           *FINSClock      `json:"clock,omitempty"`
		ReadAreas       []FINSReadArea  `json:"read_areas,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var dataBytes []byte
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if len(raw.Data) != 0 && string(raw.Data) != "null" {
		if err := json.Unmarshal(raw.Data, &dataBytes); err != nil {
			var values []uint8
			if err := json.Unmarshal(raw.Data, &values); err != nil {
				return fmt.Errorf("fins: data must be a base64 string or byte array: %w", err)
			}
			dataBytes = values
		}
	}
	*c = FINSCommand{
		Command: raw.Command, Direction: raw.Direction, SID: raw.SID, ICF: raw.ICF,
		MemoryArea: raw.MemoryArea, Address: raw.Address, Bit: raw.Bit, BitSet: fields["bit"] != nil, Items: raw.Items,
		Data: dataBytes, ResponseEndCode: raw.ResponseEndCode,
		ExpectResponse: raw.ExpectResponse, Clock: raw.Clock, ReadAreas: raw.ReadAreas,
	}
	return nil
}

type FINSClock struct {
	Century uint8 `json:"century,omitempty"`
	Year    uint8 `json:"year,omitempty"`
	Month   uint8 `json:"month,omitempty"`
	Day     uint8 `json:"day,omitempty"`
	Hour    uint8 `json:"hour,omitempty"`
	Minute  uint8 `json:"minute,omitempty"`
	Second  uint8 `json:"second,omitempty"`
	Weekday uint8 `json:"weekday,omitempty"`
}

const MetadataKey = "fins"

func AttachSpec(spec core.FlowSpec, cfg *FINSConfig) core.FlowSpec {
	if spec.Metadata == nil {
		spec.Metadata = make(map[string]interface{})
	}
	spec.Metadata[MetadataKey] = cfg
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	return spec
}

func GetConfig(spec core.FlowSpec) *FINSConfig {
	if spec.Metadata == nil {
		return nil
	}
	switch value := spec.Metadata[MetadataKey].(type) {
	case *FINSConfig:
		return value
	case map[string]interface{}:
		raw, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		var cfg FINSConfig
		if json.Unmarshal(raw, &cfg) != nil {
			return nil
		}
		return &cfg
	case json.RawMessage:
		var cfg FINSConfig
		if json.Unmarshal(value, &cfg) != nil {
			return nil
		}
		return &cfg
	default:
		return nil
	}
}
