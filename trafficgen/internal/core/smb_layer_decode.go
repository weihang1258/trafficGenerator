package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// SMB 层链解码（D-SMB-1 #50）：layers[].smb → *SMBConfig，parseSMBConfig
// 同源宽容口径（hex 字符串数值、GUID hex 串、data 原文字节、ops 级 file_id）
// + 未知键严格拒。做法：先 DisallowUnknownFields 过一遍只做未知键检查
// （预归一化副本上跑，hex/byte 类值先换成同类型占位），再用 parseSMBConfig
// 做宽容填充（flat mold 单一真相）。
func TranslateSMBConfigFromMap(m map[string]interface{}) (*SMBConfig, error) {
	if m == nil {
		return &SMBConfig{}, nil
	}
	if err := smbLayerKeyCheck(normalizeSMBLayerMap(m)); err != nil {
		return nil, fmt.Errorf("smb layer config decode: %v", err)
	}
	cfg := parseSMBConfig(m)
	if cfg == nil {
		return &SMBConfig{}, nil
	}
	return cfg, nil
}

// normalizeSMBLayerMap returns a copy of m where values that encoding/json
// cannot decode into SMBConfig/SMBOperation (hex-string numerics, GUID hex
// strings, raw-text data, base64 data_b64, byte-list security_blob) are
// replaced by same-type placeholders, so smbLayerKeyCheck sees only key
// presence. Value semantics come from parseSMBConfig, never from this copy.
// tpos064 note: impersonation_level is a dead key (no SMBConfig field,
// generator hardcodes 2) — dropped here so the strict gate passes; P5 drops
// it from the case file with a notes entry.
func normalizeSMBLayerMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		// tpos064 dead key (see header note).
		if k == "impersonation_level" {
			continue
		}
		out[k] = v
	}
	// hex-string numerics → 0 (number placeholder keeps key presence).
	for _, k := range []string{"error_response_status", "previous_session_id"} {
		if s, ok := out[k].(string); ok && len(s) > 0 {
			out[k] = float64(0)
		}
	}
	// GUID hex strings → empty array placeholder ([16]byte decodes arrays).
	for _, k := range []string{"client_guid", "server_guid", "file_id"} {
		if _, ok := out[k].(string); ok {
			out[k] = []interface{}{}
		}
	}
	// security_blob byte list & data strings are natively decodable; data
	// as raw text is NOT base64 — replace with placeholder, value truth is
	// parseSMBConfig/getByteSlice.
	if ops, ok := out["operations"].([]interface{}); ok {
		norm := make([]interface{}, len(ops))
		for i, item := range ops {
			om, ok := item.(map[string]interface{})
			if !ok {
				norm[i] = item
				continue
			}
			cp := make(map[string]interface{}, len(om))
			for ok2, v := range om {
				cp[ok2] = v
			}
			if _, ok := cp["data"].(string); ok {
				cp["data"] = []interface{}{}
			}
			if _, ok := cp["file_id"].(string); ok {
				cp["file_id"] = []interface{}{}
			}
			norm[i] = cp
		}
		out["operations"] = norm
	}
	return out
}

// smbLayerKeyCheck strict-decodes the (pre-normalized) map with
// DisallowUnknownFields at config + per-op level (xmrmining 事件级严格同款).
func smbLayerKeyCheck(m map[string]interface{}) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var probe SMBConfig
	if err := dec.Decode(&probe); err != nil {
		return err
	}
	if arr, ok := m["operations"].([]interface{}); ok {
		for i, item := range arr {
			om, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			oraw, err := json.Marshal(om)
			if err != nil {
				return err
			}
			odec := json.NewDecoder(bytes.NewReader(oraw))
			odec.DisallowUnknownFields()
			var op SMBOperation
			if err := odec.Decode(&op); err != nil {
				return fmt.Errorf("operations[%d]: %v", i, err)
			}
		}
	}
	return nil
}
