package mcp

import (
	"reflect"
	"strings"
	"testing"
)

// TestPcapDescriptions_P0Fields（D-PARSE-1 §MCP 规则 3，13.13 引申）：解析侧
// 新字段落地面必须在工具描述/schema 词表中可见——列加了描述忘加=红。
func TestPcapDescriptions_P0Fields(t *testing.T) {
	// 字段 jsonschema 是结构体字面量 tag（13.13），反射取原文
	rt := reflect.TypeOf(managePcapsInput{})
	getTag := func(field string) string {
		f, ok := rt.FieldByName(field)
		if !ok {
			t.Fatalf("field %s missing", field)
		}
		tag := f.Tag.Get("jsonschema")
		if tag == "" {
			t.Fatalf("field %s jsonschema tag empty", field)
		}
		return tag
	}
	actionTag := getTag("Action")
	extractTag := getTag("ExtractRules")
	if pcapToolDescription == "" {
		t.Fatalf("pcapToolDescription empty")
	}

	cases := []struct {
		name  string
		hay   string
		needs []string
	}{
		{"action schema list_flows P0 面", actionTag, []string{"vlan", "payload+body sha256", "first_time", "icmp/sctp"}},
		{"action schema list_flows P1 面", actionTag, []string{"typed L7 detail"}},
		{"action schema get_packet dns 层", actionTag, []string{"dns layer"}},
		{"tool description P2a 解析器面", pcapToolDescription, []string{"coap", "ike_nat_t"}},
		{"action schema list_packets 头字段", actionTag, []string{"ip_id", "seq-ack-flags-window", "udp_len", "icmp", "payload_len"}},
		{"action schema get_packet icmpv6", actionTag, []string{"icmpv6"}},
		{"extract_rules unknown_fields", extractTag, []string{"unknown_fields", "ip_id", "embedded_*"}},
		{"tool description list_flows", pcapToolDescription, []string{"vlan/encap", "first_time"}},
		{"tool description get_packet", pcapToolDescription, []string{"icmpv6"}},
	}
	for _, c := range cases {
		for _, need := range c.needs {
			if !strings.Contains(c.hay, need) {
				t.Errorf("%s: 描述缺关键词 %q（新增列未同步描述，13.28）", c.name, need)
			}
		}
	}
}
