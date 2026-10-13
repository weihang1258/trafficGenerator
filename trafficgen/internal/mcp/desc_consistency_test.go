package mcp

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestMCPSurfaceProtocolCountAgreement (客户端审查 2026-10-13 问题3)：instructions
// 写 125、工具描述写 123 的漂移不能再发生。struct tag 不能拼 const，所以三处
// 是"1 常量 + 2 字面量"——本测试把三方锁到同一个数字。真实口径 = rest
// GetProtocols（engine.ListProtocols() − udp），加协议时三处同步改。
func TestMCPSurfaceProtocolCountAgreement(t *testing.T) {
	want := "123"
	re := regexp.MustCompile(`for (\d+) protocols\.`)
	m := re.FindStringSubmatch(serverInstructions)
	if m == nil {
		t.Fatalf("serverInstructions missing protocol count: %.80s", serverInstructions)
	}
	if m[1] != want {
		t.Errorf("serverInstructions says %s protocols, want %s", m[1], want)
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(generateTrafficInput{}),
		reflect.TypeOf(manageStrategiesInput{}),
	} {
		f, ok := typ.FieldByName("Protocol")
		if !ok {
			t.Fatalf("%s has no Protocol field", typ.Name())
		}
		tag := f.Tag.Get("jsonschema")
		if !strings.Contains(tag, want+" protocols supported") {
			t.Errorf("%s.Protocol tag %q missing %q", typ.Name(), tag, want+" protocols supported")
		}
	}
}
