package filesystem

import (
	"encoding/json"
	"strings"
	"testing"
)

// 第10轮反馈 B（键名零校验）：{"file_path":...} 之类直觉键名此前静默忽略，
// 任务 completed 但内容为空。FileSource 未知键必须在解码即报错（fail-loud），
// 五个规范键不受影响。
func TestFileSourceUnmarshalRejectsUnknownKeys(t *testing.T) {
	var fs FileSource
	err := json.Unmarshal([]byte(`{"file_path":"a.bin"}`), &fs)
	if err == nil || !strings.Contains(err.Error(), "file_path") {
		t.Fatalf("未知键 file_path 应报错且点名键名, got %v", err)
	}
	err = json.Unmarshal([]byte(`{"zzz_bogus_key":"x"}`), &fs)
	if err == nil {
		t.Fatal("未知键 zzz_bogus_key 应报错")
	}
	// 五个规范键 + omitempty 组合不受影响
	err = json.Unmarshal([]byte(`{"file":"a.bin"}`), &fs)
	if err != nil || fs.File != "a.bin" {
		t.Fatalf("规范键 file 不应报错: %v", err)
	}
	err = json.Unmarshal([]byte(`{"file_id":"`+strings.Repeat("ab", 32)+`"}`), &fs)
	if err != nil || fs.FileID != strings.Repeat("ab", 32) {
		t.Fatalf("规范键 file_id 不应报错: %v", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &fs); err != nil {
		t.Fatalf("空对象不应报错: %v", err)
	}
}
