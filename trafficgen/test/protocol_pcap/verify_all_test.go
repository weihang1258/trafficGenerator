package protocolpcap

// verify_all.go: 独立验证工具——复用 VerifyPcap 对已生成 pcap 目录逐用例
// tshark 核对，不受 go test 超时限制（阶段一全量 2157 用例的后半段）。
//
//	go test ./test/protocol_pcap/ -run TestVerifyExistingPcaps -v
//	VERIFY_ONLY=fail   # 只打印失败
//	VERIFY_PROTO=tcp   # 只验证单协议
//	VERIFY_SKIP_EXPECT_ERROR=1  # 跳过 expect_error 用例（无 pcap 可验证）

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestVerifyExistingPcaps 对 /tmp/mcp-pcaps/<proto>/<caseID>.pcap 逐个执行
// VerifyPcap（tshark 断言）。用例加载逻辑与 loadCases 一致。仅当
// VERIFY_RUN=1 时运行，避免污染常规全量测试。
func TestVerifyExistingPcaps(t *testing.T) {
	if os.Getenv("VERIFY_RUN") != "1" {
		t.Skip("set VERIFY_RUN=1 to run the offline pcap verifier")
	}
	pcapRoot := envPcapRoot
	if pcapRoot == "" {
		pcapRoot = "/tmp/mcp-pcaps"
	}
	onlyFail := os.Getenv("VERIFY_ONLY") == "fail"
	protoFilter := os.Getenv("VERIFY_PROTO")
	skipExpectError := os.Getenv("VERIFY_SKIP_EXPECT_ERROR") == "1"

	// 失败即时落盘：go test 超时杀测试时缓冲的 t.Errorf 会丢失，
	// 文件写入则总能留下（重跑时用 -timeout 0）。
	failFile := os.Getenv("VERIFY_FAIL_FILE")
	if failFile == "" {
		failFile = "/tmp/verify-failures.txt"
	}
	ff, ferr := os.Create(failFile)
	if ferr != nil {
		t.Fatalf("create fail file: %v", ferr)
	}
	defer ff.Close()
	w := bufio.NewWriter(ff)

	cases := loadCases(t)
	total, pass, fail := 0, 0, 0
	for proto, cs := range cases {
		if protoFilter != "" && proto != protoFilter {
			continue
		}
		for _, c := range cs {
			if skipExpectError && c.Expect.ExpectError {
				continue
			}
			total++
			// 路径必须与 RunCase 一致（用 case 的 proto 字段而非 map key）：
			// 文件名与 proto 字段可能不同（如 cases/probe_smb.json 声明 proto=smb）。
			pcap := filepath.Join(pcapRoot, c.Proto, c.ID+".pcap")
			if _, err := os.Stat(pcap); err != nil {
				fail++
				line := fmt.Sprintf("MISSING\t%s\t%s\tpcap missing: %v\n", proto, c.ID, err)
				w.WriteString(line)
				w.Flush()
				if !onlyFail {
					t.Errorf("[%s] %s: pcap missing: %v", proto, c.ID, err)
				}
				continue
			}
			probs := VerifyPcap(pcap, c)
			if len(probs) == 0 {
				pass++
				continue
			}
			fail++
			line := fmt.Sprintf("%s\t%s\t%s\n", proto, c.ID, joinProbs(probs))
			w.WriteString(line)
			w.Flush()
			if !onlyFail {
				t.Errorf("[%s] %s: %s", proto, c.ID, joinProbs(probs))
			}
		}
	}
	t.Logf("VERIFY RESULT: %d pass, %d fail (of %d)", pass, fail, total)
}
