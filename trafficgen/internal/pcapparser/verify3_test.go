package pcapparser

import (
	"fmt"
	"os"
	"testing"
)

// 三轮反馈真机样本回归：openvpn_tcp / smtp_auth（AUTH LOGIN 不吞命令）。
// 样本不在本机时 Skip（本地语料回归，非 CI 面）。
func TestZZRound3Verify(t *testing.T) {
	for name, c := range map[string]struct {
		path string
		want string
	}{
		"openvpn_tcp": {"/home/pcap_auto/VPN/OPENVPN/OPENVPN_TCP_V2_HMAC-2.pcap", "openvpn"},
		"smtp_auth":   {"/home/pcap_auto/mypcap/publicpcap/IPv4/email/M_SMTP.pcap", "smtp"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(c.path); err != nil {
				t.Skipf("样本缺席: %s", c.path)
			}
			a, err := Parse(c.path, &Options{PcapAssetID: "z", UserID: "u"})
			if err != nil {
				t.Fatal(err)
			}
			protos := map[string]int{}
			var detail string
			for _, f := range a.Flows {
				protos[f.L7Protocol]++
				if f.L7Protocol == c.want && detail == "" {
					detail = f.L7Detail
				}
			}
			fmt.Printf("%s: protos=%v\n%s\n", name, protos, detail)
			if protos[c.want] == 0 {
				t.Errorf("%s: no %s flow (got %v)", name, c.want, protos)
			}
		})
	}
}
