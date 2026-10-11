package pcapparser

// T-PARSE-COVERAGE：用例全量样本批量导入验证（用户验收"二"项）。
// 直接走 pcapparser.Parse（不走 REST/MCP），输出 L7Protocol + L7Detail 关键字段。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBatchCoverage(t *testing.T) {
	base := "/home/pcap_auto"
	groups := []struct {
		label   string
		pattern string
	}{
		{"Telnet23", "fiter/IP-TCP-*-23-*.pcap"},
		{"SMTP25", "fiter/IP-TCP-*-25-*.pcap"},
		{"POP3_110", "fiter/IP-TCP-*-110-*.pcap"},
		{"IMAP_143", "fiter/IP-TCP-*-143-*.pcap"},
		{"SMTPS_465", "fiter/IP-TCP-*-465-*.pcap"},
		{"IMAPS_993", "fiter/IP-TCP-*-993-*.pcap"},
		{"POP3S_995", "fiter/IP-TCP-*-995-*.pcap"},
		{"LDAP_389", "fiter/IP-TCP-*-389-*.pcap"},
		{"XMPP_5222", "fiter/IP-TCP-*-5222-*.pcap"},
		{"VNC_5901", "fiter/IP-TCP-*-5901-*.pcap"},
		{"RDP_3389", "fiter/IP-TCP-*-3389-*.pcap"},
		{"SOCKS_1080", "fiter/IP-TCP-*-1080-*.pcap"},
		{"H323_1720", "fiter/IP-TCP-*-1720-*.pcap"},
		{"PPTP_1723", "fiter/IP-TCP-*-1723-*.pcap"},
		{"RTMP_1935", "fiter/IP-TCP-*-1935-*.pcap"},
		{"HTTP_8000", "fiter/IP-TCP-*-8000-*.pcap"},
		{"DHCPv6_547", "fiter/IP-UDP-*-547-*.pcap"},
		{"mDNS_5353", "fiter/IP-UDP-*-5353-*.pcap"},
		{"NAT_T_4500", "fiter/IP-UDP-*-4500-*.pcap"},
		{"TCP_62763", "fiter/IP-TCP-*-62763-*.pcap"},
		{"TCP_7611", "fiter/IP-TCP-*-7611-*.pcap"},
		{"UDP_17767", "fiter/IP-UDP-*-17767-*.pcap"},
		{"UDP_31601", "fiter/IP-UDP-*-31601-*.pcap"},
		{"DNS_TCP_DNSHTTP", "dns/TCP_DNSHTTP_1_8.pcap"},
		{"DNS_recode_1", "dns/dns_recode_1.pcap"},
		{"DNS_more4A", "dns/dns_more4A.pcap"},
		{"DNS_moreA", "dns/dns_moreA.pcap"},
		{"DNS_1", "dns/dns_1.pcap"},
	}
	for _, g := range groups {
		files, _ := filepath.Glob(filepath.Join(base, g.pattern))
		if len(files) == 0 {
			fmt.Printf("COVER|%s|NO_SAMPLE\n", g.label)
			continue
		}
		a, err := Parse(files[0], &Options{PcapAssetID: "cov", UserID: "u"})
		if err != nil {
			fmt.Printf("COVER|%s|%s|PARSE_ERR|%v\n", g.label, filepath.Base(files[0]), err)
			continue
		}
		var protos []string
		for _, f := range a.Flows {
			protos = append(protos, f.L7Protocol)
		}
		// 取第一条有 L7Detail 的流
		detailSnippet := ""
		for _, f := range a.Flows {
			if f.L7Detail != "" && f.L7Detail != "{}" {
				var d L7Detail
				if json.Unmarshal([]byte(f.L7Detail), &d) == nil && len(d.Messages) > 0 {
					b, _ := json.Marshal(map[string]any{
						"type": d.Type, "msg_count": len(d.Messages),
						"kinds": msgKinds(d.Messages), "pair": d.Pair,
					})
					detailSnippet = string(b)
				}
				break
			}
		}
		fmt.Printf("COVER|%s|%s|flows=%d|l7=%s|detail=%s\n",
			g.label, filepath.Base(files[0]), len(a.Flows),
			strings.Join(uniq(protos), ","), detailSnippet)
	}
	
	// 特殊文件：pcapdump_1~16
	for i := 1; i <= 16; i++ {
		p := filepath.Join(base, "bc", fmt.Sprintf("pcapdump_%d.pcap", i))
		if _, err := os.Stat(p); err != nil {
			continue
		}
		a, err := Parse(p, &Options{PcapAssetID: "cov", UserID: "u"})
		if err != nil {
			fmt.Printf("PCAPDUMP|%d|PARSE_ERR|%v\n", i, err)
			continue
		}
		var protos []string
		for _, f := range a.Flows {
			protos = append(protos, f.L7Protocol)
		}
		fmt.Printf("PCAPDUMP|%d|%s|flows=%d|l7=%s\n",
			i, filepath.Base(p), len(a.Flows), strings.Join(uniq(protos), ","))
	}
}

func msgKinds(msgs []L7Message) []string {
	var out []string
	for _, m := range msgs {
		out = append(out, m.Kind)
	}
	return out
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
