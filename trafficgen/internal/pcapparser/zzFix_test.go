package pcapparser

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestFixDNS(t *testing.T) {
	a, err := Parse("/home/pcap_auto/dns/DNS_v4_vlan.pcap", &Options{PcapAssetID: "fix", UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Flows {
		if f.L7Protocol != "dns" {
			continue
		}
		var d L7Detail
		json.Unmarshal([]byte(f.L7Detail), &d)
		fmt.Printf("dns: pair=%+v messages=%d extra=%v\n", d.Pair, len(d.Messages), d.Extra)
		for _, m := range d.Messages {
			fmt.Printf("  dir=%s kind=%s qr=%v rcode=%v answers=%d wire_len=%d\n",
				m.Dir, m.Kind, m.Fields["qr"], m.Fields["rcode"], m.Fields["ancount"], m.Fields["wire_len"])
			if ans, ok := m.Fields["answers"].([]map[string]any); ok {
				for _, r := range ans {
					fmt.Printf("    RR %s type=%s rdata=%s\n", r["name"], r["type_str"], r["rdata"])
				}
			}
		}
	}
}

func TestFixTFTPAssoc(t *testing.T) {
	a, err := Parse("/home/pcap_auto/fiter/IP-UDP-10.9.1.227-20.9.1.227-61442-69-1-0-78-0.pcap", &Options{PcapAssetID: "fix", UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range a.Flows {
		fmt.Printf("flow[%d] l7=%q rel=%q/%q ports=%d→%d\n", i, f.L7Protocol, f.RelatedFlowID, f.RelatedRole, f.SrcPort, f.DstPort)
	}
}

func TestFixSIPAssoc(t *testing.T) {
	a, err := Parse("/home/pcap_auto/fiter/IP-TCP-10.9.1.231-20.9.1.231-54100-5060-7-7-1449-1720.pcap", &Options{PcapAssetID: "fix", UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range a.Flows {
		fmt.Printf("flow[%d] l7=%q rel=%q/%q\n", i, f.L7Protocol, f.RelatedFlowID, f.RelatedRole)
		if f.L7Protocol == "sip" && f.L7Detail != "" {
			var d L7Detail
			json.Unmarshal([]byte(f.L7Detail), &d)
			fmt.Printf("  sip extra=%v methods=%v\n", d.Extra, d.Messages[0].Fields["methods"])
		}
	}
}
