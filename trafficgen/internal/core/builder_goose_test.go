package core

import (
	"encoding/binary"
	"testing"
)

func TestBuilder_GOOSEDirectEtherTypeAndPayload(t *testing.T) {
	payload := []byte{0x61, 0x03, 0x80, 0x01, 0x01}
	pkt, err := NewBuilder().Build(PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:01", DstMAC: "01:0c:cd:01:02:03", EtherType: EtherTypeGOOSE},
		L4: L4Config{Protocol: "goose"}, Payload: payload,
	})
	if err != nil { t.Fatalf("Build() error = %v", err) }
	if got := binary.BigEndian.Uint16(pkt[12:14]); got != EtherTypeGOOSE { t.Fatalf("EtherType = 0x%04x, want 0x88b8", got) }
	if got := pkt[14]; got != 0x61 { t.Fatalf("payload starts at offset 14 with 0x%02x, want APDU tag 0x61", got) }
	if len(pkt) < MinEthernetFrame { t.Fatalf("frame length = %d, want Ethernet minimum padding", len(pkt)) }
}

func TestBuilder_GOOSEDoesNotEmitIPHeader(t *testing.T) {
	pkt, err := NewBuilder().Build(PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:01", DstMAC: "01:0c:cd:01:02:03", EtherType: EtherTypeGOOSE},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", Protocol: ProtocolTCP},
		L4: L4Config{Protocol: "goose"}, Payload: []byte{0x61, 0x00},
	})
	if err != nil { t.Fatalf("Build() error = %v", err) }
	if pkt[14] == 0x45 || pkt[14] == 0x60 { t.Fatalf("GOOSE frame unexpectedly contains an IP version header at offset 14") }
}
