# 协议层 - DNS/ICMP/ARP实现

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**模块**: pkg/protocols

---

## 1. DNS协议实现

```go
// pkg/protocols/dns.go
package protocols

import (
    "encoding/binary"
    "math/rand"
)

type DNSSpec struct {
    Domain      string
    QueryType   uint16 // A=1, AAAA=28, MX=15
    SrcIP       string
    DstIP       string
    SrcPort     uint16
    Response    bool
    ResponseIP  string
}

func PlanDNSFlow(spec DNSSpec) <-chan PacketConfig {
    ch := make(chan PacketConfig, 2)
    
    go func() {
        defer close(ch)
        
        txID := uint16(rand.Intn(65536))
        
        // DNS查询
        query := buildDNSQuery(txID, spec.Domain, spec.QueryType)
        ch <- PacketConfig{
            L2: L2Config{
                SrcMAC: "00:00:00:00:00:01",
                DstMAC: "00:00:00:00:00:02",
            },
            L3: L3Config{
                SrcIP: spec.SrcIP,
                DstIP: spec.DstIP,
            },
            L4: L4Config{
                Protocol: "udp",
                SrcPort:  spec.SrcPort,
                DstPort:  53,
            },
            Payload:   query,
            Direction: "up",
        }
        
        // DNS响应
        if spec.Response {
            response := buildDNSResponse(txID, spec.Domain, spec.ResponseIP)
            ch <- PacketConfig{
                L2: L2Config{
                    SrcMAC: "00:00:00:00:00:02",
                    DstMAC: "00:00:00:00:00:01",
                },
                L3: L3Config{
                    SrcIP: spec.DstIP,
                    DstIP: spec.SrcIP,
                },
                L4: L4Config{
                    Protocol: "udp",
                    SrcPort:  53,
                    DstPort:  spec.SrcPort,
                },
                Payload:   response,
                Direction: "down",
            }
        }
    }()
    
    return ch
}

func buildDNSQuery(txID uint16, domain string, qtype uint16) []byte {
    buf := make([]byte, 12+len(domain)+2+4) // Header + Question
    
    // Header
    binary.BigEndian.PutUint16(buf[0:2], txID)
    binary.BigEndian.PutUint16(buf[2:4], 0x0100) // Standard query
    binary.BigEndian.PutUint16(buf[4:6], 1)      // 1 question
    
    // Question
    offset := 12
    for _, label := range strings.Split(domain, ".") {
        buf[offset] = byte(len(label))
        offset++
        copy(buf[offset:], label)
        offset += len(label)
    }
    buf[offset] = 0 // End of domain
    offset++
    
    binary.BigEndian.PutUint16(buf[offset:], qtype) // Type
    binary.BigEndian.PutUint16(buf[offset+2:], 1)   // Class IN
    
    return buf
}

func buildDNSResponse(txID uint16, domain string, ip string) []byte {
    // 构造DNS响应报文
    // Header + Question + Answer
    // 实现略...
    return []byte{}
}
```

---

## 2. ICMP协议实现

```go
// pkg/protocols/icmp.go
package protocols

type ICMPSpec struct {
    Type     uint8  // 8=Echo Request, 0=Echo Reply
    Code     uint8
    SrcIP    string
    DstIP    string
    Sequence uint16
    Data     []byte
}

func PlanICMPFlow(spec ICMPSpec) <-chan PacketConfig {
    ch := make(chan PacketConfig, 2)
    
    go func() {
        defer close(ch)
        
        id := uint16(rand.Intn(65536))
        
        // Echo Request
        request := buildICMPPacket(8, 0, id, spec.Sequence, spec.Data)
        ch <- PacketConfig{
            L2: L2Config{
                SrcMAC: "00:00:00:00:00:01",
                DstMAC: "00:00:00:00:00:02",
            },
            L3: L3Config{
                SrcIP:    spec.SrcIP,
                DstIP:    spec.DstIP,
                Protocol: 1, // ICMP
            },
            Payload:   request,
            Direction: "up",
        }
        
        // Echo Reply
        reply := buildICMPPacket(0, 0, id, spec.Sequence, spec.Data)
        ch <- PacketConfig{
            L2: L2Config{
                SrcMAC: "00:00:00:00:00:02",
                DstMAC: "00:00:00:00:00:01",
            },
            L3: L3Config{
                SrcIP:    spec.DstIP,
                DstIP:    spec.SrcIP,
                Protocol: 1,
            },
            Payload:   reply,
            Direction: "down",
        }
    }()
    
    return ch
}

func buildICMPPacket(icmpType, code uint8, id, seq uint16, data []byte) []byte {
    buf := make([]byte, 8+len(data))
    buf[0] = icmpType
    buf[1] = code
    binary.BigEndian.PutUint16(buf[4:6], id)
    binary.BigEndian.PutUint16(buf[6:8], seq)
    copy(buf[8:], data)
    
    // Checksum
    checksum := calculateChecksum(buf)
    binary.BigEndian.PutUint16(buf[2:4], checksum)
    
    return buf
}
```

---

## 3. ARP协议实现

```go
// pkg/protocols/arp.go
package protocols

type ARPSpec struct {
    Operation uint16 // 1=Request, 2=Reply
    SenderMAC string
    SenderIP  string
    TargetMAC string
    TargetIP  string
}

func PlanARPFlow(spec ARPSpec) <-chan PacketConfig {
    ch := make(chan PacketConfig, 2)
    
    go func() {
        defer close(ch)
        
        // ARP Request
        request := buildARPPacket(1, spec.SenderMAC, spec.SenderIP, 
            "00:00:00:00:00:00", spec.TargetIP)
        ch <- PacketConfig{
            L2: L2Config{
                SrcMAC:    spec.SenderMAC,
                DstMAC:    "ff:ff:ff:ff:ff:ff", // Broadcast
                EtherType: 0x0806,               // ARP
            },
            Payload:   request,
            Direction: "up",
        }
        
        // ARP Reply
        reply := buildARPPacket(2, spec.TargetMAC, spec.TargetIP,
            spec.SenderMAC, spec.SenderIP)
        ch <- PacketConfig{
            L2: L2Config{
                SrcMAC:    spec.TargetMAC,
                DstMAC:    spec.SenderMAC,
                EtherType: 0x0806,
            },
            Payload:   reply,
            Direction: "down",
        }
    }()
    
    return ch
}

func buildARPPacket(op uint16, senderMAC, senderIP, targetMAC, targetIP string) []byte {
    buf := make([]byte, 28)
    
    binary.BigEndian.PutUint16(buf[0:2], 1)    // Hardware type: Ethernet
    binary.BigEndian.PutUint16(buf[2:4], 0x0800) // Protocol type: IPv4
    buf[4] = 6  // Hardware size
    buf[5] = 4  // Protocol size
    binary.BigEndian.PutUint16(buf[6:8], op)
    
    copy(buf[8:14], parseMAC(senderMAC))
    copy(buf[14:18], parseIP(senderIP))
    copy(buf[18:24], parseMAC(targetMAC))
    copy(buf[24:28], parseIP(targetIP))
    
    return buf
}
```

---

## 4. 协议注册

```go
// pkg/protocols/init.go
func init() {
    Register("tcp", PlanTCPFlow)
    Register("udp", PlanUDPFlow)
    Register("http", PlanHTTPSession)
    Register("dns", PlanDNSFlow)
    Register("icmp", PlanICMPFlow)
    Register("arp", PlanARPFlow)
}
```
