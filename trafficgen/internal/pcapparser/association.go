package pcapparser

// 跨流关联解析（D-PARSE-1 §跨流关联设计；3.8-3.10 解析面呈现）：全部流
// finalize 后第二遍，控制流文本面提取端口/地址，精确五元组命中 → 数据流
// RelatedFlowID=控制流 ID + RelatedRole。匹配不上不反向污染。

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// linkFlowAssociations 推导父子流（对 flows 逐控制流规则执行）。
func linkFlowAssociations(flows map[string]*FlowState) {
	for _, ctl := range flows {
		if ctl.FlowModel.L7Protocol == "ftp" {
			linkFTP(ctl, flows)
		} else if ctl.FlowModel.L7Protocol == "tftp" {
			linkTFTP(ctl, flows)
		} else if ctl.FlowModel.L7Protocol == "sip" {
			linkSIP(ctl, flows)
		} else if ctl.FlowModel.L7Protocol == "rtsp" {
			linkRTSP(ctl, flows)
		}
		// pptp：GRE 载荷流在 RC8 混搭面下身份不可靠 → not_derivable（注记）
		// h323：媒体端口经 H.245 协商，线上形态本批不解（关联表待确认行）
	}
}

// markRelated 记录关联（幂等：不覆盖已有关联）。
func markRelated(data *FlowState, ctl *FlowState, role string) {
	if data.FlowModel.RelatedFlowID != "" {
		return
	}
	data.FlowModel.RelatedFlowID = ctl.FlowModel.ID
	data.FlowModel.RelatedRole = role
	if ctl.FlowModel.RelatedRole == "" {
		ctl.FlowModel.RelatedRole = "control"
	}
}

// linkFTP：RFC 959 §4.1.2 PASV 响应 "227 ... (h1,h2,h3,h4,p1,p2)"。
func linkFTP(ctl *FlowState, flows map[string]*FlowState) {
	for _, buf := range [][]byte{ctl.streamBytes("c2s"), ctl.streamBytes("s2c")} {
		if buf == nil {
			continue
		}
		s := string(buf)
		for len(s) > 0 {
			i := strings.Index(s, "227 ")
			if i < 0 {
				break
			}
			seg := s[i:]
			open := strings.IndexByte(seg, '(')
			close_ := strings.IndexByte(seg, ')')
			if open < 0 || close_ < open {
				break
			}
			parts := strings.Split(seg[open+1:close_], ",")
			if len(parts) == 6 {
				h := make([]int, 6)
				valid := true
				for k, p := range parts {
					n, err := strconv.Atoi(strings.TrimSpace(p))
					if err != nil || n < 0 || n > 255 {
						valid = false
						break
					}
					h[k] = n
				}
				if valid {
					ip := strconv.Itoa(h[0]) + "." + strconv.Itoa(h[1]) + "." + strconv.Itoa(h[2]) + "." + strconv.Itoa(h[3])
					port := uint16(h[4]<<8 | h[5])
					linkByEndpoint(flows, ctl, ip, port, "data")
					// 数据流补 ftp_data 标签（第11轮反馈：数据流 L7=unknown
					// 应标 ftp-data；linkTFTP 同款先例）。
					for _, fs := range flows {
						if fs.FlowModel.RelatedFlowID == ctl.FlowModel.ID && fs.FlowModel.RelatedRole == "data" &&
							(fs.FlowModel.L7Protocol == "" || fs.FlowModel.L7Protocol == "unknown") {
							fs.FlowModel.L7Protocol = "ftp_data"
						}
					}
				}
				// 多传输各带 PASV（RFC 959 同控制连接顺序多数据流）——扫全程
				s = seg[close_:]
			}
			s = seg[1:]
		}
	}
}

// linkSIP：SDP c=/m=（RFC 8866 §5）→ RTP 流 + RTCP 相邻口（RFC 3550 §11 端口对）。
func linkSIP(ctl *FlowState, flows map[string]*FlowState) {
	if ctl.l7DetailAcc == nil {
		return
	}
	addrs, _ := ctl.l7DetailAcc.Extra["sdp_connection"].([]string)
	medias, _ := ctl.l7DetailAcc.Extra["sdp_media"].([]string)
	if len(addrs) == 0 || len(medias) == 0 {
		return
	}
	// c=IN IP4 <addr>
	var ip string
	for _, a := range addrs {
		f := strings.Fields(a)
		if len(f) >= 3 {
			ip = f[2]
			break
		}
	}
	if ip == "" {
		return
	}
	for _, m := range medias {
		// m=audio <port> RTP/AVP ...
		f := strings.Fields(m)
		if len(f) < 2 {
			continue
		}
		if port, err := strconv.Atoi(f[1]); err == nil && port > 0 {
			linkByEndpoint(flows, ctl, ip, uint16(port), "media_rtp")
			// RTCP 相邻口（RFC 3550 §11 端口对：偶/奇）
			linkByEndpoint(flows, ctl, ip, uint16(port+1), "media_rtcp")
			// NAT 回退：SDP IP 可能因 NAT 与实际流 IP 不一致——端口精确匹配
			linkByEndpointAnyIP(flows, ctl, uint16(port), "media_rtp")
			// RTCP NAT 回退（反馈项 3：RTCP 流=RTP+1 端口，补 AnyIP 匹配）
			linkByEndpointAnyIP(flows, ctl, uint16(port+1), "media_rtcp")
		}
	}
}

// linkRTSP：Transport: server_port=A-B / client_port=A-B（RFC 2326 §12.39）。
func linkRTSP(ctl *FlowState, flows map[string]*FlowState) {
	if ctl.l7DetailAcc == nil {
		return
	}
	transports, _ := ctl.l7DetailAcc.Extra["transports"].([]string)
	for _, tr := range transports {
		for _, kv := range strings.Split(tr, ";") {
			if strings.HasPrefix(kv, "server_port=") || strings.HasPrefix(kv, "client_port=") {
				ports := strings.Split(strings.SplitN(kv, "=", 2)[1], "-")
				if len(ports) >= 1 {
					if port, err := strconv.Atoi(ports[0]); err == nil && port > 0 {
						linkByEndpointAnyIP(flows, ctl, uint16(port), "media_rtp")
					}
				}
			}
		}
	}
}

// linkByEndpoint：流端点（src 或 dst）精确命中 ip:port。
func linkByEndpoint(flows map[string]*FlowState, ctl *FlowState, ip string, port uint16, role string) {
	for _, fs := range flows {
		if fs == ctl {
			continue
		}
		if (fs.FlowModel.SrcIP == ip && fs.FlowModel.SrcPort == port) ||
			(fs.FlowModel.DstIP == ip && fs.FlowModel.DstPort == port) {
			markRelated(fs, ctl, role)
		}
	}
}

// linkByEndpointAnyIP：仅端口命中（RTSP transport 不带 IP——控制流对端推断）。
func linkByEndpointAnyIP(flows map[string]*FlowState, ctl *FlowState, port uint16, role string) {
	for _, fs := range flows {
		if fs == ctl {
			continue
		}
		if fs.FlowModel.SrcPort == port || fs.FlowModel.DstPort == port {
			markRelated(fs, ctl, role)
		}
	}
}

// streamBytes 取方向缓冲（关联面只读）。
func (fs *FlowState) streamBytes(dir string) []byte {
	if dir == "c2s" && fs.c2sStream != nil {
		return fs.c2sStream.buf
	}
	if dir == "s2c" && fs.s2cStream != nil {
		return fs.s2cStream.buf
	}
	return nil
}

// linkTFTP：TFTP 控制流(69 端口)关联数据流（缺陷 3）。RFC 1350 §4：RRQ/WRQ
// 走 69 端口，数据走服务器临时端口。找同 IP 对 + 同客户端临时端口 + 非 69
// 端口的 UDP 流。
func linkTFTP(ctl *FlowState, flows map[string]*FlowState) {
	clientIP, clientPort := ctl.FlowModel.SrcIP, ctl.FlowModel.SrcPort
	// TFTP 控制流方向可能是 client→69 或 69→client，取非 69 端为客户端
	if clientPort == 69 {
		clientIP, clientPort = ctl.FlowModel.DstIP, ctl.FlowModel.DstPort
	}
	for _, fs := range flows {
		if fs == ctl || fs.FlowModel.L4Protocol != "udp" {
			continue
		}
		// 数据流：同客户端 IP+端口，非 69 端口
		var peerPort uint16
		if fs.FlowModel.SrcIP == clientIP && fs.FlowModel.SrcPort == clientPort {
			peerPort = fs.FlowModel.DstPort
		} else if fs.FlowModel.DstIP == clientIP && fs.FlowModel.DstPort == clientPort {
			peerPort = fs.FlowModel.SrcPort
		} else {
			continue
		}
		if peerPort == 69 {
			continue
		}
		markRelated(fs, ctl, "data")
		// 数据流补 tftp 标签（反馈项：数据流 L7=unknown 应标 tftp）
		if fs.FlowModel.L7Protocol == "" || fs.FlowModel.L7Protocol == "unknown" {
			fs.FlowModel.L7Protocol = "tftp_data"
		}
	}
}

// linkRTP：SIP SDP c=/m= 提取的 RTP 端口找 UDP 流（缺陷 2 补充——RTP 流给 rtp 识别）
func linkRTP(ctl *FlowState, flows map[string]*FlowState, ip string, port uint16) {
	for _, fs := range flows {
		if fs == ctl || fs.FlowModel.L4Protocol != "udp" {
			continue
		}
		if (fs.FlowModel.SrcIP == ip && fs.FlowModel.SrcPort == port) ||
			(fs.FlowModel.DstIP == ip && fs.FlowModel.DstPort == port) {
			markRelated(fs, ctl, "media")
			// RTP 流补 RTP 识别（ssrc 等 UDP 载荷首 12B 可解析时）
			if fs.FlowModel.L7Protocol == "" || fs.FlowModel.L7Protocol == "unknown" {
				fs.FlowModel.L7Protocol = "rtp"
				if fs.c2sHasher != nil || fs.c2sPrev != nil {
					// RTP 头：V(2) P(1) X(1) CC(4) M(1) PT(7) + seq(2) + timestamp(4) + ssrc(4)
					// 从第一个 UDP 载荷提取（由 feedUDPPayload 累积的 prev 前 12B）
					if len(fs.c2sPrev) >= 12 {
						fs.l7DetailAcc = &L7Detail{DetailVersion: L7DetailVersion, Type: "rtp", Extra: map[string]any{
							"ssrc":         binary.BigEndian.Uint32(fs.c2sPrev[8:12]),
							"payload_type": fs.c2sPrev[1] & 0x7F,
							"seq":          binary.BigEndian.Uint16(fs.c2sPrev[2:4]),
						}}
					} else if len(fs.s2cPrev) >= 12 {
						fs.l7DetailAcc = &L7Detail{DetailVersion: L7DetailVersion, Type: "rtp", Extra: map[string]any{
							"ssrc":         binary.BigEndian.Uint32(fs.s2cPrev[8:12]),
							"payload_type": fs.s2cPrev[1] & 0x7F,
						}}
					}
				}
			}
		}
		// RTCP 对口
		if (fs.FlowModel.SrcIP == ip && fs.FlowModel.SrcPort == port+1) ||
			(fs.FlowModel.DstIP == ip && fs.FlowModel.DstPort == port+1) {
			markRelated(fs, ctl, "media")
		}
	}
}
