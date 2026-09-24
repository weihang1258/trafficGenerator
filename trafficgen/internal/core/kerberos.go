package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Kerberos（D-KERBEROS-1 #44，契约 59-kerberos v1.0.0）配置类型。
// 字段名对齐契约 §2：sessions[] 事件编排会话（每事件 = 一条完整 Kerberos
// 消息 = 一 UDP datagram 或一 TCP record——RFC 4120 §6 双载体），多会话
// 按序回放，会话间 nonce/ticket/framing 状态全隔离（设计 §9）。
// 链形 [ip→udp→kerberos] 或 [ip→tcp→kerberos]：端口 88（KDC 惯用，tshark
// 自动解码依赖）。
//
// 编码权威：ASN.1 DER definite-length（BER 宽松解析不改变线上生成契约
// ——设计 §4）。消息结构 = RFC 4120 §5.2–5.4.2（P2 tag 权威表）。
// 加密边界：EncryptedData etype/kvno/cipher 长度可见，内层 opaque
// （设计 §1/§7——cipher 确定性填充，不伪造密文语义；key log 另立项）。

// KerberosConfig is the flow's kerberos terminal-layer configuration.
type KerberosConfig struct {
	// Sessions is the ordered session list（会话间 nonce/ticket/分帧状态
	// 不跨会话串用——设计 §9）.
	Sessions []KerberosSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault（6 值枚举，设计 §10 与
	// 用例 §4/§5 三方同序）.
	WireFault string `json:"wire_fault,omitempty"`
}

// KerberosSession is one event-orchestration session：端点覆盖 + 有序事件列。
// 会话身份 = SrcIP/SrcPort 覆盖（空/0 = 流缺省）。
type KerberosSession struct {
	// SrcIP overrides the session's source IP（多会话双客户端；空 = 流
	// 缺省。仅 up 方向直落——down 方向留空走链层交换，bacnet/dtls 先例。
	// 仅 UDP 载体可用：TCP 连接身份 = 四元组 connKey，带 src_ip 覆盖的
	// down 事件会被折叠成第二条连接——tcp 载体声明即拒，builder 守卫）.
	SrcIP string `json:"src_ip,omitempty"`
	// SrcPort overrides the session's source port (0 = 流缺省).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port (0 = 继承链级缺省
	// 88 via FieldContract；validator 守会话间一致性).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Events is the session's ordered event list；每事件一消息.
	Events []KerberosEvent `json:"events,omitempty"`
}

// KerberosEvent is one Kerberos message（事件）：kind 决定 application tag
// 与 DER 结构；Up 显式声明方向（KDC 请求/应答按 fixture 编排）。
type KerberosEvent struct {
	// Kind: as_req|as_rep|tgs_req|tgs_rep|ap_req|ap_rep|krb_error
	// （application tag 10/11/12/13/14/15/30；未知 kind 拒）.
	Kind string `json:"kind"`
	// Up declares the direction (true=client→KDC/service).
	Up bool `json:"up,omitempty"`
	// MsgType declares the msg-type INTEGER（指针：缺省按 kind 派生；
	// 声明值 ≠ kind 派生值 = tag↔msg-type 一致性守卫拒——裁定6）.
	MsgType *int `json:"msg_type,omitempty"`

	// Realm is the server realm（req-body[2]/rep srealm[9]/ticket realm[1]）.
	Realm string `json:"realm,omitempty"`
	// CRealm is the client realm（KDC-REP crealm[3]；空 = 复用 Realm）.
	CRealm string `json:"crealm,omitempty"`
	// CName/SName are PrincipalName name-string 组件（不把 user@REALM
	// 当单一 name-string——设计 §7）.
	CName []string `json:"cname,omitempty"`
	SName []string `json:"sname,omitempty"`
	// NameType is PrincipalName name-type [0]（缺省 1 = KRB5_NT_PRINCIPAL）.
	NameType *int `json:"name_type,omitempty"`

	// EType is the EncryptedData etype [0]（缺省 18 = aes256-cts-hmac-sha1-96，
	// RFC 3968/4121）.
	EType *int `json:"etype,omitempty"`
	// KVNO is the optional kvno [1]（nil = 省略 OPTIONAL 字段）.
	KVNO *int `json:"kvno,omitempty"`
	// CipherLen declares the opaque cipher OCTET STRING length（确定性
	// 填充 0xA5；缺省 52）.
	CipherLen int `json:"cipher_len,omitempty"`

	// Nonce is the req-body nonce [9]（缺省 778001——MIT kinit 惯用形态）.
	Nonce *int `json:"nonce,omitempty"`
	// Till is the req-body till [7] GeneralizedTime（缺省 20370913024805Z
	// ——MIT 形态）.
	Till string `json:"till,omitempty"`
	// CTime/CUsec declare client time（PA-ENC-TIMESTAMP 外壳/KRB-ERROR
	// ctime[2]/cusec[3]；缺省 20260924120000Z / 0）.
	CTime string `json:"ctime,omitempty"`
	CUsec *int   `json:"cusec,omitempty"`
	// Stime/SUsec are KRB-ERROR server time [4]/[5]（缺省同 CTime 缺省）.
	Stime string `json:"stime,omitempty"`
	SUsec *int   `json:"susec,omitempty"`
	// ErrorCode is the KRB-ERROR error-code [6]（krb_error 必声明；
	// 7 = KDC_ERR_PREAUTH_REQUIRED、25 = KRB_AP_ERR_SKEW 等）.
	ErrorCode *int `json:"error_code,omitempty"`
	// EText is the optional e-text [11].
	EText string `json:"e_text,omitempty"`
	// PAData declares req-body padata [3]（METHOD-DATA 保序不覆盖——
	// RFC 6113；value = 确定性 opaque 填充）.
	PAData []KerberosPAData `json:"padata,omitempty"`

	// Body overrides the full message DER（hex；opaque fixture 逃生口——
	// 负例/特殊形用；声明时其余结构字段不参与渲染）.
	Body string `json:"body,omitempty"`
}

// KerberosPAData is one PA-DATA：type [1] + value [2]（value = ValueLen
// 确定性 opaque 字节；0 = 空 OCTET STRING）.
type KerberosPAData struct {
	Type     int `json:"type"`
	ValueLen int `json:"value_len,omitempty"`
}

// UnmarshalJSON strict-decodes the kerberos layer config（未知键拒绝；
// dtls 同款递归严格面）。
func (c *KerberosConfig) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	type alias KerberosConfig
	var a alias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*c = KerberosConfig(a)
	return nil
}

// 6 wire_fault 值（设计 §2 配置键表逐字；锚词=testcase §4 目标词——逐值
// 单锚词；负例 ID 后缀与 wire_fault 值不同名是设计既定——§10 表）。
const (
	KerberosWireFaultRecordTruncated   = "record_truncated"   // 消息/DER 头截断
	KerberosWireFaultRecordLength      = "record_length"      // TCP 4B 长度前缀错
	KerberosWireFaultTag               = "tag"                // tag/pvno/msg-type 不一致
	KerberosWireFaultEncryptedBoundary = "encrypted_boundary" // EncryptedData 外壳越界
	KerberosWireFaultReplay            = "replay"             // skew/nonce/replay 状态错
	KerberosWireFaultCarrier           = "carrier"            // 载体错（缺/双载体）
)

// DescribeKerberosWireFault returns the row's 主锚词（error_contains 断言）。
func DescribeKerberosWireFault(kind string) (string, error) {
	anchors := map[string]string{
		KerberosWireFaultRecordTruncated:   "record",
		KerberosWireFaultRecordLength:      "tcp",
		KerberosWireFaultTag:               "tag",
		KerberosWireFaultEncryptedBoundary: "encrypted",
		KerberosWireFaultReplay:            "replay",
		KerberosWireFaultCarrier:           "udp",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("kerberos: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
