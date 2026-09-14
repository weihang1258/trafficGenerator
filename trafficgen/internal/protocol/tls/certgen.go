// Copyright 2026 TrafficGen Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-TLS-2 certgen: 从层 config 的 cert 对象构建真实 X.509 DER，替换
// buildCertificate13/12 的 256B rand.Read 随机模板。
//
// 确定性：P-256 私钥由固定种子经 SHA-256 派生为标量（ScalarBaseMult 推
// 公钥，跨进程稳定）；签名熵由固定种子派生（ECDSA 需要 reader 供
// mixedCSPRNG，传 nil 会 panic）；序列号 = SHA-256(规范化参数串) 前 8B；
// 有效期=用户配置或固定默认常量（不用 time.Now，跨跑稳定）。
// 实证：2026-09-14 /tmp/certprobe，同参数 DER 逐字节相等，默认参数 465B。
//
// 私钥永不进配置、永不落盘：它是运行期从常量种子派生的测试密钥。

// 固定种子（与签名字段共享，无需分开）。
const (
	// certKeySeed 派生 P-256 私钥。
	certKeySeed = "trafficgen-tls-test-key-p256"
	// certSignSeed 派生 ECDSA 签名熵。
	certSignSeed = "trafficgen-tls-sign-entropy"
)

// cert 默认值（"缺省给全"裁定：cert 块缺席或单键缺席一律填完整默认值）。
const (
	defaultCertSubject   = "CN=trafficgen-test,O=TrafficGen Test Lab,C=CN"
	defaultCertSAN       = "example.com"
	defaultCertKeyType   = "ecdsa-p256"
	defaultCertNotBefore = "2026-01-01T00:00:00Z"
	defaultCertNotAfter  = "2036-01-01T00:00:00Z"
)

// certCache 按规范化参数串缓存 DER（同参数→同 DER，只读命中无竞争）。
var certCache sync.Map

// certgenRef 是 BuildCertDER 的输入：5 个明文字段（X509Ref 是 flat 侧
// 同名字段的层链侧镜像；私钥永不进配置）。
type certgenRef struct {
	subject   string
	san       []string
	keyType   string
	notBefore string
	notAfter  string
}

// canonKey 规范化参数串：缓存键 + 序列号派生源。san 保持用户顺序
// （顺序即意图，不排序——["a","b"] 与 ["b","a"] 是不同证书）。
func (r *certgenRef) canonKey() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s",
		r.subject, fmt.Sprint(r.san), r.keyType, r.notBefore, r.notAfter)
}

// defaultCertRef 返回缺省给全的默认 ref。
func defaultCertRef() *certgenRef {
	return &certgenRef{
		subject:   defaultCertSubject,
		san:       []string{defaultCertSAN},
		keyType:   defaultCertKeyType,
		notBefore: defaultCertNotBefore,
		notAfter:  defaultCertNotAfter,
	}
}

// parseCertConfig 把层 config 的 cert 对象解为 ref（缺键填默认）。
// 传入 nil 或空 map 均返回全默认 ref（"缺席即默认"）。
// 未知子键 / 非字符串标量 / san 非字符串数组 → 同步错误（create 期拒绝）。
func parseCertConfig(v interface{}) (*certgenRef, error) {
	ref := defaultCertRef()
	if v == nil {
		return ref, nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("tls cert must be an object")
	}
	for k, val := range m {
		switch k {
		case "subject":
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("tls cert.subject must be a string")
			}
			if s != "" {
				ref.subject = s
			}
		case "san":
			switch t := val.(type) {
			case string:
				if t != "" {
					ref.san = []string{t}
				}
			case []interface{}:
				var san []string
				for _, item := range t {
					s, ok := item.(string)
					if !ok {
						return nil, fmt.Errorf("tls cert.san must be a string or string array")
					}
					san = append(san, s)
				}
				if len(san) > 0 {
					ref.san = san
				}
			default:
				return nil, fmt.Errorf("tls cert.san must be a string or string array")
			}
		case "key_type":
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("tls cert.key_type must be a string")
			}
			if s != "" {
				ref.keyType = s
			}
		case "not_before":
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("tls cert.not_before must be a string")
			}
			if s != "" {
				ref.notBefore = s
			}
		case "not_after":
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("tls cert.not_after must be a string")
			}
			if s != "" {
				ref.notAfter = s
			}
		default:
			return nil, fmt.Errorf("tls cert: unknown field %q", k)
		}
	}
	return ref, nil
}

// validateCertRef 校验 ref 的业务约束（链结构性校验调用）：
// key_type 枚举（本轮仅 ecdsa-p256）、日期 RFC3339 可解析且
// not_after > not_before、每条 SAN ≤253B、subject 可解析为 DN。
func validateCertRef(ref *certgenRef) error {
	if ref.keyType != "ecdsa-p256" {
		return fmt.Errorf("tls chain: cert.key_type %q not supported yet (only \"ecdsa-p256\")", ref.keyType)
	}
	nb, err := time.Parse(time.RFC3339, ref.notBefore)
	if err != nil {
		return fmt.Errorf("tls chain: cert.not_before %q invalid RFC3339 timestamp: %v", ref.notBefore, err)
	}
	na, err := time.Parse(time.RFC3339, ref.notAfter)
	if err != nil {
		return fmt.Errorf("tls chain: cert.not_after %q invalid RFC3339 timestamp: %v", ref.notAfter, err)
	}
	if !na.After(nb) {
		return fmt.Errorf("tls chain: cert.not_after must be after not_before")
	}
	for _, s := range ref.san {
		if len(s) > 253 {
			return fmt.Errorf("tls chain: cert.san entry length %d exceeds max 253 bytes", len(s))
		}
	}
	if _, err := parseDN(ref.subject); err != nil {
		return err
	}
	return nil
}

// dnAttrs 是解析后的 DN（只取签名证书需要的子集，多值 O/OU 保留）。
type dnAttrs struct {
	cn string
	o  []string
	ou []string
	l  string
	st string
	c  string
}

// parseDN 解析 "CN=…,O=…,OU=…,L=…,ST=…,C=…"（RFC 4514 风格子集）。
// 未知属性 / 缺 "=" / 空值 → 错误。值内逗号不支持转义（测试 DN 不需要）。
func parseDN(s string) (*dnAttrs, error) {
	d := &dnAttrs{}
	for _, kv := range splitDN(s) {
		parts := splitN(kv, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("tls chain: cert.subject %q invalid DN (want K=V pairs)", s)
		}
		k, v := trimSpace(parts[0]), trimSpace(parts[1])
		if v == "" {
			return nil, fmt.Errorf("tls chain: cert.subject %q has empty value for %q", s, k)
		}
		switch k {
		case "CN":
			d.cn = v
		case "O":
			d.o = append(d.o, v)
		case "OU":
			d.ou = append(d.ou, v)
		case "L":
			d.l = v
		case "ST":
			d.st = v
		case "C":
			d.c = v
		default:
			return nil, fmt.Errorf("tls chain: cert.subject has unknown attribute %q", k)
		}
	}
	if d.cn == "" {
		return nil, fmt.Errorf("tls chain: cert.subject %q missing CN", s)
	}
	return d, nil
}

func splitDN(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func splitN(s, sep string, n int) []string {
	if n != 2 {
		panic("splitN only supports n=2")
	}
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return []string{s[:i], s[i+len(sep):]}
		}
	}
	return []string{s}
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// fixedP256Key 从固定种子派生 P-256 私钥（SHA-256 种子→标量，
// ScalarBaseMult 推公钥；标量为 0 或 ≥N 时循环加盐重派生——实测种子一次过）。
func fixedP256Key() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	n := curve.Params().N
	seed := certKeySeed
	for {
		h := sha256.Sum256([]byte(seed))
		d := new(big.Int).SetBytes(h[:])
		if d.Sign() != 0 && d.Cmp(n) < 0 {
			priv := new(ecdsa.PrivateKey)
			priv.D = d
			priv.PublicKey.Curve = curve
			priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
			return priv
		}
		seed += "\x00"
	}
}

// fixedEntropyReader 给 CreateCertificate 的确定性熵源（ECDSA 签名需要
// reader 供 mixedCSPRNG；c=SHA-256(seed‖ctr) 流式输出）。
type fixedEntropyReader struct {
	seed string
	ctr  uint64
}

func (r *fixedEntropyReader) Read(p []byte) (int, error) {
	off := 0
	for off < len(p) {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", r.seed, r.ctr)))
		r.ctr++
		n := copy(p[off:], h[:])
		off += n
	}
	return len(p), nil
}

// BuildCertDER 由 ref 构建 DER（缓存命中直接返回；未命中=DN 解析+
// 1 次 ECDSA 签名 ~100µs）。ref nil → 全默认 ref。
func BuildCertDER(ref *certgenRef) ([]byte, error) {
	if ref == nil {
		ref = defaultCertRef()
	}
	key := ref.canonKey()
	if v, ok := certCache.Load(key); ok {
		if der, ok := v.([]byte); ok {
			return der, nil
		}
	}
	dn, err := parseDN(ref.subject)
	if err != nil {
		return nil, err
	}
	nb, err := time.Parse(time.RFC3339, ref.notBefore)
	if err != nil {
		return nil, fmt.Errorf("tls cert.not_before %q invalid RFC3339 timestamp: %v", ref.notBefore, err)
	}
	na, err := time.Parse(time.RFC3339, ref.notAfter)
	if err != nil {
		return nil, fmt.Errorf("tls cert.not_after %q invalid RFC3339 timestamp: %v", ref.notAfter, err)
	}
	if !na.After(nb) {
		return nil, fmt.Errorf("tls cert.not_after must be after not_before")
	}
	if ref.keyType != "ecdsa-p256" {
		return nil, fmt.Errorf("tls cert.key_type %q not supported yet (only \"ecdsa-p256\")", ref.keyType)
	}
	serialSrc := sha256.Sum256([]byte(key))
	serial := new(big.Int).SetBytes(serialSrc[:8])
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         dn.cn,
			Organization:       dn.o,
			OrganizationalUnit: dn.ou,
			Locality:           nonEmpty(dn.l),
			Province:           nonEmpty(dn.st),
			Country:            nonEmpty(dn.c),
		},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              append([]string(nil), ref.san...),
	}
	priv := fixedP256Key()
	der, err := x509.CreateCertificate(
		&fixedEntropyReader{seed: certSignSeed}, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("tls cert: create certificate: %w", err)
	}
	certCache.Store(key, der)
	return der, nil
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// certRefFromX509 把 flat 侧 core.X509Ref 转为 certgenRef（legacy 路径复活
// 死参数 t.ServerCertificate：subject/san/key_type 直读；NotBefore/NotAfter
// unix 秒→RFC3339，0=默认常量；FileSource 忽略——层链 drive 期无文件注入通道）。
func certRefFromX509(x *core.X509Ref) *certgenRef {
	ref := defaultCertRef()
	if x == nil {
		return ref
	}
	if x.Subject != "" {
		ref.subject = x.Subject
	}
	if len(x.San) > 0 {
		ref.san = append([]string(nil), x.San...)
	}
	if x.KeyType != "" {
		ref.keyType = x.KeyType
	}
	if x.NotBefore != 0 {
		ref.notBefore = time.Unix(x.NotBefore, 0).UTC().Format(time.RFC3339)
	}
	if x.NotAfter != 0 {
		ref.notAfter = time.Unix(x.NotAfter, 0).UTC().Format(time.RFC3339)
	}
	return ref
}

// fallbackCertDER 返回 BuildCertDER 失败时的确定性占位（全默认 ref 必成功，
// 此函数理论不可达——存在只为杜绝"回退随机模板"重引入 BER 伪影）。
func fallbackCertDER() []byte {
	der, err := BuildCertDER(defaultCertRef())
	if err != nil {
		// 全默认 ref 解析失败意味着代码 bug（默认 DN 非法），panic 比静默错包好。
		panic("tls certgen: default ref failed: " + err.Error())
	}
	return der
}

// certDERsEqual 比较两份 DER 是否逐字节相等（测试用）。
func certDERsEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
