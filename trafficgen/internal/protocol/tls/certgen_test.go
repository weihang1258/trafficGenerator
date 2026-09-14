package tls

import (
	"crypto/x509"
	"testing"
)

// D-TLS-2 步骤 0 locking①：BuildCertDER 确定性（同参数两次调用逐字节相等）。
func TestDTLS2_CertDERDeterministic(t *testing.T) {
	a, err := BuildCertDER(nil)
	if err != nil {
		t.Fatalf("BuildCertDER(nil) err: %v", err)
	}
	b, err := BuildCertDER(nil)
	if err != nil {
		t.Fatalf("BuildCertDER(nil) err: %v", err)
	}
	if !certDERsEqual(a, b) {
		t.Fatalf("DER not deterministic: len %d vs %d", len(a), len(b))
	}
}

// D-TLS-2 步骤 0 locking②：DER 可解析且明文字段回读正确。
func TestDTLS2_CertDERParses(t *testing.T) {
	der, err := BuildCertDER(nil)
	if err != nil {
		t.Fatalf("BuildCertDER(nil) err: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate err: %v", err)
	}
	if cert.Subject.CommonName != "trafficgen-test" {
		t.Errorf("CN=%q, want trafficgen-test", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "TrafficGen Test Lab" {
		t.Errorf("O=%v, want [TrafficGen Test Lab]", cert.Subject.Organization)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Errorf("SAN=%v, want [example.com]", cert.DNSNames)
	}
	if cert.NotBefore.UTC().Format("2006-01-02") != "2026-01-01" {
		t.Errorf("NotBefore=%v, want 2026-01-01", cert.NotBefore)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0 {
		t.Errorf("SerialNumber missing")
	}
}

// D-TLS-2 步骤 0 locking③：缺省给全（nil 与空对象均产完整默认 DER）。
func TestDTLS2_CertDefaultsFilled(t *testing.T) {
	a, err := BuildCertDER(nil)
	if err != nil {
		t.Fatalf("nil err: %v", err)
	}
	ref, err := parseCertConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("empty map err: %v", err)
	}
	b, err := BuildCertDER(ref)
	if err != nil {
		t.Fatalf("empty ref err: %v", err)
	}
	if !certDERsEqual(a, b) {
		t.Fatalf("nil vs empty-object DER differ: %d vs %d", len(a), len(b))
	}
	cert, _ := x509.ParseCertificate(a)
	if cert.Subject.CommonName == "" || len(cert.DNSNames) == 0 || cert.NotAfter.IsZero() {
		t.Fatalf("defaults not filled: CN=%q SAN=%v NotAfter=%v",
			cert.Subject.CommonName, cert.DNSNames, cert.NotAfter)
	}
}
