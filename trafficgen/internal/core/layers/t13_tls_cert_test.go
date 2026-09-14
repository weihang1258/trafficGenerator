package layers_test

import (
	"crypto/x509"
	"testing"
)

// D-TLS-2 步骤 0 locking④：链上 frame7 Certificate 载荷含可解析 DER。
func TestDTLS2_T13CertParses(t *testing.T) {
	frames := buildTLSChain(t, `[{"tls":{}},{"http":{}}]`)
	payloadOff := 14 + 20 + 20
	var certDER []byte
	for _, f := range frames {
		if len(f) <= payloadOff+5 {
			continue
		}
		rec := tlsRecordAt(f, payloadOff)
		if rec == nil || rec[0] != 0x16 {
			continue
		}
		body := rec[5:]
		if len(body) < 1 || body[0] != 11 {
			continue
		}
		// Certificate: hs type(1)+len(3)+ctx(1)+list_len(3)+entry[len(3)+der+ext(2)]
		if len(body) < 4+1+3+3 {
			t.Fatalf("Certificate body too short: %d", len(body))
		}
		hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		_ = hsLen
		ctxLen := int(body[4])
		listOff := 5 + ctxLen
		listLen := int(body[listOff])<<16 | int(body[listOff+1])<<8 | int(body[listOff+2])
		entryOff := listOff + 3
		certLen := int(body[entryOff])<<16 | int(body[entryOff+1])<<8 | int(body[entryOff+2])
		certDER = body[entryOff+3 : entryOff+3+certLen]
		_ = listLen
		break
	}
	if certDER == nil {
		t.Fatal("no Certificate handshake found")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("chain Certificate DER does not parse: %v (len %d)", err, len(certDER))
	}
	if cert.Subject.CommonName != "trafficgen-test" {
		t.Errorf("CN=%q, want trafficgen-test", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Errorf("SAN=%v, want [example.com]", cert.DNSNames)
	}
}
