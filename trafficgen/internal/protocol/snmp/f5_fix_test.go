package snmp

// F5 regression test: derivePrivKey must use the configured auth protocol for
// the KDF, not a hardcoded "md5". Per RFC 3414 §3.2, the privacy key is
// derived using the same hash as the auth key: MD5 when auth=md5, SHA-1 when
// auth=sha1. A hardcoded MD5 KDF means auth=sha1 produces the wrong priv key
// (identical to the MD5 case), which would cause AES decryption failures on
// real SNMP agents.

import (
	"bytes"
	"testing"
)

// TestF5_derivePrivKey_UsesAuthProtocol verifies that derivePrivKey produces
// DIFFERENT keys when auth=md5 vs auth=sha1. With the bug (hardcoded "md5"),
// both calls produce identical keys and the test fails.
func TestF5_derivePrivKey_UsesAuthProtocol(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1F, 0x88, 0x12, 0x34, 0x56, 0x78}
	password := "testpassword123"

	keyMD5 := derivePrivKey(password, engineID, "aes128", "md5")
	keySHA1 := derivePrivKey(password, engineID, "aes128", "sha1")

	if len(keyMD5) != 16 {
		t.Fatalf("aes128 key length = %d, want 16", len(keyMD5))
	}
	if len(keySHA1) != 16 {
		t.Fatalf("aes128 key length = %d, want 16", len(keySHA1))
	}
	if bytes.Equal(keyMD5, keySHA1) {
		t.Error("priv key with auth=sha1 is identical to auth=md5; " +
			"derivePrivKey does not use the auth protocol for the KDF " +
			"(RFC 3414 §3.2 requires SHA-1 KDF when auth=sha1)")
	}
}

// TestF5_derivePrivKey_SHA1MatchesDirectDerivation verifies that the SHA-1
// derived priv key matches a manual SHA-1 KDF computation. This confirms the
// key is not just "different" but actually uses SHA-1.
func TestF5_derivePrivKey_SHA1MatchesDirectDerivation(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1F, 0x88}
	password := "maplesyrup"

	// Derive via the function under test.
	keyViaFunc := derivePrivKey(password, engineID, "aes128", "sha1")

	// Derive manually using SHA-1 (same algorithm as deriveAuthKey but inline).
	manualKey := deriveAuthKey(password, engineID, "sha1")[:16]

	if !bytes.Equal(keyViaFunc, manualKey) {
		t.Errorf("derivePrivKey(auth=sha1) = %x, want %x (direct SHA-1 KDF)",
			keyViaFunc, manualKey)
	}
}

// TestF5_derivePrivKey_MD5MatchesDirectDerivation verifies the MD5 path still
// works correctly (regression guard for the fix).
func TestF5_derivePrivKey_MD5MatchesDirectDerivation(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1F, 0x88}
	password := "maplesyrup"

	keyViaFunc := derivePrivKey(password, engineID, "aes128", "md5")
	manualKey := deriveAuthKey(password, engineID, "md5")[:16]

	if !bytes.Equal(keyViaFunc, manualKey) {
		t.Errorf("derivePrivKey(auth=md5) = %x, want %x (direct MD5 KDF)",
			keyViaFunc, manualKey)
	}
}
