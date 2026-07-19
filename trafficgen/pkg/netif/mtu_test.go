package netif

import (
	"net"
	"strings"
	"testing"
)

// TestEnsureMTU_DisabledWhenZero: minMTU=0 disables the check entirely.
// Expected: nil return, no `ip` invocation, no error.
func TestEnsureMTU_DisabledWhenZero(t *testing.T) {
	// minMTU=0 must short-circuit before touching any interface.
	if err := EnsureMTU("any-iface-name", 0); err != nil {
		t.Fatalf("EnsureMTU with minMTU=0 should be a no-op, got err: %v", err)
	}
	// Negative values also disable (defensive).
	if err := EnsureMTU("any-iface-name", -1); err != nil {
		t.Fatalf("EnsureMTU with negative minMTU should be a no-op, got err: %v", err)
	}
}

// TestEnsureMTU_EmptyInterfaceName: empty interface name is a caller bug;
// surface it as an error rather than silently skipping.
func TestEnsureMTU_EmptyInterfaceName(t *testing.T) {
	if err := EnsureMTU("", 2000); err == nil {
		t.Fatal("EnsureMTU with empty interface name should return an error")
	}
}

// TestEnsureMTU_InterfaceNotFound: a non-existent interface returns an error
// (net.InterfaceByName fails). This guards the path where the configured
// port_group references an interface that doesn't exist on the host.
func TestEnsureMTU_InterfaceNotFound(t *testing.T) {
	err := EnsureMTU("definitely-not-a-real-iface-xyz123", 2000)
	if err == nil {
		t.Fatal("EnsureMTU on a non-existent interface should return an error")
	}
	if !strings.Contains(err.Error(), "definitely-not-a-real-iface-xyz123") {
		t.Fatalf("error should mention the interface name, got: %v", err)
	}
}

// TestEnsureMTU_AlreadySufficient: when the interface's MTU is already >=
// minMTU, EnsureMTU should return nil without invoking `ip link set`.
// Uses the loopback interface (lo), whose MTU is 65536 on Linux -- well
// above any reasonable min_mtu. This verifies the no-op path for the common
// case where the operator's NIC is already configured correctly.
func TestEnsureMTU_AlreadySufficient(t *testing.T) {
	ifi, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface not available on this platform: %v", err)
	}
	// Require MTU > 1500 so the test is meaningful; on weird platforms lo
	// could be smaller, in which case skip rather than falsely pass.
	if ifi.MTU <= 1500 {
		t.Skipf("loopback MTU too small (%d) to test the already-sufficient path", ifi.MTU)
	}
	if err := EnsureMTU("lo", ifi.MTU); err != nil {
		t.Fatalf("EnsureMTU should be a no-op when MTU is already sufficient, got: %v", err)
	}
	// Also verify the >= comparison (not just ==): feed a minMTU below current.
	if err := EnsureMTU("lo", 1500); err != nil {
		t.Fatalf("EnsureMTU should be a no-op when minMTU <= current MTU, got: %v", err)
	}
}
