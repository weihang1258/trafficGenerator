// Package netif provides network interface management.
package netif

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// EnsureMTU checks the MTU of the given interface and raises it to minMTU if
// below. Returns nil if already >= minMTU or if the raise succeeded.
// Returns an error if the raise failed (permission, driver unsupported, etc).
//
// Logs a WARN when MTU is changed. The original MTU is NOT restored after the
// task ends: multiple concurrent tasks may share the same NIC and fighting
// over the value would race; the operator can revert manually if needed.
//
// minMTU <= 0 disables the check (no-op, returns nil).
func EnsureMTU(iface string, minMTU int) error {
	if minMTU <= 0 {
		return nil
	}
	if iface == "" {
		return fmt.Errorf("EnsureMTU: empty interface name")
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	if ifi.MTU >= minMTU {
		return nil
	}
	oldMTU := ifi.MTU
	// `ip link set` requires CAP_NET_ADMIN. Running as root works; non-root
	// will fail with "RTNETLINK answers: Operation not permitted" -- the
	// returned error surfaces that to the caller so the task fails cleanly.
	cmd := exec.Command("ip", "link", "set", "dev", iface, "mtu", fmt.Sprintf("%d", minMTU))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("set MTU %d on %s: %w (output: %s). Run trafficgen as root or lower engine.min_mtu",
			minMTU, iface, err, strings.TrimSpace(string(out)))
	}
	zap.L().Warn("NIC MTU raised for task",
		zap.String("interface", iface),
		zap.Int("old_mtu", oldMTU),
		zap.Int("new_mtu", minMTU),
		zap.String("note", "original MTU not restored after task"),
	)
	return nil
}
