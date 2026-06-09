// Package netif provides network interface management.
package netif

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// Interface represents a network interface.
type Interface struct {
	Name        string           `json:"name"`
	MAC         net.HardwareAddr `json:"mac"`
	IPs         []net.IP         `json:"ips"`
	IsUp        bool             `json:"is_up"`
	LinkUp      bool             `json:"link_up"`
	MTU         int              `json:"mtu"`
	Description string           `json:"description"`
	IsVirtual   bool             `json:"is_virtual"`
}

// virtualInterfaceNames lists interface names that are always virtual.
var virtualInterfaceNames = map[string]bool{
	"any": true, "lo": true,
}

// virtualInterfacePrefixes lists prefixes that indicate a virtual interface.
var virtualInterfacePrefixes = []string{
	"nf", "usbmon", "bluetooth", "bridge", "docker",
	"veth", "virbr", "vnic", "cni-", "flannel", "tun", "tap",
	"gre", "sit", "ipip", "wg", "ovs-", "br-",
}

// isVirtualInterface determines if an interface is virtual based on its name.
func isVirtualInterface(name string) bool {
	if virtualInterfaceNames[name] {
		return true
	}
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Manager manages network interfaces.
type Manager struct {
	interfaces map[string]*Interface
	mu         sync.RWMutex
}

// NewManager creates a new interface manager.
func NewManager() *Manager {
	return &Manager{
		interfaces: make(map[string]*Interface),
	}
}

// Discover discovers all network interfaces.
func (m *Manager) Discover() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all interfaces from pcap
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("failed to find devices: %w", err)
	}

	// Also get net.Interfaces for additional info
	netIfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}

	// Create a map for quick lookup
	netMap := make(map[string]net.Interface)
	for _, ni := range netIfaces {
		netMap[ni.Name] = ni
	}

	// Process pcap devices
	for _, dev := range devs {
		iface := &Interface{
			Name:        dev.Name,
			Description: dev.Description,
			IPs:         make([]net.IP, 0),
			IsVirtual:   isVirtualInterface(dev.Name),
		}

		// Get addresses
		for _, addr := range dev.Addresses {
			if addr.IP != nil {
				iface.IPs = append(iface.IPs, addr.IP)
			}
		}

		// Get additional info from net.Interfaces
		if ni, ok := netMap[dev.Name]; ok {
			iface.MAC = ni.HardwareAddr
			iface.MTU = ni.MTU
			iface.IsUp = ni.Flags&net.FlagUp != 0
		}

		// Skip link status check for virtual interfaces (they cannot be opened via pcap)
		if !iface.IsVirtual {
			iface.LinkUp = m.checkLinkStatus(dev.Name)
		}

		m.interfaces[dev.Name] = iface

		zap.L().Debug("discovered interface",
			zap.String("name", iface.Name),
			zap.Strings("ips", ipsToStrings(iface.IPs)),
			zap.Bool("is_up", iface.IsUp),
			zap.Bool("link_up", iface.LinkUp),
			zap.Bool("is_virtual", iface.IsVirtual),
		)
	}

	zap.L().Info("interface discovery completed",
		zap.Int("count", len(m.interfaces)),
	)

	return nil
}

// checkLinkStatus checks if the interface has link.
func (m *Manager) checkLinkStatus(name string) bool {
	// Try to open the interface to check link status
	handle, err := pcap.OpenLive(name, 64, false, time.Second)
	if err != nil {
		return false
	}
	handle.Close()
	return true
}

// Get retrieves an interface by name.
func (m *Manager) Get(name string) (*Interface, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	iface, ok := m.interfaces[name]
	return iface, ok
}

// List returns all interfaces.
func (m *Manager) List() []*Interface {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Interface, 0, len(m.interfaces))
	for _, iface := range m.interfaces {
		list = append(list, iface)
	}
	return list
}

// ValidateInterface validates that an interface exists and is usable.
func (m *Manager) ValidateInterface(name string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	iface, ok := m.interfaces[name]
	if !ok {
		return fmt.Errorf("interface not found: %s", name)
	}

	if !iface.IsUp {
		return fmt.Errorf("interface is not up: %s", name)
	}

	if !iface.LinkUp {
		return fmt.Errorf("interface has no link: %s", name)
	}

	return nil
}

// Refresh refreshes interface information.
func (m *Manager) Refresh() error {
	return m.Discover()
}

// GetMAC returns the MAC address for an interface.
func (m *Manager) GetMAC(name string) (net.HardwareAddr, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	iface, ok := m.interfaces[name]
	if !ok {
		return nil, fmt.Errorf("interface not found: %s", name)
	}

	if len(iface.MAC) == 0 {
		return nil, fmt.Errorf("no MAC address for interface: %s", name)
	}

	return iface.MAC, nil
}

// GetIP returns the first IP address for an interface.
func (m *Manager) GetIP(name string) (net.IP, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	iface, ok := m.interfaces[name]
	if !ok {
		return nil, fmt.Errorf("interface not found: %s", name)
	}

	if len(iface.IPs) == 0 {
		return nil, fmt.Errorf("no IP address for interface: %s", name)
	}

	return iface.IPs[0], nil
}

// ipsToStrings converts IP addresses to strings.
func ipsToStrings(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}
