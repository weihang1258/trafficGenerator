package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// startCapture starts tcpdump on the given interface, writing to a pcap file.
// Returns a stop function that stops tcpdump and returns the captured packets.
// Skips the test if tcpdump is unavailable or the interface doesn't exist.
func startCapture(t *testing.T, iface, filter string) (stop func() []gopacket.Packet) {
	t.Helper()
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skipf("tcpdump not available: %v", err)
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		t.Skipf("interface %s not available: %v", iface, err)
	}
	pcapPath := filepath.Join(t.TempDir(), "capture.pcap")
	// -U: packet-buffered output (flush each packet)
	// -s 0: capture full packet
	cmd := exec.Command("tcpdump", "-i", iface, "-w", pcapPath, "-U", "-s", "0", filter)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tcpdump: %v", err)
	}
	// Give tcpdump time to start
	time.Sleep(200 * time.Millisecond)

	stop = func() []gopacket.Packet {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
		return readPcap(t, pcapPath)
	}
	return stop
}

// readPcap reads all packets from a pcap file.
func readPcap(t *testing.T, path string) []gopacket.Packet {
	t.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("open pcap %s: %v", path, err)
	}
	defer handle.Close()
	var pkts []gopacket.Packet
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		pkts = append(pkts, pkt)
	}
	return pkts
}

// extractFlowKey extracts a bidirectional flow key from a packet.
// Returns "minIP-maxIP-minPort-maxPort" (unordered, same for both directions).
// Returns "" if the packet has no network or transport layer.
func extractFlowKey(pkt gopacket.Packet) string {
	nw := pkt.NetworkLayer()
	tp := pkt.TransportLayer()
	if nw == nil || tp == nil {
		return ""
	}
	srcIP, dstIP := nw.NetworkFlow().Src().String(), nw.NetworkFlow().Dst().String()
	if dstIP < srcIP {
		srcIP, dstIP = dstIP, srcIP
	}
	srcPort, dstPort := tp.TransportFlow().Src().String(), tp.TransportFlow().Dst().String()
	if dstPort < srcPort {
		srcPort, dstPort = dstPort, srcPort
	}
	return fmt.Sprintf("%s-%s-%s-%s", srcIP, dstIP, srcPort, dstPort)
}
