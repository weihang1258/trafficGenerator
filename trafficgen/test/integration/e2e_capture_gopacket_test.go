package integration_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// E2E capture + gopacket-based verification of trafficgen packet fields.
// Verifies the v3 default-value changes (commit 60a5ae2 + review fixes)
// at the wire level using real tcpdump capture parsed with gopacket.
//
// Run with: go test -race -count=1 -timeout 120s -v ./test/integration/ -run TestE2EGoPacket

const (
	e2eIface      = "enp135s0f0np0"
	e2ePortGroup  = "eb94c12f-0bc1-4021-8e5a-fe5fb64c1c87"
	e2eBase       = "http://localhost:8080"
	e2eAdminUser  = "admin"
	e2eAdminPass  = "admin"
)

func e2eLogin(t *testing.T) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": e2eAdminUser, "password": e2eAdminPass})
	resp, err := http.Post(e2eBase+"/api/v1/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	var r struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if r.Data.Token == "" {
		t.Fatal("empty token")
	}
	return r.Data.Token
}

func e2eAPI(t *testing.T, token, method, path string, body interface{}) map[string]interface{} {
	t.Helper()
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req, _ = http.NewRequest(method, e2eBase+path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest(method, e2eBase+path, nil)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var r map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&r)
	return r
}

// e2eStartCapture starts tcpdump writing to a temp pcap file. Returns a
// stop function that returns the file path. Requires root for -Z root.
func e2eStartCapture(t *testing.T, filter string) (stop func() string) {
	t.Helper()
	pcapPath := t.TempDir() + "/cap.pcap"
	cmd := exec.Command("tcpdump", "-i", e2eIface, "-w", pcapPath, "-U", "-s", "0", "-Z", "root", filter)
	if err := cmd.Start(); err != nil {
		t.Skipf("tcpdump start failed (need root?): %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	stop = func() string {
		cmd.Process.Signal(os.Interrupt)
		cmd.Process.Wait()
		return pcapPath
	}
	return
}

// e2eReadPcap parses a pcap file with gopacket, returns all packets.
func e2eReadPcap(t *testing.T, path string) []gopacket.Packet {
	t.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	var pkts []gopacket.Packet
	for p := range src.Packets() {
		pkts = append(pkts, p)
	}
	return pkts
}

// e2eExtractTCP returns the TCP layer + IPv4 layer from a packet, or nil.
func e2eExtractTCP(p gopacket.Packet) (ip *layers.IPv4, tcp *layers.TCP) {
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ip = l.(*layers.IPv4)
	}
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		tcp = l.(*layers.TCP)
	}
	return
}

// e2eFindSyn finds the first SYN packet (FIN=0, SYN=1, ACK=0) in the list.
func e2eFindSyn(pkts []gopacket.Packet) (*layers.IPv4, *layers.TCP) {
	for _, p := range pkts {
		ip, tcp := e2eExtractTCP(p)
		if tcp == nil {
			continue
		}
		if tcp.SYN && !tcp.ACK {
			return ip, tcp
		}
	}
	return nil, nil
}

// e2eCreateStrategyAndTask creates a strategy + task (not started), returns taskID.
func e2eCreateStrategyAndTask(t *testing.T, token, name, protocol string, config map[string]interface{}) (stratID, taskID string) {
	t.Helper()
	r := e2eAPI(t, token, "POST", "/api/v1/strategies", map[string]interface{}{
		"name":     name,
		"mode":     "synth",
		"protocol": protocol,
		"config":   config,
	})
	stratID, _ = r["data"].(map[string]interface{})["id"].(string)
	if stratID == "" {
		t.Fatalf("create strategy: %v", r)
	}
	r = e2eAPI(t, token, "POST", "/api/v1/tasks", map[string]interface{}{
		"name":         name + "-task",
		"strategy_ids": []string{stratID},
		"output_type":  "port_group",
		"output_config": map[string]interface{}{
			"port_group_id": e2ePortGroup,
		},
	})
	taskID, _ = r["data"].(map[string]interface{})["id"].(string)
	if taskID == "" {
		t.Fatalf("create task: %v", r)
	}
	return
}

// ========================================================================
// Scenario 1: TCP SYN seq is random (not fixed 1000)
// ========================================================================

func TestE2EGoPacket_TCPSeqRandom(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-seq-rand", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 11111, "dst_port": 80,
		"tcp": map[string]interface{}{"handshake": true, "termination": false},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	ip, tcp := e2eFindSyn(pkts)
	if tcp == nil {
		t.Fatal("no SYN found")
	}
	if tcp.Seq == 1000 {
		t.Errorf("SYN Seq = 1000 (fixed), want random; got seq=%d", tcp.Seq)
	}
	t.Logf("SYN Seq = %d (random, OK)", tcp.Seq)
	_ = ip
}

// ========================================================================
// Scenario 2: TCP IPID is random (not fixed 1)
// ========================================================================

func TestE2EGoPacket_TCPIPIDRandom(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-ipid-rand", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 22222, "dst_port": 80,
		"tcp": map[string]interface{}{"handshake": true, "termination": false},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	ip, tcp := e2eFindSyn(pkts)
	if ip == nil {
		t.Fatal("no IPv4 layer")
	}
	if ip.Id == 1 {
		t.Errorf("IPID = 1 (fixed), want random; got Id=%d", ip.Id)
	}
	t.Logf("IPID = %d (random, OK)", ip.Id)
	_ = tcp
}

// ========================================================================
// Scenario 3: TCP SYN options include Window Scale (kind=3, data=0x07)
// ========================================================================

func TestE2EGoPacket_TCPSynWindowScale(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-ws", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 33333, "dst_port": 80,
		"tcp": map[string]interface{}{"handshake": true, "termination": false},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	_, tcp := e2eFindSyn(pkts)
	if tcp == nil {
		t.Fatal("no SYN found")
	}
	var hasWS, hasMSS, hasSACK bool
	var wsData byte
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			hasMSS = true
		case layers.TCPOptionKindWindowScale:
			hasWS = true
			if len(opt.OptionData) >= 1 {
				wsData = opt.OptionData[0]
			}
		case layers.TCPOptionKindSACKPermitted:
			hasSACK = true
		}
	}
	if !hasMSS {
		t.Error("SYN options missing MSS")
	}
	if !hasWS {
		t.Fatal("SYN options missing Window Scale (kind=3)")
	}
	if wsData != 0x07 {
		t.Errorf("Window Scale shift = %d, want 7", wsData)
	}
	if !hasSACK {
		t.Error("SYN options missing SACK-Permitted")
	}
	t.Logf("SYN options: MSS=%v WS=%v(shift=%d) SACK=%v", hasMSS, hasWS, wsData, hasSACK)
}

// ========================================================================
// Scenario 4: TCP MSS=0 normalizes to DefaultMSS (1460) in SYN
// ========================================================================

func TestE2EGoPacket_TCPMSSZeroDefaults(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-mss0", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 44444, "dst_port": 80,
		"tcp": map[string]interface{}{"handshake": true, "termination": false, "mss": 0},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	_, tcp := e2eFindSyn(pkts)
	if tcp == nil {
		t.Fatal("no SYN found")
	}
	var mss uint16
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) >= 2 {
			mss = uint16(opt.OptionData[0])<<8 | uint16(opt.OptionData[1])
		}
	}
	if mss == 0 {
		t.Fatal("SYN has no MSS option (MSS=0 should normalize to 1460)")
	}
	if mss != 1460 {
		t.Errorf("MSS = %d, want 1460 (DefaultMSS)", mss)
	}
	t.Logf("SYN MSS = %d (normalized from 0, OK)", mss)
}

// ========================================================================
// Scenario 5: DSCP default is CS1 (TOS byte = 0x20 = 0x08 << 2)
// ========================================================================

func TestE2EGoPacket_DSCPDefaultCS1(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-dscp", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 55555, "dst_port": 80,
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	ip, _ := e2eFindSyn(pkts)
	if ip == nil {
		t.Fatal("no IPv4 SYN found")
	}
	// TOS byte = DSCP<<2 | ECN. DSCP=0x08 (CS1) -> TOS high 6 bits = 0x08,
	// TOS byte = 0x08<<2 = 0x20 (ECN=0).
	tos := ip.TOS
	if tos != 0x20 {
		t.Errorf("IP TOS = 0x%02x, want 0x20 (DSCP=CS1=0x08 << 2)", tos)
	}
	t.Logf("IP TOS = 0x%02x (DSCP=CS1, OK)", tos)
}

// ========================================================================
// Scenario 6: HTTP Host: www.home.com (user-provided)
// ========================================================================

func TestE2EGoPacket_HTTPHostUserProvided(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-http-host", "http", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 56666, "dst_port": 80,
		"http": map[string]interface{}{
			"method":  "GET",
			"uri":     "/index.html",
			"version": "HTTP/1.1",
			"request_headers": map[string]interface{}{
				"Host": "www.home.com",
			},
		},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	// Find HTTP GET packet (PSH+ACK with payload)
	var httpPayload string
	for _, p := range pkts {
		_, tcp := e2eExtractTCP(p)
		if tcp == nil || len(tcp.Payload) == 0 {
			continue
		}
		s := string(tcp.Payload)
		if strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") {
			httpPayload = s
			break
		}
	}
	if httpPayload == "" {
		t.Fatal("no HTTP request payload found")
	}
	if !strings.Contains(httpPayload, "Host: www.home.com") {
		t.Errorf("HTTP payload missing 'Host: www.home.com':\n%s", httpPayload)
	}
	t.Logf("HTTP request has Host: www.home.com (OK)")
}

// ========================================================================
// Scenario 7: HTTP Host default = dst_ip when not user-provided (HTTP/1.1)
// ========================================================================

func TestE2EGoPacket_HTTPHostDefault(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-http-defhost", "http", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 57777, "dst_port": 80,
		"http": map[string]interface{}{
			"method":  "GET",
			"uri":     "/",
			"version": "HTTP/1.1",
		},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	var httpPayload string
	for _, p := range pkts {
		_, tcp := e2eExtractTCP(p)
		if tcp == nil || len(tcp.Payload) == 0 {
			continue
		}
		s := string(tcp.Payload)
		if strings.HasPrefix(s, "GET ") {
			httpPayload = s
			break
		}
	}
	if httpPayload == "" {
		t.Fatal("no HTTP GET found")
	}
	want := "Host: 10.0.0.2"
	if !strings.Contains(httpPayload, want) {
		t.Errorf("HTTP payload missing default '%s':\n%s", want, httpPayload)
	}
	t.Logf("HTTP default Host = %s (OK)", want)
}

// ========================================================================
// Scenario 8: HTTP/1.0 does NOT auto-add Host
// ========================================================================

func TestE2EGoPacket_HTTP10NoAutoHost(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-http10", "http", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 58888, "dst_port": 80,
		"http": map[string]interface{}{
			"method":  "GET",
			"uri":     "/",
			"version": "HTTP/1.0",
		},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	var httpPayload string
	for _, p := range pkts {
		_, tcp := e2eExtractTCP(p)
		if tcp == nil || len(tcp.Payload) == 0 {
			continue
		}
		s := string(tcp.Payload)
		if strings.HasPrefix(s, "GET ") {
			httpPayload = s
			break
		}
	}
	if httpPayload == "" {
		t.Fatal("no HTTP GET found")
	}
	if strings.Contains(httpPayload, "Host:") {
		t.Errorf("HTTP/1.0 should NOT auto-add Host, but found:\n%s", httpPayload)
	}
	t.Logf("HTTP/1.0 no auto Host (OK)")
}

// ========================================================================
// Scenario 9: HTTP Content-Length auto-computed from body
// ========================================================================

func TestE2EGoPacket_HTTPContentLength(t *testing.T) {
	token := e2eLogin(t)
	body := "hello-world-body-12345"
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-http-cl", "http", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 59999, "dst_port": 80,
		"http": map[string]interface{}{
			"method":  "POST",
			"uri":     "/api",
			"version": "HTTP/1.1",
			"body":    body,
		},
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	var httpPayload string
	for _, p := range pkts {
		_, tcp := e2eExtractTCP(p)
		if tcp == nil || len(tcp.Payload) == 0 {
			continue
		}
		s := string(tcp.Payload)
		if strings.HasPrefix(s, "POST ") {
			httpPayload = s
			break
		}
	}
	if httpPayload == "" {
		t.Fatal("no HTTP POST found")
	}
	want := fmt.Sprintf("Content-Length: %d", len(body))
	if !strings.Contains(httpPayload, want) {
		t.Errorf("HTTP payload missing '%s':\n%s", want, httpPayload)
	}
	t.Logf("HTTP Content-Length = %d (auto, OK)", len(body))
}

// ========================================================================
// Scenario 10: MTU >= 2000 enforced after task start
// ========================================================================

func TestE2EGoPacket_MTUEnforced(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-mtu", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 60001, "dst_port": 80,
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	stop()
	ifi, err := net.InterfaceByName(e2eIface)
	if err != nil {
		t.Fatalf("interface: %v", err)
	}
	if ifi.MTU < 2000 {
		t.Errorf("NIC MTU = %d, want >= 2000", ifi.MTU)
	}
	t.Logf("NIC MTU = %d (>= 2000, OK)", ifi.MTU)
}

// ========================================================================
// Scenario 11: TCP two flows have distinct SYN seq (random per flow)
// ========================================================================

func TestE2EGoPacket_TwoFlowsDistinctSeq(t *testing.T) {
	token := e2eLogin(t)
	_, task1 := e2eCreateStrategyAndTask(t, token, "e2e-flow1", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 60010, "dst_port": 80,
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+task1+"/start", nil)
	time.Sleep(2 * time.Second)
	pcap1 := stop()
	pkts1 := e2eReadPcap(t, pcap1)
	_, tcp1 := e2eFindSyn(pkts1)
	if tcp1 == nil {
		t.Fatal("flow1 no SYN")
	}

	_, task2 := e2eCreateStrategyAndTask(t, token, "e2e-flow2", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 60020, "dst_port": 80,
	})
	stop = e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+task2+"/start", nil)
	time.Sleep(2 * time.Second)
	pcap2 := stop()
	pkts2 := e2eReadPcap(t, pcap2)
	_, tcp2 := e2eFindSyn(pkts2)
	if tcp2 == nil {
		t.Fatal("flow2 no SYN")
	}

	if tcp1.Seq == tcp2.Seq {
		t.Errorf("two flows have same SYN Seq = %d (want distinct)", tcp1.Seq)
	}
	t.Logf("flow1 Seq=%d, flow2 Seq=%d (distinct, OK)", tcp1.Seq, tcp2.Seq)
}

// ========================================================================
// Scenario 12: initial_seq user override is honored (after review fix C1)
// ========================================================================

func TestE2EGoPacket_InitialSeqOverride(t *testing.T) {
	token := e2eLogin(t)
	_, taskID := e2eCreateStrategyAndTask(t, token, "e2e-initseq", "tcp", map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
		"src_port": 60030, "dst_port": 80,
		"initial_seq": 0x12345678,
	})
	stop := e2eStartCapture(t, "tcp")
	e2eAPI(t, token, "POST", "/api/v1/tasks/"+taskID+"/start", nil)
	time.Sleep(2 * time.Second)
	pcapPath := stop()
	pkts := e2eReadPcap(t, pcapPath)
	_, tcp := e2eFindSyn(pkts)
	if tcp == nil {
		t.Fatal("no SYN found")
	}
	if tcp.Seq != 0x12345678 {
		t.Errorf("SYN Seq = 0x%x, want 0x12345678 (user override)", tcp.Seq)
	}
	t.Logf("SYN Seq = 0x%x (user override, OK)", tcp.Seq)
}

// keep imports used
var (
	_ = sync.Mutex{}
	_ = exec.Command
)
