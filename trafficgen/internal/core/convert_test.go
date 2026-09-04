package core

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestValidateFlowSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    FlowSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: false,
		},
		{
			name: "invalid src IP",
			spec: FlowSpec{
				SrcIP:   "invalid",
				DstIP:   "192.168.1.2",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid dst IP",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "invalid",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid src MAC",
			spec: FlowSpec{
				SrcIP:   "192.168.1.1",
				DstIP:   "192.168.1.2",
				SrcMAC:  "invalid",
				SrcPort: 12345,
				DstPort: 80,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlowSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFlowSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTask(t *testing.T) {
	tests := []struct {
		name    string
		task    Task
		wantErr bool
	}{
		{
			name: "valid task",
			task: Task{
				Name:     "test task",
				Protocol: "tcp",
				Spec: FlowSpec{
					SrcIP:   "192.168.1.1",
					DstIP:   "192.168.1.2",
					SrcPort: 12345,
					DstPort: 80,
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			task: Task{
				Protocol: "tcp",
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			task: Task{
				Name:     "test",
				Protocol: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTask(tt.task)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTask() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateFlowSpec_VLANIDZeroWarns verifies that a VLAN ID of 0 does
// not fail validation (it is a valid 802.1Q priority-tag construct) but is
// surfaced as a warning so users learn that VID 0 is a priority tag, not a
// real VLAN. The test asserts only that Validate returns nil (warn, not
// error); the warning itself is observable via zap and is not asserted here.
func TestValidateFlowSpec_VLANIDZeroWarns(t *testing.T) {
	spec := FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		VLAN:    &VLAN{ID: 0, Priority: 5},
	}
	if err := ValidateFlowSpec(spec); err != nil {
		t.Fatalf("ValidateFlowSpec() with vlan.id=0: expected no error (warn only), got %v", err)
	}
}

// TestValidateFlowSpec_VLANIDZeroNoPointer verifies that vlan.id==0 inside
// a nil VLAN pointer does not trigger the warning path. The 802.1Q warning
// is specific to an explicitly configured VLAN tag with VID 0.
func TestValidateFlowSpec_VLANNilNoWarn(t *testing.T) {
	spec := FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
		// VLAN is nil -- no warning path should execute.
	}
	if err := ValidateFlowSpec(spec); err != nil {
		t.Fatalf("ValidateFlowSpec() with nil VLAN: expected no error, got %v", err)
	}
}

func TestParseBPS(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"100", 100, false},
		{"1k", 1000, false},
		{"1K", 1000, false},
		{"1m", 1000000, false},
		{"1M", 1000000, false},
		{"1g", 1000000000, false},
		{"1G", 1000000000, false},
		{"200k", 200000, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseBPS(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBPS() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseBPS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIRequestToTask(t *testing.T) {
	task := APIRequestToTask("test", "description", "tcp", FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 80,
	}, "eth0")

	if task.Name != "test" {
		t.Errorf("Name = %s, want test", task.Name)
	}
	if task.Protocol != "tcp" {
		t.Errorf("Protocol = %s, want tcp", task.Protocol)
	}
	if task.Interface != "eth0" {
		t.Errorf("Interface = %s, want eth0", task.Interface)
	}
	if task.ID == "" {
		t.Error("ID should not be empty")
	}
}

// TestValidateBatchSpec_DuplicateClassID verifies duplicate class IDs are
// rejected (previously they collided on the rate-limiter key and config
// ClassID, breaking per-class rate isolation).
func TestValidateBatchSpec_DuplicateClassID(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{
		{ID: "a", Type: "tcp", FlowCount: 1,
			Config: map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}},
		{ID: "a", Type: "tcp", FlowCount: 1,
			Config: map[string]interface{}{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}},
	}}
	err := ValidateBatchSpec(batch)
	if err == nil {
		t.Fatal("expected error for duplicate class id, got nil")
	}
}

// TestValidateConfigRanges_TruncationBypass verifies out-of-range DSCP/ECN/VLAN
// values are rejected based on the raw int, not the truncated uint8/uint16.
// Previously dscp=256 silently wrapped to 0 (valid) via uint8(256).
func TestValidateConfigRanges_TruncationBypass(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"dscp 256 wraps to 0", map[string]interface{}{"dscp": float64(256)}},
		{"ecn 4", map[string]interface{}{"ecn": float64(4)}},
		{"vlan_id 65536 wraps to 0", map[string]interface{}{"vlan_id": float64(65536)}},
		{"vlan_priority 8", map[string]interface{}{"vlan_priority": float64(8)}},
		{"flags 8 wraps", map[string]interface{}{"flags": float64(8)}},
		{"frag_offset 9000 out of 13-bit", map[string]interface{}{"frag_offset": float64(9000)}},
		{"ttl 256 wraps to 0", map[string]interface{}{"ttl": float64(256)}},
		{"tos 256 wraps to 0", map[string]interface{}{"tos": float64(256)}},
		{"dscp -1 wraps to 255", map[string]interface{}{"dscp": float64(-1)}},
		{"vlan_id -1", map[string]interface{}{"vlan_id": float64(-1)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateConfigRanges(c.cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
		})
	}
	// Valid values must still pass (including 0 = default for ttl/flags/frag).
	valid := map[string]interface{}{"dscp": float64(46), "ecn": float64(0), "vlan_id": float64(100),
		"flags": float64(2), "frag_offset": float64(0), "ttl": float64(0), "tos": float64(0)}
	if err := ValidateConfigRanges(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// TestValidateBatchSpec_AllProtocols verifies the whitelist covers every
// protocol planner registered in internal/protocol/. Previously the whitelist
// in ValidateBatchSpec only listed 11 base protocols, so all 25 L7 planners
// (ssh, telnet, rdp, redis, ntp, snmp, syslog, smtp, pop3, imap, mysql,
// postgresql, ike, ike_nat_t, l2tp, tls, openvpn, shadowsocks, vmess,
// wireguard, dhcp, dhcpv6, mdns, ssdp, grpc) were rejected with
// "invalid type" despite having planners on disk and being registered with
// the engine.
func TestValidateBatchSpec_AllProtocols(t *testing.T) {
	// All 38 planners registered in cmd/server/main.go.
	allProtocols := []string{
		"tcp", "udp", "http", "dns", "icmp", "arp", "ftp", "sip", "sctp", "icmpv6",
		"replay",
		"ntp", "snmp", "syslog", "smtp", "pop3", "telnet", "imap", "grpc",
		"ssh", "ike", "ike_nat_t", "l2tp", "rdp", "redis", "mysql", "postgresql",
		"tls", "openvpn", "shadowsocks", "vmess", "wireguard", "dhcp", "dhcpv6",
		"mdns", "ssdp", "pppoe", "gre", "mpls", "gtp", "socks5", "radius", "ldap", "vnc",
		"pptp",
	}
	for _, proto := range allProtocols {
		t.Run(proto, func(t *testing.T) {
			class := TrafficClass{
				ID:        proto + "-1",
				Type:      proto,
				FlowCount: 1,
				Config:    map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"},
			}
			// Replay classes need a non-empty Replay field (the planner
			// unmarshals this JSON into its ReplaySpec); all other classes
			// leave Replay nil.
			if proto == "replay" {
				class.Replay = json.RawMessage(`{"pcap_asset_id":"x","speed":{"mode":"original"},"direction":"single","checksum_mode":"recompute"}`)
				// Replay skips FlowSpec validation; reset the placeholder so
				// downstream asserts don't trip on a 0 FlowCount.
				class.FlowCount = 0
			}
			if err := ValidateBatchSpec(BatchSpec{Classes: []TrafficClass{class}}); err != nil {
				t.Fatalf("protocol %q rejected by ValidateBatchSpec: %v", proto, err)
			}
		})
	}
}

// TestMapToFlowSpec_SSDP_NextBootID_SearchPort verifies the SSDP converter
// (parseSSDPConfig) wires the next_boot_id and search_port JSON fields into
// the SSDPConfig struct. This is a regression guard for a real bug found via
// NIC testing: the planner emitted NEXTBOOTID.UPNP.ORG / SEARCHPORT.UPNP.ORG
// headers only when NextBootID>0 / SearchPort>0, but the converter never
// populated those fields (they stayed zero-valued), so the planner conditions
// were never true and the headers were silently dropped.
func TestMapToFlowSpec_SSDP_NextBootID_SearchPort(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"ssdp": map[string]interface{}{
			"message_type": "update",
			"boot_id":      float64(2),
			"config_id":    float64(3),
			"next_boot_id": float64(5),
			"search_port":  float64(49152),
		},
	}
	spec := mapToFlowSpec(raw, "ssdp")
	if spec.SSDP == nil {
		t.Fatalf("spec.SSDP is nil")
	}
	if spec.SSDP.NextBootID != 5 {
		t.Errorf("NextBootID = %d, want 5 (next_boot_id not wired)", spec.SSDP.NextBootID)
	}
	if spec.SSDP.SearchPort != 49152 {
		t.Errorf("SearchPort = %d, want 49152 (search_port not wired)", spec.SSDP.SearchPort)
	}
	// BootID/ConfigID were already wired; guard against regression.
	if spec.SSDP.BootID != 2 {
		t.Errorf("BootID = %d, want 2", spec.SSDP.BootID)
	}
	if spec.SSDP.ConfigID != 3 {
		t.Errorf("ConfigID = %d, want 3", spec.SSDP.ConfigID)
	}
}

// TestMapToFlowSpec_ICMPv6_FileSource verifies the ICMPv6 converter wires
// the file_source sub-map into ICMPv6Config.FileSource. This is a regression
// guard for a real bug found via NIC testing: the ICMPv6 planner was fixed to
// resolve FileSource (mirroring ICMPv4), but the converter never populated
// spec.ICMPv6.FileSource, so the FileSource was silently dropped — the task
// completed but echo data fell back to default/inline instead of the file
// bytes.
func TestMapToFlowSpec_ICMPv6_FileSource(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"icmpv6": map[string]interface{}{
			"type": float64(128),
			"file_source": map[string]interface{}{
				"literal": "FS-V6-LITERAL",
			},
		},
	}
	spec := mapToFlowSpec(raw, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatalf("spec.ICMPv6 is nil")
	}
	if spec.ICMPv6.FileSource == nil {
		t.Fatalf("ICMPv6.FileSource is nil (file_source not wired for icmpv6)")
	}
	if spec.ICMPv6.FileSource.Literal == "" {
		t.Fatalf("ICMPv6.FileSource.Literal is empty (file_source parsed but Literal dropped)")
	}
	if spec.ICMPv6.FileSource.Literal != "FS-V6-LITERAL" {
		t.Errorf("ICMPv6.FileSource.Literal = %q, want %q", spec.ICMPv6.FileSource.Literal, "FS-V6-LITERAL")
	}
}

// TestMapToFlowSpec_ICMPv6_FileSourcePrecedenceOverInline verifies that when
// both inline data and file_source are set, both are surfaced (the planner,
// not the converter, decides precedence — the planner lets FileSource win).
// The converter must populate BOTH so the planner has the choice.
func TestMapToFlowSpec_ICMPv6_FileSourcePrecedenceOverInline(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"icmpv6": map[string]interface{}{
			"data": "FROM-INLINE-DATA",
			"file_source": map[string]interface{}{
				"literal": "FROM-FILESOURCE",
			},
		},
	}
	spec := mapToFlowSpec(raw, "icmpv6")
	if spec.ICMPv6 == nil {
		t.Fatalf("spec.ICMPv6 is nil")
	}
	if spec.ICMPv6.FileSource == nil {
		t.Fatalf("ICMPv6.FileSource is nil (file_source not wired when data also set)")
	}
	if spec.ICMPv6.FileSource.Literal != "FROM-FILESOURCE" {
		t.Errorf("FileSource.Literal = %q, want FROM-FILESOURCE", spec.ICMPv6.FileSource.Literal)
	}
	if string(spec.ICMPv6.Data) != "FROM-INLINE-DATA" {
		t.Errorf("Data = %q, want FROM-INLINE-DATA", string(spec.ICMPv6.Data))
	}
}

// TestMapToFlowSpec_POP3_MIMEParts verifies the POP3 converter wires
// mime_parts (including body_b64 and per-part headers) and boundary into
// the POP3Message. Regression guard: these fields were added for MIME
// multipart support (RFC 2046); if the converter drops them the planner
// silently falls back to the simple Body path and no multipart output
// appears on the wire.
func TestMapToFlowSpec_POP3_MIMEParts(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pop3": map[string]interface{}{
			"commands": []interface{}{
				map[string]interface{}{
					"cmd":            "RETR 1",
					"emit_mail_drop": true,
					"msg_num":        float64(1),
					"emit_top":       false,
					"top_lines":      float64(0),
				},
			},
			"mailbox": map[string]interface{}{
				"messages": []interface{}{
					map[string]interface{}{
						"uid":      "u1",
						"boundary": "MB",
						"headers":  []interface{}{"From: a@b.com"},
						"mime_parts": []interface{}{
							map[string]interface{}{
								"headers": []interface{}{"Content-Type: text/plain"},
								"body":    "Hello",
							},
							map[string]interface{}{
								"headers": []interface{}{
									"Content-Type: application/octet-stream",
									"Content-Transfer-Encoding: base64",
									`Content-Disposition: attachment; filename="x.bin"`,
								},
								"body_b64": "SGVsbG8=",
							},
						},
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "pop3")
	if spec.POP3 == nil {
		t.Fatalf("spec.POP3 is nil")
	}
	if spec.POP3.Mailbox == nil || len(spec.POP3.Mailbox.Messages) != 1 {
		t.Fatalf("Mailbox.Messages wrong")
	}
	msg := spec.POP3.Mailbox.Messages[0]
	if msg.Boundary != "MB" {
		t.Errorf("Boundary = %q, want MB", msg.Boundary)
	}
	if len(msg.MIMEParts) != 2 {
		t.Fatalf("MIMEParts len = %d, want 2", len(msg.MIMEParts))
	}
	// Part 1: text body.
	if msg.MIMEParts[0].Body != "Hello" {
		t.Errorf("part[0].Body = %q, want Hello", msg.MIMEParts[0].Body)
	}
	if len(msg.MIMEParts[0].Headers) != 1 || msg.MIMEParts[0].Headers[0] != "Content-Type: text/plain" {
		t.Errorf("part[0].Headers wrong: %v", msg.MIMEParts[0].Headers)
	}
	// Part 2: base64 attachment.
	if msg.MIMEParts[1].BodyB64 != "SGVsbG8=" {
		t.Errorf("part[1].BodyB64 = %q, want SGVsbG8=", msg.MIMEParts[1].BodyB64)
	}
	if len(msg.MIMEParts[1].Headers) != 3 {
		t.Errorf("part[1].Headers len = %d, want 3", len(msg.MIMEParts[1].Headers))
	}
	// EmitTop / TopLines wired.
	if len(spec.POP3.Commands) != 1 {
		t.Fatalf("Commands len wrong")
	}
	if spec.POP3.Commands[0].EmitMailDrop != true {
		t.Errorf("EmitMailDrop not wired")
	}
	if spec.POP3.Commands[0].MsgNum != 1 {
		t.Errorf("MsgNum = %d, want 1", spec.POP3.Commands[0].MsgNum)
	}
}

// TestMapToFlowSpec_SMTP_Email verifies the JSON-decoded "email" sub-map
// is parsed into *SMTPEmail with Headers, TextBody, HTMLBody, Boundary,
// and Attachments (each with Data/DataB64).
func TestMapToFlowSpec_SMTP_Email(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"smtp": map[string]interface{}{
			"banner": "220 mail.example.org ESMTP",
			"email": map[string]interface{}{
				"headers":   []interface{}{"From: a@b.com", "Subject: Test"},
				"text_body": "plain text",
				"html_body": "<p>html</p>",
				"boundary":  "MYBOUND",
				"attachments": []interface{}{
					map[string]interface{}{
						"filename":     "x.bin",
						"content_type": "application/octet-stream",
						"data":         "raw bytes",
					},
					map[string]interface{}{
						"filename": "y.bin",
						"data_b64": "SGVsbG8=",
					},
				},
			},
			"dialog": []interface{}{
				map[string]interface{}{"cmd": "HELO client", "response": "250 ok"},
			},
		},
	}
	spec := mapToFlowSpec(raw, "smtp")
	if spec.SMTP == nil {
		t.Fatalf("spec.SMTP is nil")
	}
	if spec.SMTP.Banner != "220 mail.example.org ESMTP" {
		t.Errorf("Banner = %q", spec.SMTP.Banner)
	}
	if spec.SMTP.Email == nil {
		t.Fatalf("Email is nil")
	}
	email := spec.SMTP.Email
	if len(email.Headers) != 2 || email.Headers[0] != "From: a@b.com" {
		t.Errorf("Headers wrong: %v", email.Headers)
	}
	if email.TextBody != "plain text" {
		t.Errorf("TextBody = %q", email.TextBody)
	}
	if email.HTMLBody != "<p>html</p>" {
		t.Errorf("HTMLBody = %q", email.HTMLBody)
	}
	if email.Boundary != "MYBOUND" {
		t.Errorf("Boundary = %q, want MYBOUND", email.Boundary)
	}
	if len(email.Attachments) != 2 {
		t.Fatalf("Attachments len = %d, want 2", len(email.Attachments))
	}
	att0 := email.Attachments[0]
	if att0.Filename != "x.bin" {
		t.Errorf("att[0].Filename = %q", att0.Filename)
	}
	if att0.ContentType != "application/octet-stream" {
		t.Errorf("att[0].ContentType = %q", att0.ContentType)
	}
	if string(att0.Data) != "raw bytes" {
		t.Errorf("att[0].Data = %q, want 'raw bytes'", att0.Data)
	}
	att1 := email.Attachments[1]
	if att1.Filename != "y.bin" {
		t.Errorf("att[1].Filename = %q", att1.Filename)
	}
	if att1.DataB64 != "SGVsbG8=" {
		t.Errorf("att[1].DataB64 = %q", att1.DataB64)
	}
	// Dialog still wired.
	if len(spec.SMTP.Dialog) != 1 || spec.SMTP.Dialog[0].Cmd != "HELO client" {
		t.Errorf("Dialog wrong: %v", spec.SMTP.Dialog)
	}
}

// TestMapToFlowSpec_SMTP_EmailAbsent verifies that when the "email"
// sub-map is absent, Email is nil (backward-compatible Dialog-only
// path).
func TestMapToFlowSpec_SMTP_EmailAbsent(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"smtp": map[string]interface{}{
			"banner": "220 x",
			"dialog": []interface{}{
				map[string]interface{}{"cmd": "HELO c", "response": "250 ok"},
			},
		},
	}
	spec := mapToFlowSpec(raw, "smtp")
	if spec.SMTP == nil {
		t.Fatalf("spec.SMTP is nil")
	}
	if spec.SMTP.Email != nil {
		t.Errorf("Email should be nil when absent, got %+v", spec.SMTP.Email)
	}
	if len(spec.SMTP.Dialog) != 1 {
		t.Errorf("Dialog should still parse, got %v", spec.SMTP.Dialog)
	}
}

// TestMapToFlowSpec_L2TP_TunnelWithData verifies the JSON-decoded "l2tp"
// sub-map with scenario="tunnel_with_data" and inner_ip is parsed into
// *L2TPConfig with Scenario + InnerIP (SrcIP/DstIP/Proto/SrcPort/DstPort/
// TTL/Payload/DataFrames). Regression guard: these fields were added for
// the dual-IP encapsulation scenario (RFC 2661 + RFC 1661 §6 + RFC 791);
// if the converter drops them the planner silently falls back to manual
// Scenarios/PPPFrames mode and emits no inner-IPv4 traffic.
func TestMapToFlowSpec_L2TP_TunnelWithData(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"l2tp": map[string]interface{}{
			"version":  float64(2),
			"role":     "lac",
			"scenario": "tunnel_with_data",
			"inner_ip": map[string]interface{}{
				"src_ip":      "10.10.10.1",
				"dst_ip":      "10.10.10.2",
				"proto":       float64(17),
				"src_port":    float64(5000),
				"dst_port":    float64(8080),
				"ttl":         float64(64),
				"payload":     "aGVsbG8=", // base64 "hello"
				"data_frames": float64(3),
			},
		},
	}
	spec := mapToFlowSpec(raw, "l2tp")
	if spec.L2TP == nil {
		t.Fatalf("spec.L2TP is nil")
	}
	if spec.L2TP.Scenario != "tunnel_with_data" {
		t.Errorf("Scenario = %q, want tunnel_with_data", spec.L2TP.Scenario)
	}
	if spec.L2TP.InnerIP == nil {
		t.Fatalf("InnerIP is nil")
	}
	ip := spec.L2TP.InnerIP
	if ip.SrcIP != "10.10.10.1" {
		t.Errorf("InnerIP.SrcIP = %q, want 10.10.10.1", ip.SrcIP)
	}
	if ip.DstIP != "10.10.10.2" {
		t.Errorf("InnerIP.DstIP = %q, want 10.10.10.2", ip.DstIP)
	}
	if ip.Proto != 17 {
		t.Errorf("InnerIP.Proto = %d, want 17 (UDP)", ip.Proto)
	}
	if ip.SrcPort != 5000 {
		t.Errorf("InnerIP.SrcPort = %d, want 5000", ip.SrcPort)
	}
	if ip.DstPort != 8080 {
		t.Errorf("InnerIP.DstPort = %d, want 8080", ip.DstPort)
	}
	if ip.TTL != 64 {
		t.Errorf("InnerIP.TTL = %d, want 64", ip.TTL)
	}
	if ip.DataFrames != 3 {
		t.Errorf("InnerIP.DataFrames = %d, want 3", ip.DataFrames)
	}
	// payload field maps to getByteSlice which interprets string as raw
	// bytes (NOT base64). Use a byte array for base64-style payloads.
	wantPayload := []byte("aGVsbG8=")
	if string(ip.Payload) != string(wantPayload) {
		t.Errorf("InnerIP.Payload = %q, want %q", ip.Payload, wantPayload)
	}
	// Default port wiring: L2TP 目的端口 1701 由 ChainPlanner.ValidateSpec
	// 的 DstPort switch 在 Plan 时补齐（T2.4 起 mapToFlowSpec 不再设置）——
	// 端口默认行为由 layers/flat_dstport_default_test.go 锁定。
}

// TestMapToFlowSpec_L2TP_TunnelWithData_Defaults verifies that when
// inner_ip is omitted, Scenario is still wired and InnerIP is nil (the
// planner synthesizes defaults at Plan time).
func TestMapToFlowSpec_L2TP_TunnelWithData_Defaults(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"l2tp": map[string]interface{}{
			"scenario": "tunnel_with_data",
		},
	}
	spec := mapToFlowSpec(raw, "l2tp")
	if spec.L2TP == nil {
		t.Fatalf("spec.L2TP is nil")
	}
	if spec.L2TP.Scenario != "tunnel_with_data" {
		t.Errorf("Scenario = %q, want tunnel_with_data", spec.L2TP.Scenario)
	}
	if spec.L2TP.InnerIP != nil {
		t.Errorf("InnerIP should be nil when omitted, got %+v", spec.L2TP.InnerIP)
	}
}

// TestMapToFlowSpec_PPPoE verifies the JSON-decoded "pppoe" sub-map is
// parsed into *PPPoEConfig. The wire-level fields (code/session_id/
// ppp_protocol/payload_length/discovery_tags) feed the builder for
// single-frame crafting; the session-level fields (skip_discovery/
// ac_name/service_name/cookie/mru/magic_number/auth/username/password/
// data_frames/data_payload/inner_proto/data_direction) drive the
// internal/protocol/pppoe planner. If the converter drops them, the
// planner silently falls back to defaults and emits a different session.
func TestMapToFlowSpec_PPPoE(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"pppoe": map[string]interface{}{
			"code":           float64(0),
			"session_id":     float64(15),
			"ppp_protocol":   float64(0xc021),
			"payload_length": float64(0x0010),
			"skip_discovery": true,
			"ac_name":        "bras1",
			"service_name":   "isp",
			"cookie":         []interface{}{float64(0xde), float64(0xad), float64(0xbe), float64(0xef)},
			"mru":            float64(1492),
			"magic_number":   float64(0x09e5f145),
			"auth":           "pap",
			"username":       "alice",
			"password":       "s3cret",
			"data_frames":    float64(3),
			"data_payload":   "hello",
			"inner_proto":    float64(6),
			"data_direction": "down",
			"discovery_tags": []interface{}{
				map[string]interface{}{"type": float64(0x0101), "value": "isp"},
				map[string]interface{}{"type": float64(0x0104), "value": []interface{}{float64(1), float64(2)}},
			},
		},
	}
	spec := mapToFlowSpec(raw, "pppoe")
	if spec.PPPoE == nil {
		t.Fatalf("spec.PPPoE is nil")
	}
	cfg := spec.PPPoE
	if cfg.Code != 0 || cfg.SessionID != 15 || cfg.PPPProtocol != 0xc021 || cfg.PayloadLength != 0x0010 {
		t.Errorf("wire fields = code %d session %d proto 0x%04x len %d, want 0/15/0xc021/0x0010",
			cfg.Code, cfg.SessionID, cfg.PPPProtocol, cfg.PayloadLength)
	}
	if !cfg.SkipDiscovery {
		t.Errorf("SkipDiscovery = false, want true")
	}
	if cfg.ACName != "bras1" || cfg.ServiceName != "isp" {
		t.Errorf("ACName/ServiceName = %q/%q, want bras1/isp", cfg.ACName, cfg.ServiceName)
	}
	if !bytes.Equal(cfg.Cookie, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("Cookie = % x, want de ad be ef", cfg.Cookie)
	}
	if cfg.MRU != 1492 || cfg.MagicNumber != 0x09e5f145 {
		t.Errorf("MRU/MagicNumber = %d/0x%08x, want 1492/0x09e5f145", cfg.MRU, cfg.MagicNumber)
	}
	if cfg.Auth != "pap" || cfg.Username != "alice" || cfg.Password != "s3cret" {
		t.Errorf("Auth/Username/Password = %q/%q/%q, want pap/alice/s3cret", cfg.Auth, cfg.Username, cfg.Password)
	}
	if cfg.DataFrames != 3 || string(cfg.DataPayload) != "hello" || cfg.InnerProto != 6 || cfg.DataDirection != "down" {
		t.Errorf("data plane = frames %d payload %q proto %d dir %q, want 3/hello/6/down",
			cfg.DataFrames, cfg.DataPayload, cfg.InnerProto, cfg.DataDirection)
	}
	if len(cfg.DiscoveryTags) != 2 {
		t.Fatalf("DiscoveryTags = %d entries, want 2", len(cfg.DiscoveryTags))
	}
	if cfg.DiscoveryTags[0].Type != 0x0101 || string(cfg.DiscoveryTags[0].Value) != "isp" {
		t.Errorf("DiscoveryTags[0] = %+v, want Service-Name \"isp\"", cfg.DiscoveryTags[0])
	}
	if cfg.DiscoveryTags[1].Type != 0x0104 || !bytes.Equal(cfg.DiscoveryTags[1].Value, []byte{1, 2}) {
		t.Errorf("DiscoveryTags[1] = %+v, want AC-Cookie [1 2]", cfg.DiscoveryTags[1])
	}
}

// TestMapToFlowSpec_PPPoE_Absent verifies "pppoe" is nil when the sub-map
// is absent (no accidental zero-value pointer).
func TestMapToFlowSpec_PPPoE_Absent(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"}, "pppoe")
	if spec.PPPoE != nil {
		t.Errorf("spec.PPPoE = %+v, want nil when pppoe absent", spec.PPPoE)
	}
}

// TestMapToFlowSpec_GRE verifies the JSON-decoded "gre" sub-map is parsed
// into *GREConfig. The wire-level fields (protocol_type/checksum/
// key_present/key/sequence_present/sequence/routing_present/routing) feed
// the builder's GRE header; the tunnel-level fields (inner_src_ip/
// inner_dst_ip/inner_proto/inner_ttl/inner_ipid/inner_payload/tcp_options/
// frames/direction) drive the internal/protocol/gre planner. If the
// converter drops them, the planner silently falls back to defaults and
// emits a different tunnel.
func TestMapToFlowSpec_GRE(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"gre": map[string]interface{}{
			"protocol_type":    float64(0x0806),
			"checksum":         true,
			"key_present":      true,
			"key":              float64(0xdeadbeef),
			"sequence_present": true,
			"sequence":         float64(7),
			"routing_present":  true,
			"routing":          []interface{}{float64(0x00), float64(0x01), float64(0x02), float64(0x03)},
			"inner_src_ip":     "192.168.1.1",
			"inner_dst_ip":     "192.168.1.2",
			"inner_proto":      float64(6),
			"inner_ttl":        float64(32),
			"inner_ipid":       float64(0x1234),
			"inner_payload":    "hello",
			"tcp_options": []interface{}{
				map[string]interface{}{"kind": float64(2), "data": []interface{}{float64(0x05), float64(0xb4)}},
			},
			"frames":    float64(3),
			"direction": "down",
		},
	}
	spec := mapToFlowSpec(raw, "gre")
	if spec.GRE == nil {
		t.Fatalf("spec.GRE is nil")
	}
	cfg := spec.GRE
	if cfg.ProtocolType != 0x0806 || !cfg.Checksum || !cfg.KeyPresent || cfg.Key != 0xdeadbeef {
		t.Errorf("wire flags = proto 0x%04x checksum %v key %v/0x%08x, want 0x0806/true/true/0xdeadbeef",
			cfg.ProtocolType, cfg.Checksum, cfg.KeyPresent, cfg.Key)
	}
	if !cfg.SequencePresent || cfg.Sequence != 7 || !cfg.RoutingPresent || !bytes.Equal(cfg.Routing, []byte{0, 1, 2, 3}) {
		t.Errorf("seq/routing = present %v/%v seq %d routing % x, want true/true/7/00 01 02 03",
			cfg.SequencePresent, cfg.RoutingPresent, cfg.Sequence, cfg.Routing)
	}
	if cfg.InnerSrcIP != "192.168.1.1" || cfg.InnerDstIP != "192.168.1.2" || cfg.InnerProto != 6 {
		t.Errorf("inner = %s/%s proto %d, want 192.168.1.1/192.168.1.2/6",
			cfg.InnerSrcIP, cfg.InnerDstIP, cfg.InnerProto)
	}
	if cfg.InnerTTL != 32 || cfg.InnerIPID != 0x1234 || string(cfg.InnerPayload) != "hello" {
		t.Errorf("inner packet = ttl %d ipid 0x%04x payload %q, want 32/0x1234/hello",
			cfg.InnerTTL, cfg.InnerIPID, cfg.InnerPayload)
	}
	if len(cfg.TCPOptions) != 1 || cfg.TCPOptions[0].Kind != 2 || !bytes.Equal(cfg.TCPOptions[0].Data, []byte{0x05, 0xb4}) {
		t.Errorf("TCPOptions = %+v, want single MSS 0x05b4 option", cfg.TCPOptions)
	}
	if cfg.Frames != 3 || cfg.Direction != "down" {
		t.Errorf("Frames/Direction = %d/%q, want 3/down", cfg.Frames, cfg.Direction)
	}
}

// TestMapToFlowSpec_GRE_Absent verifies "gre" is nil when the sub-map is
// absent (no accidental zero-value pointer).
func TestMapToFlowSpec_GRE_Absent(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"}, "gre")
	if spec.GRE != nil {
		t.Errorf("spec.GRE = %+v, want nil when gre absent", spec.GRE)
	}
}

// TestMapToFlowSpec_MPLS verifies the JSON-decoded "mpls" sub-map is parsed
// into *MPLSConfig. The wire-level fields (labels/multicast) feed the
// builder's label-stack emission; the tunnel-level fields (inner_proto/
// inner_payload/frames/direction) drive the internal/protocol/mpls planner.
// If the converter drops them, the planner silently falls back to defaults
// and emits a different LSP data plane.
func TestMapToFlowSpec_MPLS(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"mpls": map[string]interface{}{
			"labels": []interface{}{
				map[string]interface{}{"label": float64(16), "tc": float64(6), "s": true, "ttl": float64(255)},
				map[string]interface{}{"label": float64(2859), "ttl": float64(200)},
			},
			"multicast":     true,
			"inner_proto":   float64(6),
			"inner_payload": "hello",
			"frames":        float64(3),
			"direction":     "down",
		},
	}
	spec := mapToFlowSpec(raw, "mpls")
	if spec.MPLS == nil {
		t.Fatalf("spec.MPLS is nil")
	}
	cfg := spec.MPLS
	if !cfg.Multicast {
		t.Errorf("Multicast = false, want true")
	}
	if len(cfg.Labels) != 2 {
		t.Fatalf("Labels = %d entries, want 2", len(cfg.Labels))
	}
	if cfg.Labels[0].Label != 16 || cfg.Labels[0].TC != 6 || !cfg.Labels[0].S || cfg.Labels[0].TTL != 255 {
		t.Errorf("Labels[0] = %+v, want label 16 TC 6 S true TTL 255", cfg.Labels[0])
	}
	if cfg.Labels[1].Label != 2859 || cfg.Labels[1].S || cfg.Labels[1].TTL != 200 {
		t.Errorf("Labels[1] = %+v, want label 2859 S false TTL 200", cfg.Labels[1])
	}
	if cfg.InnerProto != 6 || string(cfg.InnerPayload) != "hello" || cfg.Frames != 3 || cfg.Direction != "down" {
		t.Errorf("tunnel fields = proto %d payload %q frames %d dir %q, want 6/hello/3/down",
			cfg.InnerProto, cfg.InnerPayload, cfg.Frames, cfg.Direction)
	}
}

// TestMapToFlowSpec_MPLS_Absent verifies "mpls" is nil when the sub-map is
// absent (no accidental zero-value pointer).
func TestMapToFlowSpec_MPLS_Absent(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"}, "mpls")
	if spec.MPLS != nil {
		t.Errorf("spec.MPLS = %+v, want nil when mpls absent", spec.MPLS)
	}
}

// TestMapToFlowSpec_GTP verifies the JSON-decoded "gtp" sub-map is parsed
// into *GTPConfig. The wire-level fields (mode/version/pt/teid/sequence_
// present/sequence/npdu_present/npdu_value/extension_present/extension_
// type/extension_data) drive the GTPv1 message header (TS 29.281 §5.1);
// the scenario steps and IEs drive the GTP-C dialog; the tunnel-level
// fields (inner_src_ip/inner_dst_ip/inner_proto/inner_ttl/inner_ipid/
// inner_payload/tcp_options/frames/direction) drive the GTP-U T-PDU inner
// packet construction in internal/protocol/gtp. If the converter drops
// them, the planner silently falls back to defaults and emits a different
// tunnel.
func TestMapToFlowSpec_GTP(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"gtp": map[string]interface{}{
			"mode":              "c",
			"version":           float64(1),
			"pt":                float64(1),
			"teid":              float64(0x002dc715),
			"sequence_present":  true,
			"sequence":          float64(0x5ee5),
			"npdu_present":      true,
			"npdu_value":        float64(0x77),
			"extension_present": true,
			"extension_type":    float64(0x40),
			"extension_data":    []interface{}{float64(0xaa), float64(0xbb)},
			"scenarios": []interface{}{
				map[string]interface{}{
					"message_type":  float64(0x01),
					"teid_override": float64(0x1234),
					"sequence":      float64(10),
					"direction":     "down",
					"ies": []interface{}{
						map[string]interface{}{"type": float64(0x0e), "value": []interface{}{float64(0x80)}},
					},
				},
			},
			"inner_src_ip":  "192.168.1.1",
			"inner_dst_ip":  "192.168.1.2",
			"inner_proto":   float64(6),
			"inner_ttl":     float64(32),
			"inner_ipid":    float64(0x1234),
			"inner_payload": "hello",
			"tcp_options": []interface{}{
				map[string]interface{}{"kind": float64(2), "data": []interface{}{float64(0x05), float64(0xb4)}},
			},
			"frames":    float64(3),
			"direction": "down",
		},
	}
	spec := mapToFlowSpec(raw, "gtp")
	if spec.GTP == nil {
		t.Fatalf("spec.GTP is nil")
	}
	cfg := spec.GTP
	if cfg.Mode != "c" || cfg.Version != 1 || cfg.PT != 1 || cfg.TEID != 0x002dc715 {
		t.Errorf("header fields = mode %q ver %d pt %d teid 0x%08x, want c/1/1/0x002dc715",
			cfg.Mode, cfg.Version, cfg.PT, cfg.TEID)
	}
	if !cfg.SequencePresent || cfg.Sequence != 0x5ee5 || !cfg.NPDUPresent || cfg.NPDUValue != 0x77 {
		t.Errorf("optional flags = seq %v/%d npdu %v/%d, want true/0x5ee5/true/0x77",
			cfg.SequencePresent, cfg.Sequence, cfg.NPDUPresent, cfg.NPDUValue)
	}
	if !cfg.ExtensionPresent || cfg.ExtensionType != 0x40 || !bytes.Equal(cfg.ExtensionData, []byte{0xaa, 0xbb}) {
		t.Errorf("extension = %v/%d/% x, want true/0x40/aa bb",
			cfg.ExtensionPresent, cfg.ExtensionType, cfg.ExtensionData)
	}
	if len(cfg.Scenarios) != 1 {
		t.Fatalf("Scenarios = %d entries, want 1", len(cfg.Scenarios))
	}
	step := cfg.Scenarios[0]
	if step.MessageType != 0x01 || step.TEIDOverride == nil || *step.TEIDOverride != 0x1234 ||
		step.Sequence != 10 || step.Direction != "down" {
		t.Errorf("step = %+v, want type 1 teid override 0x1234 seq 10 dir down", step)
	}
	if len(step.IEs) != 1 || step.IEs[0].Type != 0x0e || !bytes.Equal(step.IEs[0].Value, []byte{0x80}) {
		t.Errorf("step IEs = %+v, want single Recovery 0x80 IE", step.IEs)
	}
	if cfg.InnerSrcIP != "192.168.1.1" || cfg.InnerDstIP != "192.168.1.2" || cfg.InnerProto != 6 {
		t.Errorf("inner = %s/%s proto %d, want 192.168.1.1/192.168.1.2/6",
			cfg.InnerSrcIP, cfg.InnerDstIP, cfg.InnerProto)
	}
	if cfg.InnerTTL != 32 || cfg.InnerIPID != 0x1234 || string(cfg.InnerPayload) != "hello" {
		t.Errorf("inner packet = ttl %d ipid 0x%04x payload %q, want 32/0x1234/hello",
			cfg.InnerTTL, cfg.InnerIPID, cfg.InnerPayload)
	}
	if len(cfg.TCPOptions) != 1 || cfg.TCPOptions[0].Kind != 2 || !bytes.Equal(cfg.TCPOptions[0].Data, []byte{0x05, 0xb4}) {
		t.Errorf("TCPOptions = %+v, want single MSS 0x05b4 option", cfg.TCPOptions)
	}
	if cfg.Frames != 3 || cfg.Direction != "down" {
		t.Errorf("Frames/Direction = %d/%q, want 3/down", cfg.Frames, cfg.Direction)
	}
}

// TestMapToFlowSpec_GTP_Absent verifies "gtp" is nil when the sub-map is
// absent (no accidental zero-value pointer).
func TestMapToFlowSpec_GTP_Absent(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1"}, "gtp")
	if spec.GTP != nil {
		t.Errorf("spec.GTP = %+v, want nil when gtp absent", spec.GTP)
	}
}

// TestMapToFlowSpec_ENIP_FromResponse verifies the ENIP command converter
// wires from_response_field / source_command_index into ENIPCommand.
// Regression guard for a real bug found via pcap drive testing (T-117/T-118):
// parseENIPCommands dropped both fields, so validateFromResponseConfig (enip
// planner Plan) never fired — tasks with invalid from_response configs
// silently completed instead of erroring.
func TestMapToFlowSpec_ENIP_FromResponse(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"enip": map[string]interface{}{
			"transport": "tcp",
			"commands": []interface{}{
				map[string]interface{}{
					"command":        float64(111),
					"direction":      "down",
					"session_handle": float64(100),
					"payload":        []interface{}{float64(0), float64(0), float64(0), float64(0)},
				},
				map[string]interface{}{
					"command":              float64(112),
					"cip_service":          float64(14),
					"class_id":             float64(1),
					"instance_id":          float64(1),
					"attribute_id":         float64(1),
					"from_response_field":  "session_handle",
					"source_command_index": float64(0),
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "enip")
	if spec.ENIP == nil {
		t.Fatalf("spec.ENIP is nil")
	}
	if len(spec.ENIP.Commands) != 2 {
		t.Fatalf("Commands = %d, want 2", len(spec.ENIP.Commands))
	}
	cmd := spec.ENIP.Commands[1]
	if cmd.FromResponseField != "session_handle" {
		t.Errorf("FromResponseField = %q, want session_handle (field dropped by converter)", cmd.FromResponseField)
	}
	if cmd.SourceCommandIndex != 0 {
		t.Errorf("SourceCommandIndex = %d, want 0 (field dropped by converter)", cmd.SourceCommandIndex)
	}
}

// TestMapToFlowSpec_ENIP_SessionHandleStrategy verifies parseENIPCommands
// carries session_handle.{strategy} into ENIPCommand.SessionHandleStrategy
// (T-090/T-091, design §7.3). Before the fix the strategy map silently
// truncated to session_handle=0 and the inc/rand rejection never fired.
func TestMapToFlowSpec_ENIP_SessionHandleStrategy(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"enip": map[string]interface{}{
			"transport": "tcp",
			"commands": []interface{}{
				map[string]interface{}{
					"command": float64(111), "cip_service": float64(14),
					"session_handle": map[string]interface{}{
						"strategy": "inc",
						"range":    []interface{}{float64(1), float64(100)},
						"step":     float64(1),
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "enip")
	if spec.ENIP == nil || len(spec.ENIP.Commands) != 1 {
		t.Fatalf("ENIP commands = %+v, want 1", spec.ENIP)
	}
	cmd := spec.ENIP.Commands[0]
	if cmd.SessionHandleStrategy != "inc" {
		t.Errorf("SessionHandleStrategy = %q, want inc (strategy map dropped by converter)", cmd.SessionHandleStrategy)
	}
	if err := ValidateProtocolSubConfigs(raw, "enip"); err != nil {
		t.Errorf("ValidateProtocolSubConfigs should pass raw ranges, got: %v", err)
	}
}

// === T-074/T-075: MODBUS transactions absent vs explicit empty array ===
// The converter must distinguish "key absent" (nil → planner injects the
// default FC=0x03 transaction, T-074) from `transactions: []` (empty →
// planner emits zero transactions, handshake+teardown only, T-075).
func TestMapToFlowSpec_MODBUS_TransactionsAbsentVsEmpty(t *testing.T) {
	// Absent key: nil, planner injects default transaction.
	rawAbsent := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{"unit_id": float64(1)},
	}
	spec := mapToFlowSpec(rawAbsent, "modbus")
	if spec.MODBUS == nil {
		t.Fatalf("spec.MODBUS is nil")
	}
	if spec.MODBUS.Transactions != nil {
		t.Errorf("absent transactions: got non-nil %v, want nil (T-074 default injection)", spec.MODBUS.Transactions)
	}

	// Explicit empty array: non-nil empty slice, no default injection.
	rawEmpty := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id":      float64(1),
			"transactions": []interface{}{},
		},
	}
	spec = mapToFlowSpec(rawEmpty, "modbus")
	if spec.MODBUS == nil {
		t.Fatalf("spec.MODBUS is nil")
	}
	if spec.MODBUS.Transactions == nil {
		t.Fatal("empty transactions: got nil, want non-nil empty slice (T-075 zero transactions)")
	}
	if len(spec.MODBUS.Transactions) != 0 {
		t.Errorf("empty transactions: got %d ops, want 0", len(spec.MODBUS.Transactions))
	}
}

// === deep audit 2026-08: FC 0x2B mei_objects/conformity_level must reach
// the planner via Values (request PDU = 2B 0E <code> <object-id>) ===
// T-025/T-065/T-068/T-204: a transaction carrying mei_objects or
// conformity_level without an explicit "values" key must still produce a
// well-formed Read Device Identification request; otherwise tshark marks
// frame 4 Malformed (2-byte PDU 2B 0E).
func TestMapToFlowSpec_MODBUS_FC2BMeiObjectsDeriveRequestValues(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id": float64(1),
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code":     float64(43),
					"sub_function":      float64(14),
					"conformity_level":  float64(1),
					"mei_objects": []interface{}{
						map[string]interface{}{"object_id": float64(0), "object_value": "TrafficGen"},
						map[string]interface{}{"object_id": float64(1), "object_value": "v1"},
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "modbus")
	if spec.MODBUS == nil || len(spec.MODBUS.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %+v", spec.MODBUS)
	}
	op := spec.MODBUS.Transactions[0]
	// conformity_level=1 → Read Device ID Code=0x01 (Basic);
	// first mei_object object_id=0 → Object ID=0x00 → Values = 01 00.
	want := []byte{0x01, 0x00}
	if len(op.Values) != len(want) {
		t.Fatalf("Values: got %v (len %d), want %v (len %d)", op.Values, len(op.Values), want, len(want))
	}
	for i := range want {
		if op.Values[i] != want[i] {
			t.Fatalf("Values[%d]: got 0x%02X, want 0x%02X", i, op.Values[i], want[i])
		}
	}
}

// === deep audit 2026-08: explicit "values" key wins over derived FC 0x2B ===
func TestMapToFlowSpec_MODBUS_FC2BExplicitValuesPreserved(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id": float64(1),
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code":    float64(43),
					"sub_function":     float64(14),
					"values":           []interface{}{float64(4), float64(2)}, // Specific, Object ID=2
					"conformity_level": float64(3),
					"mei_objects": []interface{}{
						map[string]interface{}{"object_id": float64(0), "object_value": "X"},
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "modbus")
	op := spec.MODBUS.Transactions[0]
	want := []byte{0x04, 0x02}
	if len(op.Values) != len(want) {
		t.Fatalf("Values: got %v (len %d), want %v (len %d)", op.Values, len(op.Values), want, len(want))
	}
	for i := range want {
		if op.Values[i] != want[i] {
			t.Fatalf("Values[%d]: got 0x%02X, want 0x%02X", i, op.Values[i], want[i])
		}
	}
}

// === FC 0x2B: mei_objects without conformity_level defaults to code 0x01 ===
func TestMapToFlowSpec_MODBUS_FC2BMeiObjectsNoConformity(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id": float64(1),
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code": float64(43),
					"sub_function":  float64(14),
					"mei_objects": []interface{}{
						map[string]interface{}{"object_id": float64(0), "object_value": "ACME"},
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "modbus")
	op := spec.MODBUS.Transactions[0]
	want := []byte{0x01, 0x00}
	if len(op.Values) != len(want) {
		t.Fatalf("Values: got %v (len %d), want %v (len %d)", op.Values, len(op.Values), want, len(want))
	}
	for i := range want {
		if op.Values[i] != want[i] {
			t.Fatalf("Values[%d]: got 0x%02X, want 0x%02X", i, op.Values[i], want[i])
		}
	}
}

// === FC 0x2B: starting_address (T-025/S15) maps to Object ID ===
func TestMapToFlowSpec_MODBUS_FC2BStartingAddressIsObjectID(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id": float64(1),
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code":     float64(43),
					"sub_function":      float64(14),
					"starting_address":  float64(1),
					"quantity":          float64(1),
					"response_values":   []interface{}{float64(14), float64(1), float64(1), float64(0), float64(0), float64(1), float64(0), float64(4), float64(65), float64(66), float64(67), float64(68)},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "modbus")
	op := spec.MODBUS.Transactions[0]
	want := []byte{0x01, 0x01} // Basic code, Object ID=starting_address=1
	if len(op.Values) != len(want) {
		t.Fatalf("Values: got %v (len %d), want %v (len %d)", op.Values, len(op.Values), want, len(want))
	}
	for i := range want {
		if op.Values[i] != want[i] {
			t.Fatalf("Values[%d]: got 0x%02X, want 0x%02X", i, op.Values[i], want[i])
		}
	}
}

// === deep audit 2026-08: conformity_level 0x04 (Specific) passes through ===
func TestMapToFlowSpec_MODBUS_FC2BConformitySpecific(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id": float64(1),
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code":    float64(43),
					"sub_function":     float64(14),
					"conformity_level": float64(4), // Specific
					"mei_objects": []interface{}{
						map[string]interface{}{"object_id": float64(2), "object_value": "X"},
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "modbus")
	op := spec.MODBUS.Transactions[0]
	want := []byte{0x04, 0x02}
	if len(op.Values) != len(want) {
		t.Fatalf("Values: got %v (len %d), want %v (len %d)", op.Values, len(op.Values), want, len(want))
	}
	for i := range want {
		if op.Values[i] != want[i] {
			t.Fatalf("Values[%d]: got 0x%02X, want 0x%02X", i, op.Values[i], want[i])
		}
	}
}

// === deep audit 2026-08: conformity_level 0x81 (Basic+Private) → 0x01 ===
func TestMapToFlowSpec_MODBUS_FC2BConformityPrivateMasksToBase(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"modbus": map[string]interface{}{
			"unit_id": float64(1),
			"transactions": []interface{}{
				map[string]interface{}{
					"function_code":    float64(43),
					"sub_function":     float64(14),
					"conformity_level": float64(0x81), // Basic + Private
					"mei_objects": []interface{}{
						map[string]interface{}{"object_id": float64(0), "object_value": "X"},
					},
				},
			},
		},
	}
	spec := mapToFlowSpec(raw, "modbus")
	op := spec.MODBUS.Transactions[0]
	want := []byte{0x01, 0x00}
	if len(op.Values) != len(want) {
		t.Fatalf("Values: got %v (len %d), want %v (len %d)", op.Values, len(op.Values), want, len(want))
	}
	for i := range want {
		if op.Values[i] != want[i] {
			t.Fatalf("Values[%d]: got 0x%02X, want 0x%02X", i, op.Values[i], want[i])
		}
	}
}


// TestMapToFlowSpec_L2OnlyProtocolsSkipIPDefaults verifies that L2-only
// terminal protocols (goose/sv) do not receive the default src_ip/dst_ip/
// src_port/dst_port (10.0.0.1/20.0.0.1/12345/80). Those are fake values on a
// chain with no IP layer (DependsOn eth) and the terminal layer's "L2 only"
// validator rejects them — so mapToFlowSpec must leave them empty/zero unless
// the user explicitly writes them (the validator would then treat the explicit
// IP/port as an L2-only violation).
//
// Regression guard: prior to this fix mapToFlowSpec unconditionally filled the
// defaults, so every goose/sv case failed validation with "is Layer 2 only and
// must not use IP or transport fields" even though the spec had no IP at all.
// This is the framework-level "chain auto-fill conflict" (P3 T4.2/T4.3).
func TestMapToFlowSpec_L2OnlyProtocolsSkipIPDefaults(t *testing.T) {
	for _, proto := range []string{"goose", "sv"} {
		t.Run(proto, func(t *testing.T) {
			raw := map[string]interface{}{
				"layers": []interface{}{
					map[string]interface{}{"eth": map[string]interface{}{}},
					map[string]interface{}{proto: map[string]interface{}{}},
				},
			}
			spec := mapToFlowSpec(raw, proto)
			if spec.SrcIP != "" {
				t.Errorf("SrcIP = %q, want empty (L2-only)", spec.SrcIP)
			}
			if spec.DstIP != "" {
				t.Errorf("DstIP = %q, want empty (L2-only)", spec.DstIP)
			}
			if spec.SrcPort != 0 {
				t.Errorf("SrcPort = %d, want 0 (L2-only)", spec.SrcPort)
			}
			if spec.DstPort != 0 {
				t.Errorf("DstPort = %d, want 0 (L2-only)", spec.DstPort)
			}
		})
	}
}

// TestMapToFlowSpec_L2OnlyProtocolsPreserveExplicitValues verifies that an
// L2-only protocol still honors an explicitly-written src/dst (the terminal
// layer's validator decides whether an IP on an L2-only chain is an error —
// the converter must not silently drop a user value).
func TestMapToFlowSpec_L2OnlyProtocolsPreserveExplicitValues(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
		"src_port": float64(1234), "dst_port": float64(5678),
		"goose": map[string]interface{}{},
	}
	spec := mapToFlowSpec(raw, "goose")
	if spec.SrcIP != "10.0.0.1" || spec.DstIP != "20.0.0.1" {
		t.Errorf("explicit IPs lost: SrcIP=%q DstIP=%q", spec.SrcIP, spec.DstIP)
	}
	if spec.SrcPort != 1234 || spec.DstPort != 5678 {
		t.Errorf("explicit ports lost: SrcPort=%d DstPort=%d", spec.SrcPort, spec.DstPort)
	}
}

// TestMapToFlowSpec_L2OnlyTopLevelCountFallsBack verifies that the config
// top-level `count` (the case-author's frame count for L2-only protocols
// without flow_control) is propagated into GOOSE/SV config Count when the
// sub-map omits it. Regression guard: goose/sv cases put `count: N` at config
// top level, but mapToFlowSpec only read it from the sub-map, so
// GOOSEConfig.Count/SVConfig.Count stayed 0 and the generator emitted a single
// frame instead of N.
func TestMapToFlowSpec_L2OnlyTopLevelCountFallsBack(t *testing.T) {
	raw := map[string]interface{}{
		"count": float64(3),
		"layers": []interface{}{
			map[string]interface{}{"eth": map[string]interface{}{}},
			map[string]interface{}{"goose": map[string]interface{}{}},
		},
		"goose": map[string]interface{}{"gocb_ref": "g", "dat_set": "d"},
	}
	spec := mapToFlowSpec(raw, "goose")
	if spec.GOOSE == nil {
		t.Fatal("spec.GOOSE is nil")
	}
	if spec.GOOSE.Count != 3 {
		t.Errorf("GOOSE.Count = %d, want 3 (top-level count fallback)", spec.GOOSE.Count)
	}
}

// TestMapToFlowSpec_SVTopLevelCountFallsBack mirrors the goose case for sv.
func TestMapToFlowSpec_SVTopLevelCountFallsBack(t *testing.T) {
	raw := map[string]interface{}{
		"count": float64(4),
		"sv":    map[string]interface{}{"sv_id": "I", "appid": 0x4000},
	}
	spec := mapToFlowSpec(raw, "sv")
	if spec.SV == nil {
		t.Fatal("spec.SV is nil")
	}
	if spec.SV.Count != 4 {
		t.Errorf("SV.Count = %d, want 4 (top-level count fallback)", spec.SV.Count)
	}
}
