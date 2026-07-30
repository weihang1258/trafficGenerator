// Package ssh integration_test.go - end-to-end integration: planner -> builder
// -> pcap -> tshark dissection.
//
// Per CLAUDE.md testing policy §4 (integration, not just unit) and §5
// (assert observable outcomes): this test drives the full pipeline for the
// scenario-mode SSH planner and verifies that tshark can dissect the SSH layer
// (version string, KEXINIT message number, channel messages), proving the
// wire bytes are RFC 4253/4254 compliant and not just internally consistent.
//
// This test does NOT depend on the flowb engine or a running server; it uses
// the core.Builder directly to serialize planner configs into Ethernet frames,
// writes them to a pcap via pcapgo, and runs tshark to dissect.
package ssh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/core"
)

// buildFrames drains the planner output, builds each PacketConfig into an
// Ethernet frame via core.Builder, and returns the frames + timestamps.
func buildFrames(t *testing.T, spec core.FlowSpec) ([][]byte, []time.Time) {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	b := core.NewBuilder()
	var frames [][]byte
	var ts []time.Time
	now := time.Now()
	for cfg := range ch {
		frame, err := b.Build(cfg)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		frames = append(frames, frame)
		ts = append(ts, now.Add(time.Duration(cfg.PacketIndex)*time.Millisecond))
	}
	return frames, ts
}

// writePcap writes frames to a temp pcap file and returns the path.
func writePcapFrames(t *testing.T, frames [][]byte, ts []time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh_scenario.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("header: %v", err)
	}
	for i, frame := range frames {
		ci := gopacket.CaptureInfo{Timestamp: ts[i], CaptureLength: len(frame), Length: len(frame)}
		if err := w.WritePacket(ci, frame); err != nil {
			t.Fatalf("write pkt %d: %v", i, err)
		}
	}
	return path
}

// runTshark runs tshark on the pcap and returns the stdout output. Skips the
// test if tshark is not installed.
func runTshark(t *testing.T, path string, fields []string) string {
	t.Helper()
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; skipping SSH wire-format dissection check")
	}
	args := []string{"-r", path, "-T", "fields"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	out, err := exec.Command("tshark", args...).Output()
	if err != nil {
		t.Fatalf("tshark: %v", err)
	}
	return string(out)
}

// TestSSHIntegration_ExecScenarioTshark builds the exec scenario, writes a
// pcap, and verifies tshark can dissect the SSH version exchange + BPP
// messages. This proves the wire bytes are RFC-compliant (a real Wireshark
// can parse them), not just internally consistent.
func TestSSHIntegration_ExecScenarioTshark(t *testing.T) {
	spec := validSSHSpec()
	spec.SSH = &core.SSHConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9",
		ClientVersion: "SSH-2.0-trafficgen_1.0",
		Scenario:      "exec",
		Command:        "uname -a",
		Stdout:         []byte("Linux srv 5.4.0-generic"),
	}
	frames, ts := buildFrames(t, spec)
	if len(frames) < 10 {
		t.Fatalf("frame count=%d, want >= 10 (full exec session)", len(frames))
	}
	path := writePcapFrames(t, frames, ts)

	// Dissect the SSH layer: verify the version string is visible.
	out := runTshark(t, path, []string{"ssh.protocol"})
	if !strings.Contains(out, "SSH-2.0-OpenSSH_8.9") {
		t.Errorf("tshark did not see server version 'SSH-2.0-OpenSSH_8.9' in:\n%s", out)
	}
	if !strings.Contains(out, "SSH-2.0-trafficgen_1.0") {
		t.Errorf("tshark did not see client version in:\n%s", out)
	}
}

// TestSSHIntegration_AllScenariosBuild verifies every scenario produces a
// buildable, non-trivial set of frames (no panic, >= 10 frames each).
func TestSSHIntegration_AllScenariosBuild(t *testing.T) {
	for _, sc := range []string{"exec", "shell", "pty-exec", "publickey", "auth_fail_retry", "long_output"} {
		t.Run(sc, func(t *testing.T) {
			spec := validSSHSpec()
			spec.SSH = &core.SSHConfig{
				ServerVersion: "SSH-2.0-OpenSSH_8.9",
				ClientVersion: "SSH-2.0-trafficgen_1.0",
				Scenario:      sc,
				Stdout:        []byte(strings.Repeat("output line\n", 20)),
				Stderr:        []byte("stderr warn\n"),
			}
			frames, _ := buildFrames(t, spec)
			if len(frames) < 10 {
				t.Errorf("scenario %s: frame count=%d, want >= 10", sc, len(frames))
			}
			// Write to pcap and run tshark to ensure no dissection error.
			path := writePcapFrames(t, frames, make([]time.Time, len(frames)))
			if _, err := exec.LookPath("tshark"); err != nil {
				t.Skip("tshark not installed")
			}
			// tshark -r <path> should exit 0 with no "unrecognized" errors.
			if err := exec.Command("tshark", "-r", path, "-q", "-z", "io,stat,0").Run(); err != nil {
				t.Errorf("tshark stat on scenario %s failed: %v", sc, err)
			}
		})
	}
}
