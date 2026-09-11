package core_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestMapToFlowSpec_FileSource_Literal(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "tcp",
		"file_source": map[string]interface{}{
			"literal": "hello",
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource == nil {
		t.Fatalf("FileSource is nil")
	}
	if spec.FileSource.Literal != "hello" {
		t.Fatalf("Literal got %q, want %q", spec.FileSource.Literal, "hello")
	}
}

func TestMapToFlowSpec_FileSource_Fill(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "tcp",
		"file_source": map[string]interface{}{
			"fill": map[string]interface{}{
				"byte":  170,
				"bytes": 100,
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource == nil || spec.FileSource.Fill == nil {
		t.Fatalf("FileSource.Fill is nil")
	}
	if spec.FileSource.Fill.Byte != 170 || spec.FileSource.Fill.Bytes != 100 {
		t.Fatalf("Fill got %+v", spec.FileSource.Fill)
	}
}

func TestMapToFlowSpec_FileSource_Random(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "tcp",
		"file_source": map[string]interface{}{
			"random": map[string]interface{}{
				"min_bytes": 64,
				"max_bytes": 128,
				"seed":      42,
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource == nil || spec.FileSource.Random == nil {
		t.Fatalf("FileSource.Random is nil")
	}
	if spec.FileSource.Random.MinBytes != 64 || spec.FileSource.Random.MaxBytes != 128 || spec.FileSource.Random.Seed != 42 {
		t.Fatalf("Random got %+v", spec.FileSource.Random)
	}
}

// Task 5 扁平删除后，FTP 层内 data_channel.file_source 的解析经
// ParseFTPConfigFromMap（层链 translateTerminalConfig 的同一真相）；
// 扁平 cfg["ftp"] 路径已判死。
func TestParseFTPConfigFromMap_FileSource_FTPDataChannel(t *testing.T) {
	m := map[string]interface{}{
		"data_channel": map[string]interface{}{
			"file_source": map[string]interface{}{
				"file": "docs/retr.bin",
			},
		},
	}
	fc := core.ParseFTPConfigFromMap(m)
	if fc == nil || fc.DataChannel == nil || fc.DataChannel.FileSource == nil {
		t.Fatalf("FTPDataChannel.FileSource is nil")
	}
	if fc.DataChannel.FileSource.File != "docs/retr.bin" {
		t.Fatalf("File got %q", fc.DataChannel.FileSource.File)
	}
}

func TestMapToFlowSpec_FileSource_NilWhenAbsent(t *testing.T) {
	cfg := map[string]interface{}{"protocol": "tcp"}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource != nil {
		t.Fatalf("FileSource should be nil when absent")
	}
}

// TestMapToFlowSpec_FileSource_SCTPChunk verifies the basic per-chunk
// FileSource dispatch works for an all-map chunks array.
func TestMapToFlowSpec_FileSource_SCTPChunk(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "sctp",
		"sctp": map[string]interface{}{
			"chunks": []interface{}{
				map[string]interface{}{"type": "DATA", "file_source": map[string]interface{}{"literal": "chunk0"}},
				map[string]interface{}{"type": "DATA", "file_source": map[string]interface{}{"file": "docs/x.bin"}},
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatalf("SCTP is nil")
	}
	if len(spec.SCTP.Chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(spec.SCTP.Chunks))
	}
	if spec.SCTP.Chunks[0].FileSource == nil || spec.SCTP.Chunks[0].FileSource.Literal != "chunk0" {
		t.Fatalf("chunk 0 FileSource lost: %+v", spec.SCTP.Chunks[0].FileSource)
	}
	if spec.SCTP.Chunks[1].FileSource == nil || spec.SCTP.Chunks[1].FileSource.File != "docs/x.bin" {
		t.Fatalf("chunk 1 FileSource lost: %+v", spec.SCTP.Chunks[1].FileSource)
	}
}

// TestMapToFlowSpec_FileSource_SCTPChunk_NonMapEntry_DoesNotDropValidChunks
// reproduces the index-alignment bug: when the raw chunks array contains a
// non-map entry, parseSCTPChunks filters it out, so len(parsed) <
// len(raw). The dispatch loop's length-safety check failed, dropping ALL
// chunk FileSources — including valid ones at aligned indices. After the
// fix (FileSource parsing pushed into parseSCTPChunks), the two valid
// chunks retain their FileSource.
func TestMapToFlowSpec_FileSource_SCTPChunk_NonMapEntry_DoesNotDropValidChunks(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "sctp",
		"sctp": map[string]interface{}{
			"chunks": []interface{}{
				map[string]interface{}{"type": "DATA", "file_source": map[string]interface{}{"literal": "chunk0"}},
				"not-a-map", // non-map entry that parseSCTPChunks will skip
				map[string]interface{}{"type": "DATA", "file_source": map[string]interface{}{"file": "docs/x.bin"}},
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatalf("SCTP is nil")
	}
	if len(spec.SCTP.Chunks) != 2 {
		t.Fatalf("expected 2 valid chunks, got %d", len(spec.SCTP.Chunks))
	}
	if spec.SCTP.Chunks[0].FileSource == nil || spec.SCTP.Chunks[0].FileSource.Literal != "chunk0" {
		t.Fatalf("chunk 0 FileSource lost: %+v", spec.SCTP.Chunks[0].FileSource)
	}
	if spec.SCTP.Chunks[1].FileSource == nil || spec.SCTP.Chunks[1].FileSource.File != "docs/x.bin" {
		t.Fatalf("chunk 1 FileSource lost: %+v", spec.SCTP.Chunks[1].FileSource)
	}
}

// TestMapToFlowSpec_FileSource_SIPMedia locks in that the SIP media
// dispatch actually runs and assigns FileSource to SIPMedia.
func TestMapToFlowSpec_FileSource_SIPMedia(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "sip",
		"sip": map[string]interface{}{
			"media": map[string]interface{}{
				"file_source": map[string]interface{}{"literal": "rtp-frame"},
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "sip")
	if spec.SIP == nil || spec.SIP.Media == nil || spec.SIP.Media.FileSource == nil {
		t.Fatalf("SIPMedia.FileSource is nil")
	}
	if spec.SIP.Media.FileSource.Literal != "rtp-frame" {
		t.Fatalf("Literal got %q", spec.SIP.Media.FileSource.Literal)
	}
}

// TestMapToFlowSpec_FileSource_HTTPConfig locks in that the HTTP dispatch
// actually runs and assigns FileSource to HTTPConfig.
func TestMapToFlowSpec_FileSource_HTTPConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "http",
		"http": map[string]interface{}{
			"file_source": map[string]interface{}{"literal": "body"},
		},
	}
	spec := core.MapToFlowSpec(cfg, "http")
	if spec.HTTP == nil || spec.HTTP.FileSource == nil {
		t.Fatalf("HTTPConfig.FileSource is nil")
	}
	if spec.HTTP.FileSource.Literal != "body" {
		t.Fatalf("Literal got %q", spec.HTTP.FileSource.Literal)
	}
}

// TestMapToFlowSpec_FileSource_ICMPConfig locks in that the ICMP dispatch
// actually runs and assigns FileSource to ICMPConfig.
func TestMapToFlowSpec_FileSource_ICMPConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "icmp",
		"icmp": map[string]interface{}{
			"file_source": map[string]interface{}{"literal": "icmp-data"},
		},
	}
	spec := core.MapToFlowSpec(cfg, "icmp")
	if spec.ICMP == nil || spec.ICMP.FileSource == nil {
		t.Fatalf("ICMPConfig.FileSource is nil")
	}
	if spec.ICMP.FileSource.Literal != "icmp-data" {
		t.Fatalf("Literal got %q", spec.ICMP.FileSource.Literal)
	}
}
