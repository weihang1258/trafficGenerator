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

func TestMapToFlowSpec_FileSource_FTPDataChannel(t *testing.T) {
	cfg := map[string]interface{}{
		"protocol": "ftp",
		"ftp": map[string]interface{}{
			"data_channel": map[string]interface{}{
				"file_source": map[string]interface{}{
					"file": "docs/retr.bin",
				},
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "ftp")
	if spec.FTP == nil || spec.FTP.DataChannel == nil || spec.FTP.DataChannel.FileSource == nil {
		t.Fatalf("FTPDataChannel.FileSource is nil")
	}
	if spec.FTP.DataChannel.FileSource.File != "docs/retr.bin" {
		t.Fatalf("File got %q", spec.FTP.DataChannel.FileSource.File)
	}
}

func TestMapToFlowSpec_FileSource_NilWhenAbsent(t *testing.T) {
	cfg := map[string]interface{}{"protocol": "tcp"}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if spec.FileSource != nil {
		t.Fatalf("FileSource should be nil when absent")
	}
}
