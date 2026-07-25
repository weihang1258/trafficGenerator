package filesystem_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func BenchmarkUpload_SameContent_10k(b *testing.B) {
	fs, _ := filesystem.New(b.TempDir())
	ctx := context.Background()
	src := filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("file-%d.txt", i)
		if err := fs.Upload(ctx, path, src); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N), "uploads")
}

func BenchmarkRead_SamePath_10k(b *testing.B) {
	fs, _ := filesystem.New(b.TempDir())
	ctx := context.Background()
	if err := fs.Upload(ctx, "shared.txt", filesystem.FileSource{Literal: strings.Repeat("A", 64*1024)}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fs.Read(ctx, "shared.txt"); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N), "reads")
}
