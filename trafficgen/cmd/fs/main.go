// Package main implements the tgserver-fs standalone CLI binary for the
// content-addressed filesystem. Subcommands: upload, delete, mkdir, rmdir,
// list, query, read.
//
// Usage:
//
//	tgserver-fs -root <root> <command> [args] [flags]
//
// Examples:
//
//	tgserver-fs upload test.txt --literal hello
//	tgserver-fs upload test2.txt --file test.txt
//	tgserver-fs upload big.bin --fill-byte 0xAA --fill-bytes 1024
//	tgserver-fs upload rand.bin --random-min 64 --random-max 128 --seed 42
//	tgserver-fs read test.txt
//	tgserver-fs list [dir]
//	tgserver-fs query test.txt
//	tgserver-fs delete test.txt
//	tgserver-fs mkdir some/dir
//	tgserver-fs rmdir some/dir [--recursive]
//
// Each subcommand uses its own flag.FlagSet so subcommand-specific flags
// (like --literal / --file for upload, --recursive for rmdir) are parsed
// cleanly without re-calling the top-level flag.Parse.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func main() {
	root := flag.String("root", "data/filesystem", "Filesystem root")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs <command> [args]")
		fmt.Fprintln(os.Stderr, "commands: upload, delete, mkdir, rmdir, list, query, read")
		os.Exit(2)
	}

	fs, err := filesystem.New(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "filesystem.New err=%v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "upload":
		runUpload(ctx, fs, rest)
	case "delete":
		runDelete(ctx, fs, rest)
	case "mkdir":
		runMkdir(ctx, fs, rest)
	case "rmdir":
		runRmdir(ctx, fs, rest)
	case "list":
		runList(ctx, fs, rest)
	case "query":
		runQuery(ctx, fs, rest)
	case "read":
		runRead(ctx, fs, rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		fmt.Fprintln(os.Stderr, "commands: upload, delete, mkdir, rmdir, list, query, read")
		os.Exit(2)
	}
}

// runUpload handles: tgserver-fs upload <path> [--literal X | --file src | --fill-byte N --fill-bytes N | --random-min N --random-max N --seed N]
func runUpload(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs upload <path> [--literal X | --file src | --fill-byte N --fill-bytes N | --random-min N --random-max N --seed N]")
		os.Exit(2)
	}
	path := args[0]
	fsSet := flag.NewFlagSet("upload", flag.ExitOnError)
	var literal, file string
	var fillByte, fillBytes, randMin, randMax, seed int
	fsSet.StringVar(&literal, "literal", "", "literal text")
	fsSet.StringVar(&file, "file", "", "source file path (relative to filesystem root, or absolute)")
	fsSet.IntVar(&fillByte, "fill-byte", 0, "fill byte (0-255)")
	fsSet.IntVar(&fillBytes, "fill-bytes", 0, "fill size in bytes (must be > 0 to engage fill source)")
	fsSet.IntVar(&randMin, "random-min", 0, "random min bytes")
	fsSet.IntVar(&randMax, "random-max", 0, "random max bytes (must be > 0 to engage random source)")
	fsSet.IntVar(&seed, "seed", 0, "random seed (0 = crypto random)")
	if err := fsSet.Parse(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "upload flag parse err=%v\n", err)
		os.Exit(2)
	}
	src, err := buildSource(literal, file, fillByte, fillBytes, randMin, randMax, seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload err=%v\n", err)
		os.Exit(2)
	}
	if err := fs.Upload(ctx, path, src); err != nil {
		fmt.Fprintf(os.Stderr, "upload err=%v\n", err)
		os.Exit(1)
	}
	fmt.Println("uploaded", path)
}

// buildSource resolves the FileSource from the parsed flags using the
// documented priority: File > Literal > Fill > Random. Returns an error if
// no source is selected or if fill-byte is out of range.
func buildSource(literal, file string, fillByte, fillBytes, randMin, randMax, seed int) (filesystem.FileSource, error) {
	switch {
	case file != "":
		return filesystem.FileSource{File: file}, nil
	case literal != "":
		return filesystem.FileSource{Literal: literal}, nil
	case fillBytes > 0:
		if fillByte < 0 || fillByte > 255 {
			return filesystem.FileSource{}, fmt.Errorf("fill-byte must be in [0,255], got %d", fillByte)
		}
		return filesystem.FileSource{Fill: &filesystem.Fill{Byte: byte(fillByte), Bytes: fillBytes}}, nil
	case randMax > 0:
		if randMin < 0 || randMax < randMin {
			return filesystem.FileSource{}, fmt.Errorf("random-min=%d must be >= 0 and <= random-max=%d", randMin, randMax)
		}
		return filesystem.FileSource{Random: &filesystem.Random{MinBytes: randMin, MaxBytes: randMax, Seed: int64(seed)}}, nil
	default:
		return filesystem.FileSource{}, errors.New("no source specified: use one of --file, --literal, --fill-bytes, --random-max")
	}
}

// runDelete handles: tgserver-fs delete <path>
func runDelete(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs delete <path>")
		os.Exit(2)
	}
	path := args[0]
	if err := fs.Delete(ctx, path); err != nil {
		fmt.Fprintf(os.Stderr, "delete err=%v\n", err)
		os.Exit(1)
	}
	fmt.Println("deleted", path)
}

// runMkdir handles: tgserver-fs mkdir <path>
func runMkdir(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs mkdir <path>")
		os.Exit(2)
	}
	path := args[0]
	if err := fs.Mkdir(ctx, path); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir err=%v\n", err)
		os.Exit(1)
	}
	fmt.Println("mkdir", path)
}

// runRmdir handles: tgserver-fs rmdir <path> [--recursive]
func runRmdir(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs rmdir <path> [--recursive]")
		os.Exit(2)
	}
	fsSet := flag.NewFlagSet("rmdir", flag.ExitOnError)
	var recursive bool
	fsSet.BoolVar(&recursive, "recursive", false, "recursive delete (delete all files and sub-directories)")
	if err := fsSet.Parse(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "rmdir flag parse err=%v\n", err)
		os.Exit(2)
	}
	// Use the positional arg already extracted from args[0] rather than
	// fsSet.Arg(0) -- the latter interacts poorly with mixed flag/positional
	// parsing and is the source of a shadow-declaration bug in the brief.
	path := args[0]
	if err := fs.Rmdir(ctx, path, filesystem.RmdirOptions{Recursive: recursive}); err != nil {
		fmt.Fprintf(os.Stderr, "rmdir err=%v\n", err)
		os.Exit(1)
	}
	fmt.Println("rmdir", path)
}

// runList handles: tgserver-fs list [dir] (default dir = ".")
func runList(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	entries, err := fs.List(ctx, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list err=%v\n", err)
		os.Exit(1)
	}
	for _, e := range entries {
		t := "F"
		if e.IsDir {
			t = "D"
		}
		fmt.Printf("%s %12d %s\n", t, e.Size, e.Name)
	}
}

// runQuery handles: tgserver-fs query <path>
func runQuery(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs query <path>")
		os.Exit(2)
	}
	path := args[0]
	info, err := fs.Query(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query err=%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", formatFileInfo(info))
}

// formatFileInfo renders FileInfo as a single-line key=value record. Avoids
// %+v because that uses the struct field names verbatim and we want stable,
// human-friendly output that also fits in a shell pipeline.
func formatFileInfo(info filesystem.FileInfo) string {
	kind := "file"
	if info.IsDir {
		kind = "dir"
	}
	return fmt.Sprintf("name=%s type=%s size=%d modtime=%s sha256=%s",
		info.Name, kind, info.Size, info.ModTime.Format("2006-01-02T15:04:05Z07:00"), info.SHA256)
}

// runRead handles: tgserver-fs read <path>
func runRead(ctx context.Context, fs *filesystem.Filesystem, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tgserver-fs read <path>")
		os.Exit(2)
	}
	path := args[0]
	b, err := fs.Read(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read err=%v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(b); err != nil {
		fmt.Fprintf(os.Stderr, "write stdout err=%v\n", err)
		os.Exit(1)
	}
}
