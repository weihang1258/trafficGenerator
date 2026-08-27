package pcaptest

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestStopCaptureContextReapsAfterKill(t *testing.T) {
	cmd := exec.Command("sh", "-c", "trap '' INT; sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	start := time.Now()
	StopCaptureContext(context.Background(), cmd)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("StopCaptureContext took %s after kill", elapsed)
	}
	if err := cmd.Process.Signal(nil); err == nil {
		t.Fatal("process still exists after StopCaptureContext")
	}
}
