package coap

import "testing"

func TestBuildMessageOrdersObserveBeforeURIOptions(t *testing.T) {
	seq := uint32(7)
	got, err := BuildMessage(&CoAPConfig{
		Method: "GET", Path: []string{"sensors"}, Observe: &ObserveConfig{StartSequence: seq},
		ContentFormat: 50, MessageID: 1,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 8 || got[4] != 0x61 || got[5] != 7 {
		t.Fatalf("first option = %x, want Observe option 0x61 07", got[4:])
	}
}
