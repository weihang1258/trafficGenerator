package layers

import "testing"

func TestDbgTransportOn2(t *testing.T) {
	r := DefaultRegistry()
	out := []Layer{{Name: "tcp"}, {Name: "dns"}}
	changed := true
	for iter := 0; changed && iter < 10; iter++ {
		changed = false
		for i := 0; i < len(out); i++ {
			schema, ok := r.Get(out[i].Name)
			if !ok {
				t.Fatalf("unknown %s", out[i].Name)
			}
			for _, dep := range schema.DependsOn {
				if outerHas(out, i, dep) {
					continue
				}
				if len(schema.TransportOn) > 0 && schema.TransportOn[0] == dep && hasAnyOuter(out, i, schema.TransportOn) {
					t.Logf("iter%d i=%d layer=%s: SKIP dep=%s (transportOn subst, outer has %v)", iter, i, out[i].Name, dep, schema.TransportOn)
					continue
				}
				out = append(out[:i], append([]Layer{{Name: dep}}, out[i:]...)...)
				changed = true
				i++
				t.Logf("iter%d i=%d layer=%s: insert dep=%s -> [%s]", iter, i, out[i].Name, dep, chainString(out))
			}
		}
	}
	err := r.ValidateChain(out)
	t.Logf("final=[%s] err=%v", chainString(out), err)
}
