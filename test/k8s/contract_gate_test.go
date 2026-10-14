package k8s

import "testing"

// C-L11: the local-API twins may skip on a developer machine without a usable address, but never under
// CI or the gate.
func TestContractSkipUnlessGate(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		wantFatal bool
	}{
		{"developer machine skips", nil, false},
		{"CI fails", map[string]string{"CI": "true"}, true},
		{"gate fails", map[string]string{"TAGCESS_GATE": "1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tb := &fakeTB{t: t}
			tb.play(func() { skipUnlessGate(tb, func(k string) string { return tc.env[k] }, "no address %d", 1) })
			if tc.wantFatal && (tb.fatal == "" || tb.skip != "") {
				t.Errorf("fatal=%q skip=%q, want a fatal", tb.fatal, tb.skip)
			}
			if !tc.wantFatal && (tb.skip == "" || tb.fatal != "") {
				t.Errorf("fatal=%q skip=%q, want a skip", tb.fatal, tb.skip)
			}
		})
	}
}
