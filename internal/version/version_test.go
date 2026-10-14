package version

import "testing"

func TestFormat(t *testing.T) {
	tests := []struct{ name, version, commit, want string }{
		{"tagcess", "0.1.0-dev", "unknown", "tagcess 0.1.0-dev (unknown)"},
		{"tagcess", "v1.2.3", "abc1234", "tagcess v1.2.3 (abc1234)"},
		{"tagcess-ui", "", "", "tagcess-ui unknown (unknown)"},
	}
	for _, tt := range tests {
		if got := format(tt.name, tt.version, tt.commit); got != tt.want {
			t.Errorf("format(%q,%q,%q) = %q, want %q", tt.name, tt.version, tt.commit, got, tt.want)
		}
	}
}

func TestIsVersionFlag(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"-version"}, true},
		{[]string{"--version"}, true},
		{nil, false},
		{[]string{"-config", "x"}, false},
		{[]string{"-version", "x"}, false},
	}
	for _, tt := range tests {
		if got := IsVersionFlag(tt.args); got != tt.want {
			t.Errorf("IsVersionFlag(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
}
