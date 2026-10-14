package policydoc

import (
	"slices"
	"testing"
)

// ReadAutoApprovers (F3-015) reads the autoApprovers section for display: the routes
// CIDR-to-approvers map and the exitNode approver list. The tests pin the shape Headscale v0.29.4
// accepts: HuJSON with comments, a missing section, case-insensitive section names and the
// duplicate/unknown-member errors.
func TestReadAutoApprovers(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		wantRoutes map[string][]string
		wantExit   []string
		wantErr    bool
	}{
		{
			name:       "missing section",
			policy:     `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
			wantRoutes: map[string][]string{},
		},
		{
			name: "routes and exit node",
			policy: `{
				// devops manages the servers
				"autoApprovers": {
					"routes": {"10.0.0.0/24": ["tag:server"], "192.168.40.0/24": ["alice"]},
					"exitNode": ["tag:server", "alice"]
				}
			}`,
			wantRoutes: map[string][]string{
				"10.0.0.0/24":     {"tag:server"},
				"192.168.40.0/24": {"alice"},
			},
			wantExit: []string{"tag:server", "alice"},
		},
		{
			name:       "case-insensitive section and member names",
			policy:     `{"AutoApprovers": {"Routes": {"10.8.0.0/16": ["tag:k8s"]}, "ExitNode": ["alice"]}}`,
			wantRoutes: map[string][]string{"10.8.0.0/16": {"tag:k8s"}},
			wantExit:   []string{"alice"},
		},
		{
			name: "metadata members are ignored",
			policy: `{
				"autoApprovers": {
					"#comment": "managed by tagcess",
					"routes": {"#note": "prod", "10.0.0.0/24": ["tag:server"]},
					"exitNode": []
				}
			}`,
			wantRoutes: map[string][]string{"10.0.0.0/24": {"tag:server"}},
			wantExit:   []string{},
		},
		{
			name:    "routes not an object",
			policy:  `{"autoApprovers": {"routes": ["10.0.0.0/24"]}}`,
			wantErr: true,
		},
		{
			name:    "approver list holds a non-string",
			policy:  `{"autoApprovers": {"routes": {"10.0.0.0/24": [7]}}}`,
			wantErr: true,
		},
		{
			name:    "exitNode not an array",
			policy:  `{"autoApprovers": {"exitNode": {"tag:server": true}}}`,
			wantErr: true,
		},
		{
			name:    "duplicate cidr entry",
			policy:  `{"autoApprovers": {"routes": {"10.0.0.0/24": ["a"], "10.0.0.0/24": ["b"]}}}`,
			wantErr: true,
		},
		{
			name:    "unknown member",
			policy:  `{"autoApprovers": {"hosts": {}}}`,
			wantErr: true,
		},
		{
			name:    "section not an object",
			policy:  `{"autoApprovers": []}`,
			wantErr: true,
		},
		{
			name:    "not a policy document",
			policy:  `[]`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aa, err := ReadAutoApprovers(tt.policy)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ReadAutoApprovers() = %+v, want error", aa)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadAutoApprovers(): %v", err)
			}
			if len(aa.Routes) != len(tt.wantRoutes) {
				t.Fatalf("routes = %v, want %v", aa.Routes, tt.wantRoutes)
			}
			for cidr, want := range tt.wantRoutes {
				got, ok := aa.Routes[cidr]
				if !ok {
					t.Fatalf("routes lack %q: %v", cidr, aa.Routes)
				}
				if !slices.Equal(got, want) {
					t.Errorf("approvers of %q = %v, want %v", cidr, got, want)
				}
			}
			if !slices.Equal(aa.ExitNode, tt.wantExit) {
				t.Errorf("exitNode = %v, want %v", aa.ExitNode, tt.wantExit)
			}
		})
	}
}
