package main

import (
	"context"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/headscale/admin"
)

type namedNodes []admin.AdminNode

func (n namedNodes) ListNodes(context.Context) ([]admin.AdminNode, error) { return n, nil }

// U-14: Pano names a device by its unique Headscale given name, as the device list does; the
// machine's own host name repeats across devices ("JerryM" three times).
func TestF4DevicesUseGivenName(t *testing.T) {
	cases := []struct {
		name string
		node admin.AdminNode
		want string
	}{
		{"given name wins", admin.AdminNode{Name: "JerryM", GivenName: "jerrym-1"}, "jerrym-1"},
		{"host name when no given name", admin.AdminNode{Name: "JerryM"}, "JerryM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := f4Devices{nodes: namedNodes{tc.node}, now: time.Now}
			got, err := d.Devices(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Devices) != 1 || got.Devices[0].Name != tc.want {
				t.Fatalf("devices = %+v, want name %q", got.Devices, tc.want)
			}
		})
	}
}
