package site

import (
	"context"
	"reflect"
	"testing"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/store/db"
)

// TestManualDNS_StoreRoundTrip: the manual records (H-06) live in the settings table as JSON; an
// absent value is "no manual records", a stored set comes back sorted and unchanged, and a stored
// value that is not a valid record set is an error, never an empty set (fail closed).
func TestManualDNS_StoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	a := func(name, value string) dns.Record { return dns.Record{Name: name, Type: dns.TypeA, Value: value} }

	t.Run("absent is empty", func(t *testing.T) {
		s := openSeedStore(t)
		got, err := s.ManualDNS(ctx)
		if err != nil || len(got) != 0 {
			t.Fatalf("ManualDNS = %+v, %v, want empty", got, err)
		}
	})

	t.Run("round trip sorted", func(t *testing.T) {
		s := openSeedStore(t)
		in := []dns.Record{a("z.example.com", "100.64.0.9"), a("b.example.com", "100.64.0.8")}
		if err := s.SetManualDNS(ctx, in); err != nil {
			t.Fatalf("SetManualDNS: %v", err)
		}
		got, err := s.ManualDNS(ctx)
		if err != nil {
			t.Fatalf("ManualDNS: %v", err)
		}
		want := []dns.Record{a("b.example.com", "100.64.0.8"), a("z.example.com", "100.64.0.9")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ManualDNS = %+v, want %+v", got, want)
		}
	})

	t.Run("an invalid record is refused on write", func(t *testing.T) {
		s := openSeedStore(t)
		if err := s.SetManualDNS(ctx, []dns.Record{a("Bad Name", "100.64.0.9")}); err == nil {
			t.Fatal("SetManualDNS accepted an invalid record")
		}
		if got, _ := s.ManualDNS(ctx); len(got) != 0 {
			t.Errorf("a refused write left %+v behind", got)
		}
	})

	for name, value := range map[string]string{
		"not json":        "garbage",
		"invalid record":  `[{"name":"Bad Name","type":"A","value":"100.64.0.9"}]`,
		"unsupported typ": `[{"name":"x.example.com","type":"TXT","value":"100.64.0.9"}]`,
	} {
		t.Run("a stored "+name+" is an error", func(t *testing.T) {
			s := openSeedStore(t)
			if err := s.q.UpsertSetting(ctx, db.UpsertSettingParams{Key: SettingManualDNS, Value: value, UpdatedAt: "2026-10-01T00:00:00.000Z"}); err != nil {
				t.Fatalf("UpsertSetting: %v", err)
			}
			if got, err := s.ManualDNS(ctx); err == nil {
				t.Errorf("ManualDNS = %+v, want an error", got)
			}
		})
	}
}
