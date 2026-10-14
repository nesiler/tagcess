package site

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// stripStored clears what a snapshot deliberately does not carry: the row identity and the stamps.
func stripStored(s Site) Site {
	s.ID = 0
	s.CreatedAt = time.Time{}
	s.UpdatedAt = time.Time{}
	return s
}

// A-03.4: the source model is rebuilt exactly (round trip) from the stored snapshot, for every site
// kind and every sub-record.
func TestSiteSnapshot_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for _, in := range []Site{roleSite(), openSite(), systemSite()} {
		stored, err := s.CreateSite(ctx, in)
		if err != nil {
			t.Fatalf("CreateSite %v: %v", in.Hosts, err)
		}
		body, err := MarshalSnapshot(stored)
		if err != nil {
			t.Fatalf("MarshalSnapshot %v: %v", in.Hosts, err)
		}
		again, err := MarshalSnapshot(stored)
		if err != nil || string(again) != string(body) {
			t.Errorf("snapshot of %v is not deterministic", in.Hosts)
		}
		got, err := ParseSnapshot(body)
		if err != nil {
			t.Fatalf("ParseSnapshot %v: %v", in.Hosts, err)
		}
		if want := stripStored(stored); !reflect.DeepEqual(got, want) {
			t.Errorf("round trip of %v:\n got %#v\nwant %#v", in.Hosts, got, want)
		}
	}
}

func TestSiteSnapshot_ParseFailsClosed(t *testing.T) {
	good, err := MarshalSnapshot(roleSite())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body string
	}{
		{"empty", ``},
		{"not json", `{nope`},
		{"unknown version", strings.Replace(string(good), `"v":1`, `"v":2`, 1)},
		{"unknown field", strings.Replace(string(good), `"v":1`, `"v":1,"extra":true`, 1)},
		{"trailing data", string(good) + `{}`},
		{"wrong type", strings.Replace(string(good), `"maintenance":false`, `"maintenance":"yes"`, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseSnapshot([]byte(tt.body)); err == nil {
				t.Errorf("ParseSnapshot(%q) = nil error, want a refusal", tt.body)
			}
		})
	}
}

func newVersion(s Site, change int64, op string) NewVersion {
	return NewVersion{SiteID: 5, ChangeID: change, Op: op, Site: s, Actor: "dev@example.com",
		At: time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)}
}

// A-03.4: every applied change is a durable version; versions list newest first, read back to the
// exact source model, bind to a revision once and dedupe identical consecutive states.
func TestSiteVersions_RecordListBind(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	v1src := roleSite()
	v2src := roleSite()
	v2src.Roles = []string{"devops"}

	got1, recorded, err := s.RecordVersion(ctx, newVersion(v1src, 10, "add"))
	if err != nil || !recorded {
		t.Fatalf("RecordVersion v1 = %v, %v", recorded, err)
	}
	if _, recorded, err := s.RecordVersion(ctx, newVersion(v1src, 11, "resync")); err != nil || recorded {
		t.Errorf("identical consecutive state: recorded = %v, err = %v, want it skipped", recorded, err)
	}
	got2, recorded, err := s.RecordVersion(ctx, newVersion(v2src, 12, "update"))
	if err != nil || !recorded {
		t.Fatalf("RecordVersion v2 = %v, %v", recorded, err)
	}
	// A tombstone keeps the last source model and is a version of its own.
	del := newVersion(v2src, 13, "delete")
	del.Deleted = true
	if _, recorded, err := s.RecordVersion(ctx, del); err != nil || !recorded {
		t.Fatalf("RecordVersion delete = %v, %v", recorded, err)
	}

	list, err := s.ListVersions(ctx, 5)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(list) != 3 || list[0].ChangeID != 13 || list[1].ChangeID != 12 || list[2].ChangeID != 10 {
		t.Fatalf("versions = %+v, want change 13, 12, 10 newest first", list)
	}
	if !list[0].Deleted || list[1].Deleted {
		t.Errorf("deleted flags = %v, %v, want true, false", list[0].Deleted, list[1].Deleted)
	}
	if other, err := s.ListVersions(ctx, 6); err != nil || len(other) != 0 {
		t.Errorf("versions of another site = %v, %v, want none", other, err)
	}

	back, err := s.GetVersion(ctx, got1.ID)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if !reflect.DeepEqual(back.Site, stripStored(v1src)) {
		t.Errorf("version source model:\n got %#v\nwant %#v", back.Site, stripStored(v1src))
	}
	if back.Actor != "dev@example.com" || back.Op != "add" || back.ChangeID != 10 || back.Revision != "" {
		t.Errorf("version = %+v", back)
	}
	if len(back.Hosts) != 2 {
		t.Errorf("hosts = %v, want the two hosts of the snapshot", back.Hosts)
	}
	if _, err := s.GetVersion(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetVersion(unknown) = %v, want ErrNotFound", err)
	}

	// Binding fills the empty revision of every version of the change once; it never rewrites one.
	if err := s.BindRevision(ctx, 12, "abc123"); err != nil {
		t.Fatalf("BindRevision: %v", err)
	}
	if err := s.BindRevision(ctx, 12, "def456"); err != nil {
		t.Fatalf("BindRevision again: %v", err)
	}
	b2, err := s.GetVersion(ctx, got2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if b2.Revision != "abc123" {
		t.Errorf("revision = %q, want abc123 (a bound revision is never replaced)", b2.Revision)
	}
	if b1, _ := s.GetVersion(ctx, got1.ID); b1.Revision != "" {
		t.Errorf("version of another change got revision %q", b1.Revision)
	}
}

func TestSiteVersions_RefusesBadInput(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for name, mut := range map[string]func(*NewVersion){
		"no actor":   func(v *NewVersion) { v.Actor = " " },
		"no site":    func(v *NewVersion) { v.SiteID = 0 },
		"unknown op": func(v *NewVersion) { v.Op = "explode" },
	} {
		v := newVersion(roleSite(), 1, "add")
		mut(&v)
		if _, _, err := s.RecordVersion(ctx, v); err == nil {
			t.Errorf("%s: RecordVersion = nil error, want a refusal", name)
		}
	}
}
