package site

import (
	"context"
	"errors"
	"testing"
)

// F2-011: the change pipeline validates a site write against the real store rules before it
// touches any external system, and commits the record only after every artifact is applied. The
// Preview methods run the whole write (validation, system locks, host ownership) inside a
// transaction that is rolled back, so what they accept is exactly what the commit will accept.

func TestPreview_CreateAcceptsAndWritesNothing(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	got, err := s.PreviewCreateSite(ctx, validRoleSite())
	if err != nil {
		t.Fatalf("PreviewCreateSite: %v", err)
	}
	if got.ID == 0 || len(got.Hosts) != 1 {
		t.Fatalf("previewed site = %+v, want the stored shape with an id", got)
	}
	list, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("preview wrote %d sites, want none", len(list))
	}
	// The same record commits afterwards and gets the id the preview announced.
	stored, err := s.CreateSite(ctx, validRoleSite())
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if stored.ID != got.ID {
		t.Errorf("committed id = %d, preview announced %d", stored.ID, got.ID)
	}
}

func TestPreview_CreateRefusals(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.CreateSite(ctx, validRoleSite()); err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	dup := validRoleSite()
	if _, err := s.PreviewCreateSite(ctx, dup); !errors.Is(err, ErrHostTaken) {
		t.Errorf("duplicate host: err = %v, want ErrHostTaken", err)
	}
	bad := validRoleSite()
	bad.Hosts = []string{"evil.example.com\nimport x"}
	if _, err := s.PreviewCreateSite(ctx, bad); err == nil {
		t.Error("an injected host passed the preview")
	}
}

func TestPreview_UpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	stored, err := s.CreateSite(ctx, validRoleSite())
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}

	edit := validRoleSite()
	edit.Roles = []string{"devops"}
	got, err := s.PreviewUpdateSite(ctx, stored.ID, edit)
	if err != nil {
		t.Fatalf("PreviewUpdateSite: %v", err)
	}
	if len(got.Roles) != 1 {
		t.Errorf("previewed roles = %v, want [devops]", got.Roles)
	}
	cur, err := s.GetSite(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if len(cur.Roles) != 2 {
		t.Errorf("preview changed the stored roles to %v", cur.Roles)
	}
	if _, err := s.PreviewUpdateSite(ctx, 999, edit); !errors.Is(err, ErrNotFound) {
		t.Errorf("update of a missing site: err = %v, want ErrNotFound", err)
	}

	if err := s.PreviewDeleteSite(ctx, stored.ID); err != nil {
		t.Fatalf("PreviewDeleteSite: %v", err)
	}
	if _, err := s.GetSite(ctx, stored.ID); err != nil {
		t.Errorf("preview deleted the site: %v", err)
	}
	sys, err := s.CreateSite(ctx, systemSite())
	if err != nil {
		t.Fatalf("CreateSite system: %v", err)
	}
	if err := s.PreviewDeleteSite(ctx, sys.ID); !errors.Is(err, ErrSystemLocked) {
		t.Errorf("delete of a system site: err = %v, want ErrSystemLocked", err)
	}
}
