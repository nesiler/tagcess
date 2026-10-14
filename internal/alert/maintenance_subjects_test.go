package alert

import (
	"context"
	"reflect"
	"testing"
)

func TestMaintenanceSubjectsListsOnlyOnSites(t *testing.T) {
	svc, _, _, _ := openService(t)
	ctx := context.Background()
	for subject, muted := range map[string]bool{"b.example": true, "a.example": true, "c.example": false} {
		if err := svc.SetMaintenance(ctx, subject, muted); err != nil {
			t.Fatalf("SetMaintenance %s: %v", subject, err)
		}
	}
	got, err := svc.MaintenanceSubjects(ctx)
	if err != nil || !reflect.DeepEqual(got, []string{"a.example", "b.example"}) {
		t.Fatalf("MaintenanceSubjects = %v, %v", got, err)
	}
}
