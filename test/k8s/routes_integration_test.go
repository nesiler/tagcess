//go:build integration

package k8s

import "testing"

// TestK8sLabConflictStaysUnknown is F4-034 AC5 on the real cluster: the lab Ingress with overlapping
// paths and different backends stays a review request with no default target.
func TestK8sLabConflictStaysUnknown(t *testing.T) {
	scenarioConflict(t, labTarget(t))
}
