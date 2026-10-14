//go:build integration

package k8s

import "testing"

// TestK8sLab_CredentialExpiryKeepsLastGoodSnapshot is F4-034 AC3 on the real cluster: the lab revokes
// the token (the API answers 401, as for an expired one) and the last complete snapshot stays.
func TestK8sLab_CredentialExpiryKeepsLastGoodSnapshot(t *testing.T) {
	scenarioExpiry(t, labTarget(t))
}

// TestReadOnlyCredentialRotationKeepsSnapshots is F4-034 AC4 on the real cluster: a new token the
// installer issued is uploaded through the UI and the next full read completes with it.
func TestReadOnlyCredentialRotationKeepsSnapshots(t *testing.T) {
	scenarioRotation(t, labTarget(t))
}
