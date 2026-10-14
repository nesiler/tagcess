// F3b-023: a login-chain failure must never print the request URL. Go's net/http and net/url wrap a
// transport or parse failure in *url.Error, whose Error() includes the full URL (which can carry an
// OIDC authorization code, a register token or a query). safeError unwraps that to the inner error so
// a t.Fatalf message can only carry the underlying cause. This file has no build tag, so its unit
// test runs under `go test ./...` and `make check`; the integration matrix test uses the same helper.
package e2e_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// safeError returns err with a *url.Error unwrapped to its inner error. The inner error never holds
// the URL, so callers may print it and the URL, its query and any authorization code cannot leak into
// a failure message.
func safeError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// TestSafeError_HidesURL proves the helper drops the URL (and its register token / query) while
// keeping the underlying cause, and leaves a non-url error unchanged.
func TestSafeError_HidesURL(t *testing.T) {
	inner := errors.New("dial tcp 127.0.0.1:80: connect: connection refused")
	raw := "http://headscale.test/register/REGISTER-TOKEN?code=SECRET-CODE"
	got := safeError(&url.Error{Op: "Get", URL: raw, Err: inner})

	msg := got.Error()
	for _, leak := range []string{"headscale.test", "REGISTER-TOKEN", "SECRET-CODE", "http"} {
		if strings.Contains(msg, leak) {
			t.Errorf("safeError message %q still contains %q", msg, leak)
		}
	}
	if !errors.Is(got, inner) {
		t.Errorf("safeError lost the inner error: got %v, want %v", got, inner)
	}

	plain := errors.New("plain failure")
	if got := safeError(plain); !errors.Is(got, plain) {
		t.Errorf("safeError changed a non-url error: got %v, want %v", got, plain)
	}
}
