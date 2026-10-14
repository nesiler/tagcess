//go:build integration

// F2-006 compose integration: Headscale v0.29.4 consumes the extra-records file
// tagcess writes. The test runs against the local compose Headscale
// (dns.extra_records_path -> /var/lib/tagcess-dns/extra-records.json, bind-mounted
// from test/compose/dns) and verifies the atomic rename is picked up and that an
// invalid file makes Headscale log its fail-safe error while the stack keeps
// running. Requires `make lab-up` (the dns dir is seeded there).
//
// What compose cannot show: a positive "records loaded" signal needs a real
// tailscaled node to answer dig @100.100.100.100; the resolver verification is
// unit-tested in internal/dns instead and checked for real in the F2-017 prod
// dry-run. Permission semantics of macOS bind mounts are also not asserted here.
package compose_test

import (
	"context"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/dns"
)

// composeDir locates test/compose from this source file.
func dnsComposeDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate the compose dir")
	}
	return filepath.Dir(file)
}

// headscaleLogs returns the headscale container logs since a timestamp.
func headscaleLogs(t *testing.T, since time.Time) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := execDocker(ctx, "compose", "-f", filepath.Join(dnsComposeDir(t), "compose.yaml"),
		"logs", "headscale", "--since", since.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("docker compose logs headscale: %v", err)
	}
	return out
}

// TestDNSFile_HeadscaleWatches writes through the same atomic writer the
// pipeline uses and watches Headscale react: a valid file stays silent, an
// invalid one makes Headscale log its read error (old records kept), and a
// valid rewrite goes back to silence. The stack itself must stay healthy
// throughout (Headscale never crashes on a bad file).
func TestDNSFile_HeadscaleWatches(t *testing.T) {
	dir := filepath.Join(dnsComposeDir(t), "dns")
	requireHeadscaleMount(t, dir)

	path := filepath.Join(dir, "extra-records.json")
	mustMarshal := func(recs []dns.Record) string {
		t.Helper()
		body, err := dns.Marshal(recs)
		if err != nil {
			t.Fatalf("dns.Marshal: %v", err)
		}
		return body
	}
	reset := func(content string) {
		t.Helper()
		if err := dns.WriteFileAtomic(path, content); err != nil {
			t.Fatalf("WriteFileAtomic %s: %v", path, err)
		}
	}
	t.Cleanup(func() { reset("[]\n") })

	// Baseline: a valid record set, then wait out any error from earlier runs.
	reset(mustMarshal([]dns.Record{
		{Name: "f2006-test.example.com", Type: "A", Value: "100.64.0.4"},
	}))
	time.Sleep(3 * time.Second)
	baseline := time.Now()

	reset("[{broken\n")
	if err := waitForLog(t, baseline, "reading extra records from path", true); err != nil {
		t.Fatalf("invalid file was not reported by headscale: %v\n"+
			"hint: the fsnotify watcher may be stuck on an old inode (macOS bind mount, atomic rewrite); "+
			"run `docker compose -f test/compose/compose.yaml restart headscale` and rerun", err)
	}

	// The valid rewrite must go back to silence. Log counting (not --since)
	// avoids second-granularity timestamp overlap between the two phases.
	errorCount := func() int {
		return strings.Count(headscaleLogs(t, time.Time{}), "reading extra records from path")
	}
	before := errorCount()
	mark := time.Now()
	reset(mustMarshal([]dns.Record{
		{Name: "f2006-test.example.com", Type: "A", Value: "100.64.0.4"},
	}))
	// A settle window long enough for the fsnotify re-add backoff and any
	// duplicate Create/Rename event the rename produces.
	time.Sleep(6 * time.Second)
	if got := errorCount(); got != before {
		t.Errorf("valid rewrite produced %d new read errors (total %d, before %d); headscale did not accept the file",
			got-before, got, before)
	}
	t.Logf("valid rewrite took effect silently in %v", time.Since(mark).Round(time.Second))

	// The stack stayed healthy the whole time (Headscale keeps the old records
	// on a bad file instead of dying; stack-notes, extra records file).
	assertHeadscaleHealthy(t)
}

// waitForLog polls the headscale logs until needle appears (want) or stops
// appearing (!want) after the since timestamp.
func waitForLog(t *testing.T, since time.Time, needle string, want bool) error {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		logs := headscaleLogs(t, since)
		has := strings.Contains(logs, needle)
		if has == want {
			return nil
		}
		if time.Now().After(deadline) {
			return &logTimeout{needle: needle, want: want, logs: logs}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type logTimeout struct {
	needle string
	want   bool
	logs   string
}

func (e *logTimeout) Error() string {
	return "headscale logs after 15s: needle " + e.needle +
		" present=" + map[bool]string{true: "yes", false: "no"}[!e.want] + "\nlast logs:\n" + e.logs
}

// requireHeadscaleMount fails clearly when the running headscale predates the
// F2-006 compose change (no dns dir bind mount -> no extra_records_path).
func requireHeadscaleMount(t *testing.T, dir string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	container, err := execDocker(ctx, "compose", "-f", filepath.Join(dnsComposeDir(t), "compose.yaml"), "ps", "-q", "headscale")
	container = strings.TrimSpace(container)
	if err != nil || container == "" {
		t.Fatalf("headscale container is not running: %v (is `make lab-up` done?)", err)
	}
	out, err := execDocker(ctx, "inspect", container, "--format", "{{range .Mounts}}{{.Source}} {{end}}")
	if err != nil {
		t.Fatalf("docker inspect headscale: %v", err)
	}
	if !strings.Contains(out, dir) {
		t.Fatalf("headscale does not mount %s; the running stack predates F2-006 — run `make lab-up`", dir)
	}
}

func assertHeadscaleHealthy(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := execContext(ctx, "http://localhost:8090/health")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("headscale /health failed: %v (%q)", err, out)
	}
}

func execDocker(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	return string(out), err
}

// execContext GETs a URL and returns the body; errors surface as non-empty err.
func execContext(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return string(body), &statusError{code: resp.StatusCode, body: string(body)}
	}
	return string(body), nil
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return "status " + strconv.Itoa(e.code) + ": " + e.body
}
