package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// AC1: pages are chosen by source, namespace and the continue parameter, and the test can inspect
// every request the fixture received.
func TestK8sFixture_PaginationAndRequestLog(t *testing.T) {
	f := New(t)

	f.ServeList(Ingresses, "alpha",
		Page{Items: []any{object("Ingress", "a")}},
		Page{Items: []any{object("Ingress", "b")}},
	)
	f.ServeList(Ingresses, "beta", Page{Items: []any{object("Ingress", "beta-item")}})
	f.ServeList(Services, "alpha", Page{Items: []any{object("Service", "svc")}})
	f.ServeList(IngressClasses, "", Page{Items: []any{object("IngressClass", "traefik")}})

	first := f.List(t, Ingresses, "alpha", "")
	if got := itemName(t, first, 0); got != "a" {
		t.Fatalf("first ingresses page item = %q, want %q", got, "a")
	}
	if first.Metadata.Continue == "" {
		t.Fatal("first ingresses page must advertise a continue token")
	}

	second := f.List(t, Ingresses, "alpha", first.Metadata.Continue)
	if got := itemName(t, second, 0); got != "b" {
		t.Fatalf("second ingresses page item = %q, want %q", got, "b")
	}
	if itemName(t, second, 0) == itemName(t, first, 0) {
		t.Fatal("second ingresses page must differ from the first")
	}
	if second.Metadata.Continue != "" {
		t.Fatalf("last ingresses page must not advertise continue, got %q", second.Metadata.Continue)
	}

	// A different namespace of the same source answers its own page, not alpha's.
	beta := f.List(t, Ingresses, "beta", "")
	if got := itemName(t, beta, 0); got != "beta-item" {
		t.Fatalf("beta ingresses page item = %q, want %q", got, "beta-item")
	}
	if beta.Metadata.Continue != "" {
		t.Fatalf("single beta ingresses page must not advertise continue, got %q", beta.Metadata.Continue)
	}

	// A different collection answers its own page regardless of the ingresses continue token.
	services := f.List(t, Services, "alpha", "")
	if got := itemName(t, services, 0); got != "svc" {
		t.Fatalf("services page item = %q, want %q", got, "svc")
	}
	if services.Metadata.Continue != "" {
		t.Fatalf("single services page must not advertise continue, got %q", services.Metadata.Continue)
	}

	// Cluster-scoped sources carry no namespace.
	classes := f.List(t, IngressClasses, "", "")
	if got := itemName(t, classes, 0); got != "traefik" {
		t.Fatalf("ingressclasses page item = %q, want %q", got, "traefik")
	}

	got := f.Requests()
	want := []Request{
		{Method: http.MethodGet, Source: Ingresses, Namespace: "alpha"},
		{Method: http.MethodGet, Source: Ingresses, Namespace: "alpha", Continue: first.Metadata.Continue},
		{Method: http.MethodGet, Source: Ingresses, Namespace: "beta"},
		{Method: http.MethodGet, Source: Services, Namespace: "alpha"},
		{Method: http.MethodGet, Source: IngressClasses},
	}
	if len(got) != len(want) {
		t.Fatalf("request log: got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Method != want[i].Method || got[i].Source != want[i].Source ||
			got[i].Namespace != want[i].Namespace || got[i].Continue != want[i].Continue {
			t.Errorf("request %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	t.Run("empty collection and invalid token", func(t *testing.T) {
		f := New(t)
		f.ServeList(Ingresses, "alpha") // zero registered pages

		// Zero pages is an empty list, not an expired token.
		code, body := f.rawGet(t, f.Path(Ingresses, "alpha"))
		if code != http.StatusOK {
			t.Fatalf("zero-page collection: got HTTP %d, want 200: %s", code, body)
		}
		var list ListResponse
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatalf("decode zero-page list: %v: %s", err, body)
		}
		if len(list.Items) != 0 {
			t.Fatalf("zero-page collection items = %d, want 0", len(list.Items))
		}
		if list.Metadata.Continue != "" {
			t.Fatalf("zero-page collection advertised continue %q", list.Metadata.Continue)
		}

		// Positive control: a non-empty token the fixture never issued is expired.
		code, body = f.rawGet(t, f.Path(Ingresses, "alpha")+"?continue=bogus")
		if code != http.StatusGone {
			t.Fatalf("bogus continue token: got HTTP %d, want 410: %s", code, body)
		}
	})

	t.Run("unparsable path and non-GET are logged", func(t *testing.T) {
		f := New(t)

		code, _ := f.rawGet(t, "/wrong/api/prefix/ingresses")
		if code != http.StatusNotFound {
			t.Fatalf("wrong API prefix: got HTTP %d, want 404", code)
		}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.URL()+f.Path(Ingresses, "alpha"), nil)
		if err != nil {
			t.Fatalf("build POST: %v", err)
		}
		resp, err := f.Client().Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST: got HTTP %d, want 405", resp.StatusCode)
		}

		got := f.Requests()
		if len(got) != 2 {
			t.Fatalf("request log: got %d entries, want 2: %+v", len(got), got)
		}
		if got[0].Path != "/wrong/api/prefix/ingresses" || got[0].Source != "" {
			t.Errorf("unparsable path request = %+v, want path %q with empty Source", got[0], "/wrong/api/prefix/ingresses")
		}
		if got[1].Method != http.MethodPost {
			t.Errorf("non-GET request Method = %q, want %q", got[1].Method, http.MethodPost)
		}
		if got[1].Source != Ingresses {
			t.Errorf("non-GET request Source = %q, want %q", got[1].Source, Ingresses)
		}
	})
}

// AC2: 401, 403, broken JSON and a cancelled request are produced deterministically, and every
// local server the fixture started is closed.
func TestK8sFixture_FailureScenarios(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			f := New(t)
			f.Fail(Ingresses, "alpha", Failure{Status: status})

			code, body := f.rawGet(t, f.Path(Ingresses, "alpha"))
			if code != status {
				t.Fatalf("GET with Failure{Status:%d}: got HTTP %d", status, code)
			}
			var parsed struct {
				Kind string `json:"kind"`
				Code int    `json:"code"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatalf("failure body is not Kubernetes Status JSON: %v: %s", err, body)
			}
			if parsed.Kind != "Status" || parsed.Code != status {
				t.Fatalf("failure body = %+v, want kind Status code %d", parsed, status)
			}

			// The same call must answer with exactly the same bytes.
			_, again := f.rawGet(t, f.Path(Ingresses, "alpha"))
			if string(again) != string(body) {
				t.Fatalf("failure is not deterministic:\n first: %s\nsecond: %s", body, again)
			}
		}
	})

	t.Run("broken json", func(t *testing.T) {
		f := New(t)
		f.Fail(Ingresses, "alpha", Failure{Status: http.StatusOK, Body: `{"kind":"IngressList","items":[`})

		code, body := f.rawGet(t, f.Path(Ingresses, "alpha"))
		if code != http.StatusOK {
			t.Fatalf("broken JSON: got HTTP %d, want 200", code)
		}
		var parsed ListResponse
		if err := json.Unmarshal(body, &parsed); err == nil {
			t.Fatalf("broken JSON decoded without error: %s", body)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		f := New(t)
		f.Fail(Ingresses, "alpha", Failure{Hang: true})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL()+f.Path(Ingresses, "alpha"), nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		result := make(chan error, 1)
		go func() {
			resp, doErr := f.Client().Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			result <- doErr
		}()

		// Wait until the request has reached the Hang handler before cancelling, so a request that
		// never left the client cannot produce the same context.Canceled result.
		deadline := time.Now().Add(2 * time.Second)
		for len(f.Requests()) == 0 {
			if time.Now().After(deadline) {
				t.Fatal("request never reached the fixture handler")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled request: got %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled request did not return")
		}
	})

	t.Run("expired continue token", func(t *testing.T) {
		f := New(t)
		f.ServeList(Ingresses, "alpha",
			Page{Items: []any{object("Ingress", "a")}},
			Page{Items: []any{object("Ingress", "b")}},
		)
		f.ServeList(Ingresses, "beta", Page{Items: []any{object("Ingress", "beta-item")}})

		first := f.List(t, Ingresses, "alpha", "")
		foreign := first.Metadata.Continue
		if foreign == "" {
			t.Fatal("alpha page must advertise a continue token")
		}

		// Positive control: the token is valid on the namespace that issued it.
		okPage := f.List(t, Ingresses, "alpha", foreign)
		if got := itemName(t, okPage, 0); got != "b" {
			t.Fatalf("token on its own namespace: item = %q, want %q", got, "b")
		}

		// Refusal: another namespace must not accept the token.
		code, body := f.rawGet(t, f.Path(Ingresses, "beta")+"?continue="+url.QueryEscape(foreign))
		if code != http.StatusGone {
			t.Fatalf("foreign continue token: got HTTP %d, want 410: %s", code, body)
		}
	})

	t.Run("servers closed", func(t *testing.T) {
		api := New(t)
		api.ServeList(Services, "alpha", Page{})
		tlsSrv := NewTLS(t, "api.k8s.test")

		assertOpen(t, api.Addr())
		assertOpen(t, tlsSrv.Addr())

		api.Close()
		tlsSrv.Close()

		assertClosed(t, api.Addr())
		assertClosed(t, tlsSrv.Addr())
	})

	t.Run("cleanup closes servers", func(t *testing.T) {
		var apiAddr, tlsAddr string
		// The nested subtest registers New/NewTLS Cleanups; after it returns both servers must be
		// closed without this test calling Close explicitly.
		t.Run("create", func(t *testing.T) {
			api := New(t)
			api.ServeList(Services, "alpha", Page{})
			tlsSrv := NewTLS(t, "api.k8s.test")
			apiAddr, tlsAddr = api.Addr(), tlsSrv.Addr()
			assertOpen(t, apiAddr)
			assertOpen(t, tlsAddr)
		})
		assertClosed(t, apiAddr)
		assertClosed(t, tlsAddr)
	})
}

// AC3: the test CA validates the configured DNS name, a wrong name is rejected, and the observed
// Host header and TLS SNI are available to the test.
func TestK8sFixture_TLSHostAndSNI(t *testing.T) {
	const dnsName = "api.k8s.test"
	const hostHeader = "app.example.test"
	f := NewTLS(t, dnsName)

	trusted := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    f.CAPool(),
		ServerName: dnsName,
		MinVersion: tls.VersionTLS12,
	}}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.URL(), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Send a Host header deliberately different from the verified TLS name so the test can tell
	// the Host header and the SNI apart.
	req.Host = hostHeader
	resp, err := trusted.Do(req)
	if err != nil {
		t.Fatalf("correct DNS name rejected: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("correct DNS name: got HTTP %d", resp.StatusCode)
	}

	seen := f.Observations()
	if len(seen) != 1 {
		t.Fatalf("observations: got %d, want 1: %+v", len(seen), seen)
	}
	if seen[0].Host != hostHeader {
		t.Errorf("observed Host = %q, want %q", seen[0].Host, hostHeader)
	}
	if seen[0].SNI != dnsName {
		t.Errorf("observed SNI = %q, want %q", seen[0].SNI, dnsName)
	}
	if seen[0].Host == seen[0].SNI {
		t.Errorf("observed Host and SNI are both %q; the test cannot tell them apart", seen[0].Host)
	}

	wrong := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    f.CAPool(),
		ServerName: "wrong.k8s.test",
		MinVersion: tls.VersionTLS12,
	}}}
	wrongReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.URL(), nil)
	if err != nil {
		t.Fatalf("build wrong-name request: %v", err)
	}
	wrongResp, err := wrong.Do(wrongReq)
	if err == nil {
		_ = wrongResp.Body.Close()
		t.Fatal("wrong DNS name was accepted")
	}
	var hostnameErr x509.HostnameError
	if !errors.As(err, &hostnameErr) {
		t.Fatalf("wrong DNS name error = %v, want x509.HostnameError", err)
	}
	if got := len(f.Observations()); got != 1 {
		t.Fatalf("rejected handshake reached the handler: %d observations", got)
	}
}

// AC4: advancing the fake clock moves time without waiting and successive reads are stable.
func TestK8sFixture_ClockAdvance(t *testing.T) {
	start := time.Date(2026, time.October, 4, 12, 0, 0, 0, time.UTC)
	c := NewClock(start)

	if got := c.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %s, want %s", got, start)
	}
	if got := c.Now(); !got.Equal(start) {
		t.Fatalf("successive reads must be stable: got %s, want %s", got, start)
	}

	wall := time.Now()
	c.Advance(90 * time.Second)
	if got := c.Now(); !got.Equal(start.Add(90 * time.Second)) {
		t.Fatalf("after Advance(90s): got %s, want %s", got, start.Add(90*time.Second))
	}
	if elapsed := time.Since(wall); elapsed > 5*time.Second {
		t.Fatalf("Advance waited %s, want no real wait", elapsed)
	}

	c.Advance(30 * time.Second)
	if got := c.Now(); !got.Equal(start.Add(120 * time.Second)) {
		t.Fatalf("after second Advance: got %s, want %s", got, start.Add(120*time.Second))
	}

	c.Set(start)
	if got := c.Now(); !got.Equal(start) {
		t.Fatalf("after Set: got %s, want %s", got, start)
	}
}

// object builds a minimal Kubernetes object with a metadata.name, enough to tell pages apart.
func object(kind, name string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
	}
}

// itemName returns the metadata.name of item i in a decoded list page.
func itemName(t *testing.T, resp ListResponse, i int) string {
	t.Helper()
	if i >= len(resp.Items) {
		t.Fatalf("page has %d items, want index %d", len(resp.Items), i)
	}
	var obj struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(resp.Items[i], &obj); err != nil {
		t.Fatalf("decode item %d: %v", i, err)
	}
	return obj.Metadata.Name
}

// rawGet issues a GET and returns the status code and raw body.
func (f *Fixture) rawGet(t *testing.T, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.URL()+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, body
}

// assertClosed fails if addr still accepts TCP connections.
func assertClosed(t *testing.T, addr string) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("server at %s is still accepting connections after Close", addr)
	}
}

// assertOpen fails if addr does not accept TCP connections.
func assertOpen(t *testing.T, addr string) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("server at %s is not accepting connections: %v", addr, err)
	}
	_ = conn.Close()
}
