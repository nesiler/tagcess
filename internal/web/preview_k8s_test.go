package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every migrated screen has fixed previews covering its observation and form states.
func TestPreviewK8sStates(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/k8s/discovery", "app.example.com"},
		{"/k8s/discovery?state=empty", "Yeni host adayı yok."},
		{"/k8s/discovery?state=error", "discovery verisi okunamadı"},
		{"/k8s/discovery?state=setup", "Kurulum bekleniyor"},
		{"/k8s/discovery?state=stale", `data-freshness="stale"`},
		{"/k8s/discovery?state=previous", "Önceki tarama, güncel değil"},
		{"/k8s/discovery?dry=1", "dry-run"},
		{"/k8s/drafts/app.example.com", "Draft'ı kaydet"},
		{"/k8s/drafts/app.example.com?state=new", "henüz kaydedilmedi"},
		{"/k8s/drafts/app.example.com?state=empty", "Route kanıtı yok."},
		{"/k8s/drafts/app.example.com?state=error", "discovery okunamadı"},
		{"/k8s/drafts/app.example.com?state=stale", "Kaynağı yenile (seçimler korunur)"},
		{"/k8s/drafts/app.example.com?state=review", "İnceleme isteği"},
		{"/k8s/drafts/app.example.com?dry=1", "dry-run"},
	}
	handler := PreviewHandler()
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusOK || !strings.Contains(html.UnescapeString(rec.Body.String()), tc.want) {
				t.Fatalf("preview missing %q (status %d): %s", tc.want, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `href="/k8s/discovery" aria-current="page"`) {
				t.Error("preview does not mark discovery current in sidebar")
			}
		})
	}
}
