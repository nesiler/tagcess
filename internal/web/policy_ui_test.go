package web

import (
	"bytes"
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/web/ui"
)

func TestPolicyUI_FailSafeTones(t *testing.T) {
	for _, tt := range []struct {
		status string
		want   ui.Tone
	}{
		{"applied", ui.OK}, {"failed", ui.Err}, {"unknown", ui.Err},
		{"pending", ui.Warn}, {"dry_run", ui.Warn}, {"", ui.Off}, {"unexpected", ui.Off},
	} {
		t.Run("revision/"+tt.status, func(t *testing.T) {
			if got := policyStatusTone(tt.status); got != tt.want {
				t.Errorf("policyStatusTone(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
	for _, tt := range []struct {
		state string
		want  ui.Tone
	}{
		{"pass", ui.OK}, {"fail", ui.Err}, {"unverified", ui.Warn},
		{"skipped", ui.Off}, {"", ui.Off}, {"unexpected", ui.Off},
	} {
		t.Run("validation/"+tt.state, func(t *testing.T) {
			if got := stageTone(tt.state); got != tt.want {
				t.Errorf("stageTone(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestPolicyUI_DiffPreservesMarkersAndEscapes(t *testing.T) {
	rows := []diffRow{
		{Kind: diffAdd, Text: "++ <script>"},
		{Kind: diffDel, Text: "-- removed"},
		{Kind: diffNote, Text: "yalnız son satır sonu değişti"},
	}
	var buf bytes.Buffer
	if err := PolicyRawDiffPanel("Fark", rows).Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	mustContain(t, body, html.EscapeString("+ ++ <script>"), "- -- removed", "! yalnız son satır sonu değişti")
	mustNotContain(t, body, "<script>")
	buf.Reset()
	if err := PolicySemanticDiffPanel([]semanticRow{{Label: "hosts", Changed: []changedEntry{{Key: "db", Before: "100.64.0.1", After: "100.64.0.2"}}}}, true).Render(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	mustContain(t, buf.String(), "değişen: db: 100.64.0.1 → 100.64.0.2", "erişim etkisinin kanıtı değildir")
}

func TestPolicyUI_PreviewRoutes(t *testing.T) {
	h := PreviewHandler()
	for _, tt := range []struct {
		path   string
		want   []string
		absent []string
	}{
		{"/headscale/policy?state=empty", []string{"groups bölümü yok.", `action="/headscale/policy/preview"`}, nil},
		{"/headscale/policy?state=error", []string{"Headscale okunamıyor", "readonly"}, []string{`action="/headscale/policy/preview"`}},
		{"/headscale/policy?state=readonly", []string{"düzenleme kapalı", "readonly"}, []string{`action="/headscale/policy/preview"`}},
		{"/headscale/policy?state=stale", []string{"Policy dışarıdan değişti", "yeniden yükle"}, nil},
		{"/headscale/policy?state=preview&dry=1", []string{dryRunNote, confirmApplyLabel, `name="text"`, `name="report_hash"`, `name="base_hash"`, `action="/headscale/policy/save"`}, nil},
		{"/headscale/policy?state=unverified", []string{"doğrulanamadı", "kayıt kapalı"}, []string{`action="/headscale/policy/save"`}},
		{"/headscale/policy/history?state=empty", []string{"Henüz policy revision'ı yok."}, []string{"Bu sürüme dön"}},
		{"/headscale/policy/history?dry=1", []string{dryRunNote, "failed", "unknown", "dry_run", "Bu sürüme dön"}, nil},
		{"/headscale/policy/history/7?state=error", []string{"canlı policy ile fark gösterilemiyor", "Ham metin (bayt bayt)"}, []string{"Fark (ham metin):"}},
		{"/headscale/policy/history/7?state=unchanged", []string{"Canlı policy ile aynı.", "Anlamca değişiklik yok"}, nil},
		{"/headscale/policy/history/7?state=failed", []string{rollbackOnlyApplied}, []string{"Bu sürüme dön"}},
		{"/headscale/policy/history/7/rollback?dry=1", []string{dryRunNote, confirmApplyLabel, `action="/headscale/policy/history/7/rollback"`, "readonly"}, []string{`name="text"`, `name="report_hash"`}},
		{"/headscale/policy/history/7/rollback?state=error", []string{"geri alma sunulmuyor", "readonly"}, []string{confirmApplyLabel}},
		{"/headscale/policy/recovery?dry=1", []string{dryRunNote, confirmApplyLabel, `action="/headscale/policy/recovery"`, "readonly"}, []string{`name="text"`, `name="report_hash"`}},
		{"/headscale/policy/recovery?state=inactive", []string{recoveryInactive}, []string{confirmApplyLabel, "<textarea"}},
		{"/headscale/policy/recovery?state=error", []string{"Recovery bloke:", `href="/sync"`}, []string{confirmApplyLabel, "<textarea"}},
		{"/headscale/policy/recovery?state=invalid", []string{"Aday doğrulamayı geçmedi", "readonly"}, []string{confirmApplyLabel}},
		{"/headscale/policy/save?state=dry_run", []string{"Dry-run açık: yazılmadı."}, []string{"Policy apply edildi"}},
		{"/headscale/policy/save?state=unknown", []string{"Apply belirsiz:"}, []string{"Policy apply edildi"}},
		{"/headscale/policy/save?state=failed", []string{"Policy apply edilemedi;"}, []string{"Policy apply edildi"}},
		{"/headscale/policy/save", []string{"Policy apply edildi", "geri okunarak doğrulandı"}, nil},
	} {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			body := rec.Body.String()
			mustContain(t, body, tt.want...)
			mustNotContain(t, body, tt.absent...)
			if strings.Contains(body, `method="post"`) {
				mustContain(t, body, `name="`+CSRFParam+`" value="`+previewCSRF+`"`)
			}
			mustContain(t, body, `href="/headscale/policy" aria-current="page"`)
		})
	}
}

// assertPolicyHistoryStatus checks the visible value in the revision's status cell, independent
// of the component's classes and nested markup.
func assertPolicyHistoryStatus(t *testing.T, body string, id int64, want string) {
	t.Helper()
	rows := regexp.MustCompile(`(?s)<tr>(.*?)</tr>`).FindAllStringSubmatch(body, -1)
	cells := regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	tags := regexp.MustCompile(`<[^>]*>`)
	for _, row := range rows {
		if !strings.Contains(row[1], `href="/headscale/policy/history/`+strconv.FormatInt(id, 10)+`"`) {
			continue
		}
		cols := cells.FindAllStringSubmatch(row[1], -1)
		if len(cols) < 5 {
			t.Fatalf("revision #%d has %d cells", id, len(cols))
		}
		got := strings.TrimSpace(html.UnescapeString(tags.ReplaceAllString(cols[4][1], "")))
		if got != want {
			t.Errorf("revision #%d status = %q, want %q", id, got, want)
		}
		return
	}
	t.Fatalf("revision #%d row missing", id)
}
