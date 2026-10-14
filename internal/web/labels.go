package web

import (
	"regexp"
	"strings"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dashboard"
	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
)

// labels.go maps the stable internal codes (alert kinds/sources, drift subjects, boundary kinds,
// stored evidence strings) to the Turkish text a user reads (F5 N1/N2). The codes stay in the data
// model and in title/data-* attributes; mapping happens only at render time, so stored alert keys,
// dedup and resolve logic are untouched. An unknown code falls back to the raw value.

// labelOr returns table[code], or code itself when the table does not know it.
func labelOr(table map[string]string, code string) string {
	if l, ok := table[code]; ok {
		return l
	}
	return code
}

var alertKindLabels = map[string]string{
	alert.KindTargetHealth: "Sağlık kontrolü",
	alert.KindTLSExpiry:    "TLS sertifika süresi",
	alert.KindSourceStale:  "Kaynak güncel değil",
	alert.KindDrift:        "Config drift",
}

// alertKindLabel is the Turkish title of an alert kind.
func alertKindLabel(kind string) string { return labelOr(alertKindLabels, kind) }

var alertSourceLabels = map[string]string{
	alert.AlertSourceTarget: "Hedef sağlığı",
	alert.AlertSourceGate:   "Caddy erişim gate'i",
	alert.AlertSourceTLS:    "TLS sertifikası",
	alert.AlertSourceStore:  "Kontrol kayıtları",
	alert.SourceDrift:       "Apply edilen temel",
	"config_risk":           "Config riski",
}

// alertSourceLabel is the Turkish name of an alert source.
func alertSourceLabel(source string) string { return labelOr(alertSourceLabels, source) }

var severityLabels = map[string]string{
	string(alert.SeverityInfo):     "bilgi",
	string(alert.SeverityWarning):  "uyarı",
	string(alert.SeverityCritical): "kritik",
}

// severityLabel is the Turkish severity.
func severityLabel(severity string) string { return labelOr(severityLabels, severity) }

var driftSubjectLabels = map[string]string{
	alert.SubjectPolicy:    "Headscale policy",
	alert.SubjectCaddyFile: "Caddyfile (disk)",
	alert.SubjectCaddyLive: "Çalışan Caddy config'i",
	alert.SubjectDNS:       "DNS kayıtları",
	alert.SubjectURIs:      "Zitadel redirect URI'leri",
}

// driftSubjectLabel is the Turkish name of a drift artifact.
func driftSubjectLabel(subject string) string { return labelOr(driftSubjectLabels, subject) }

// alertSubjectLabel names an alert subject. Only the drift source uses artifact names; every other
// subject is a site host and is shown as-is.
func alertSubjectLabel(kind, source, subject string) string {
	if kind == alert.KindDrift || source == alert.SourceDrift {
		return driftSubjectLabel(subject)
	}
	return subject
}

// evidenceText is the Turkish rendering of the fixed English evidence strings the alert package
// stores (drift.go, sources.go). Rows written before this mapping render through it as well.
var evidenceText = map[string]string{
	// drift.go
	"the hold state could not be read":                   "bekletme durumu okunamadı",
	"an apply or maintenance window holds the artifacts": "apply veya bakım penceresi karşılaştırmayı bekletiyor",
	"the first import state could not be read":           "ilk import durumu okunamadı",
	"first import is pending: no applied baseline yet":   "ilk import bekleniyor: henüz apply edilmiş temel yok",
	"the site records could not be read":                 "site kayıtları okunamadı",
	"the render settings could not be read":              "oluşturma ayarları okunamadı",
	"source read timed out":                              "kaynak okuması zaman aşımına uğradı",
	"source could not be read":                           "kaynak okunamadı",
	"no applied policy revision to compare with":         "karşılaştırılacak apply edilmiş policy revision'ı yok",
	"a newer policy revision is pending or unverified":   "daha yeni bir policy revision'ı bekliyor veya doğrulanmadı",
	"stored sites do not render to a Caddyfile":          "kayıtlı sitelerden Caddyfile üretilemedi",
	"stored sites do not render to DNS records":          "kayıtlı sitelerden DNS kayıtları üretilemedi",
	"DNS records file is missing":                        "DNS kayıt dosyası yok",
	"no owned redirect URI record yet":                   "henüz tagcess'e ait redirect URI kaydı yok",
	"stored sites do not produce redirect URIs":          "kayıtlı siteler redirect URI'si üretmiyor",
	// sources.go
	"site list could not be read":         "site listesi okunamadı",
	"observation store could not be read": "kontrol kayıtları okunamadı",
	"check failed":                        "kontrol başarısız",
	"alternate path candidate":            "alternatif yol adayı",
	"unknown configuration risk":          "bilinmeyen config riski",
	"configuration risk recorded":         "config riski kaydedildi",
	"network measurement recorded":        "ağ kontrolü kaydedildi",
	"no attempt recorded":                 "deneme kaydı yok",
	"incomplete observation":              "eksik kontrol kaydı",
	"unknown observation category":        "bilinmeyen kontrol türü",
	"unreadable leaf expiry":              "sertifika bitiş tarihi okunamadı",
	"no verified leaf recorded":           "doğrulanmış sertifika kaydı yok",
	"legacy alerts could not be read":     "eski uyarılar okunamadı",
	"no sync run recorded":                "sync çalışması kaydı yok",
	"sync run could not be read":          "sync çalışması okunamadı",
	"pending changes could not be read":   "bekleyen değişiklikler okunamadı",
	"site removed":                        "site kaldırıldı",
	"no recent measurement":               "yakın zamanda kontrol yok",
}

func init() {
	// The health runner's failure texts are stored as health evidence; they share the dashboard's
	// Turkish failure labels, so the two tables cannot drift apart.
	for _, l := range health.FailureLabels() {
		if en, ok := health.FailureText(l); ok {
			if tr, ok := observationResultText[l]; ok {
				evidenceText[en] = tr
			}
		}
	}
}

// evidencePatterns render the formatted evidence strings (counts, revision ids). A trailing part
// (the Turkish template hint) is kept as-is.
var evidencePatterns = []struct {
	re  *regexp.Regexp
	out func(m []string) string
}{
	{regexp.MustCompile(`(?s)^running Caddy config differs from the applied records\.(.*)$`),
		func(m []string) string {
			return "Çalışan Caddy config'i apply edilen kayıtlardan farklı." + m[1]
		}},
	{regexp.MustCompile(`(?s)^Caddyfile on disk differs from the applied records \((\d+) lines\)\.(.*)$`),
		func(m []string) string {
			return "Diskteki Caddyfile apply edilen kayıtlardan farklı (" + m[1] + " satır)." + m[2]
		}},
	{regexp.MustCompile(`^live policy differs from applied revision #(\d+)$`),
		func(m []string) string { return "Canlı policy, apply edilen #" + m[1] + " revision'ından farklı" }},
	{regexp.MustCompile(`^DNS records file differs from the applied records \((\d+) lines\)$`),
		func(m []string) string {
			return "DNS kayıt dosyası apply edilen kayıtlardan farklı (" + m[1] + " satır)"
		}},
	{regexp.MustCompile(`^redirect URIs: (\d+) desired missing, (\d+) stale owned still present$`),
		func(m []string) string {
			return "Redirect URI'leri: " + m[1] + " istenen eksik, " + m[2] + " eski kayıt hâlâ duruyor"
		}},
}

const networkFailedPrefix = "network measurement failed: "

// alertEvidenceText renders a stored evidence string in Turkish; an unknown string (for example
// "HTTP 503" or a truncated summary) is shown as-is.
func alertEvidenceText(evidence string) string {
	if tr, ok := evidenceText[evidence]; ok {
		return tr
	}
	if rest, ok := strings.CutPrefix(evidence, networkFailedPrefix); ok {
		return "ağ kontrolü başarısız: " + alertEvidenceText(rest)
	}
	for _, p := range evidencePatterns {
		if m := p.re.FindStringSubmatch(evidence); m != nil {
			return p.out(m)
		}
	}
	return evidence
}

var boundaryKindLabels = map[string]string{
	dashboard.BoundaryS06Source:      "Tailnet dışı erişim",
	dashboard.BoundaryAPIExemption:   "API bypass",
	dashboard.BoundaryOpenIntent:     "Rolsüz site",
	dashboard.BoundarySystemTemplate: "Sistem sitesi",
	dashboard.BoundaryHeadscaleACL:   "Headscale ACL",
}

// boundaryKindLabel is the Turkish heading of a dashboard access boundary.
func boundaryKindLabel(kind string) string { return labelOr(boundaryKindLabels, kind) }

var loopJobLabels = map[string]string{
	monitor.JobInventory: "k8s envanteri",
	monitor.JobAlerts:    "Uyarı değerlendirme",
	monitor.JobDrift:     "Drift kontrolü",
	monitor.JobHealth:    "Sağlık kontrolleri",
}

// loopJobLabel is the Turkish name of a monitor loop job.
func loopJobLabel(job string) string { return labelOr(loopJobLabels, job) }

var loopStateLabels = map[string]string{
	string(monitor.StateFresh):   "güncel",
	string(monitor.StateStale):   "güncel değil",
	string(monitor.StateUnknown): "bilinmiyor",
	string(monitor.StateMissing): "bekliyor",
	string(monitor.StateError):   "hata",
}

// loopStateLabel is the Turkish state of a monitor loop job.
func loopStateLabel(state string) string { return labelOr(loopStateLabels, state) }

var syncResultLabels = map[string]string{
	"applied":          "apply edildi",
	"no_change":        "değişiklik yok",
	"dry_run":          "deneme (dry-run)",
	"failed":           "başarısız",
	"read_failed":      "okuma başarısız",
	"blocked":          "engellendi",
	"held":             "bekletildi",
	"needs_reapproval": "yeniden onay gerekli",
	"pending_approval": "onay bekliyor",
}

// syncResultLabel is the Turkish result of a sync run.
func syncResultLabel(result string) string { return labelOr(syncResultLabels, result) }

var syncTriggerLabels = map[string]string{
	"webhook":  "webhook",
	"periodic": "periyodik",
	"manual":   "elle",
}

// syncTriggerLabel is the Turkish trigger of a sync run.
func syncTriggerLabel(trigger string) string { return labelOr(syncTriggerLabels, trigger) }

var observationSourceLabels = map[string]string{
	health.SourceConfig:   "k8s config'i",
	health.SourceNetProbe: "ağ kontrolü",
	obsCategoryTarget:     "hedef",
	obsCategoryGate:       "Caddy erişim gate'i",
	obsCategoryTLS:        "TLS",
}

// observationSourceLabel is the Turkish name of an observation row's source.
func observationSourceLabel(source string) string { return labelOr(observationSourceLabels, source) }

var snapshotOutcomeLabels = map[string]string{
	k8s.OutcomeOK:     "başarılı",
	k8s.OutcomeFailed: "başarısız",
}

// snapshotOutcomeLabel is the Turkish outcome of a k8s snapshot attempt.
func snapshotOutcomeLabel(outcome string) string { return labelOr(snapshotOutcomeLabels, outcome) }

// alertStateText is the Turkish lifecycle state of a stored state string.
func alertStateText(state string) string {
	if l := alertStateLabel(alert.State(state)); l != "" {
		return l
	}
	return state
}

var legacyAlertKindLabels = map[string]string{
	"reconcile_read_failed":     "Sync okuması başarısız",
	"key_revoke_failed":         "Key iptali başarısız",
	"policy_mismatch":           "Canlı policy apply edilen revision'la uyuşmuyor",
	"policy_expire_failed":      "Cihaz süre sonlandırma başarısız",
	"policy_unverified":         "Policy apply'ı doğrulanamadı",
	"policy_stale":              "Policy revision'ı güncel değil",
	"policy_bookkeeping_failed": "Policy kaydı tutulamadı",
	"site_drift":                "Site config'i apply edilenden farklı",
	"site_unverified":           "Site değişikliği doğrulanamadı",
	"site_partial":              "Site değişikliği yarım kaldı",
	"site_rollback_failed":      "Site geri alma başarısız",
	"site_caddy_file":           "Caddyfile yazılamadı veya okunamadı",
	"site_dns_unverified":       "DNS kayıtları doğrulanamadı",
	"site_bookkeeping_failed":   "Site kaydı tutulamadı",
	"zitadel_uri_drift":         "Zitadel redirect URI'leri farklı",
}

// legacyAlertKindLabel is the Turkish title of an F1-F3 pipeline alarm kind.
func legacyAlertKindLabel(kind string) string { return labelOr(legacyAlertKindLabels, kind) }

var systemSourceLabels = map[string]string{
	"zitadel":   "Zitadel",
	"headscale": "Headscale",
	"caddy":     "Caddy",
	"dns":       "DNS",
}

// systemSourceLabel names the external system a legacy alarm came from.
func systemSourceLabel(source string) string { return labelOr(systemSourceLabels, source) }

var k8sClassLabels = map[string]string{
	k8s.ClassCredentialExpired:  "credential'ın süresi dolmuş (401)",
	k8s.ClassForbidden:          "yetki yok (403)",
	k8s.ClassHTTP:               "beklenmeyen HTTP yanıtı",
	k8s.ClassTimeout:            "zaman aşımı",
	k8s.ClassCanceled:           "iptal edildi",
	k8s.ClassDecode:             "yanıt çözümlenemedi",
	k8s.ClassTLS:                "TLS hatası",
	k8s.ClassConnect:            "bağlantı kurulamadı",
	k8s.ClassDenied:             "API adresi izin verilenler dışında",
	k8s.ClassCredential:         "credential yok veya okunamadı",
	k8s.ClassCredentialMismatch: "credential profille uyuşmuyor",
	k8s.ClassRead:               "okuma başarısız",
}

// k8sClassLabel is the Turkish failure class of a k8s read attempt.
func k8sClassLabel(class string) string { return labelOr(k8sClassLabels, class) }

var auditResultLabels = map[string]string{
	"requested": "istendi",
	"applied":   "apply edildi",
	"ok":        "başarılı",
	"failed":    "başarısız",
	"error":     "hata",
	"blocked":   "engellendi",
	"rejected":  "reddedildi",
	"denied":    "reddedildi",
	"approved":  "onaylandı",
	"skipped":   "atlandı",

	// Every other result the app writes to the audit log (change, hsadmin, hostapply, gitlog, sync).
	"started":           "başladı",
	"rolled_back":       "geri alındı",
	"warning":           "uyarı",
	"unknown":           "bilinmiyor",
	"stale":             "güncel değil",
	"quarantined":       "karantinaya alındı",
	"dry_run":           "deneme (dry-run)",
	"no_change":         "değişiklik yok",
	"held":              "bekletildi",
	"needs_reapproval":  "yeniden onay gerekli",
	"pending_approval":  "onay bekliyor",
	"reconcile_pending": "uzlaştırma bekliyor",
	"off":               "kapalı",
	"accepted":          "kabul edildi",
	"applying":          "apply ediliyor",
	"succeeded":         "başarılı",
	"interrupted":       "yarıda kesildi",
}

// auditResultLabel is the Turkish result of an audit entry; the event name stays a code (it is the
// search key of the audit filter).
func auditResultLabel(result string) string { return labelOr(auditResultLabels, result) }

var siteOpLabels = map[string]string{
	change.SiteAdd:       "Ekleme",
	change.SiteUpdate:    "Güncelleme",
	change.SiteDelete:    "Silme",
	change.SiteResync:    "Kayıtlardan yeniden apply",
	change.SiteManualDNS: "Elle DNS kayıtları",
}

// siteOpLabel is the Turkish name of a site change operation.
func siteOpLabel(op string) string { return labelOr(siteOpLabels, op) }
