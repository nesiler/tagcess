package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/policydoc"
)

// Policy samples use the real routes; query variants cover refused, empty and dry-run screens.
func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/policy", "headscale", "ACL / policy", func(r *http.Request) templ.Component {
			v := policyPageView{Text: previewPolicyText, BaseHash: "preview-base", Groups: `{"group:devops": ["carol@example.com"]}`, Editable: true, DryRun: previewPolicyDry(r)}
			switch r.URL.Query().Get("state") {
			case "empty":
				v.Text, v.Groups = "", ""
			case "error":
				v.HeadscaleErr, v.Editable = "Headscale bağlantısı kurulamadı.", false
			case "readonly":
				v.ZitadelErr, v.Editable = "Roller okunamadı.", false
			case "stale":
				v.Stale = true
			case "syntax":
				// A HuJSON syntax error: the editor marks the line, the diff is not claimed.
				p := previewPolicyPlan()
				p.Report.Stages[1] = policydoc.StageResult{Stage: policydoc.StageSyntax, State: policydoc.StateFail, Message: "invalid character '}' after object key", Line: 4, Column: 3}
				for i := 2; i < len(p.Report.Stages); i++ {
					p.Report.Stages[i].State = policydoc.StateSkipped
				}
				p.Raw, p.Semantic, p.Confirm = nil, nil, false
				v.Preview = &p
			case "preview", "unverified":
				p := previewPolicyPlan()
				if r.URL.Query().Get("state") == "unverified" {
					p.Report.Stages[4].State = policydoc.StateUnverified
					p.Report.Stages[4].Message = "Headscale bağlantısı kurulamadı."
					p.Confirm = false
				}
				v.Preview = &p
			}
			return PolicyPage(v, previewCSRF)
		}},
		previewPage{"/headscale/policy/save", "headscale", "Policy sonucu", func(r *http.Request) templ.Component {
			v := policyResultView{Outcome: "applied", Status: "applied", RevisionID: 8, GitRevision: "example-revision", DryRun: previewPolicyDry(r)}
			switch r.URL.Query().Get("state") {
			case "failed", "unknown":
				v.Outcome, v.Status = r.URL.Query().Get("state"), r.URL.Query().Get("state")
				v.Detail, v.GitRevision = "Policy geri okunarak doğrulanamadı.", ""
			case "dry_run":
				v.Outcome, v.Status, v.DryRun, v.GitRevision = "dry_run", "dry_run", true, ""
			}
			return PolicyResultPage(v)
		}},
		previewPage{"/headscale/policy/history", "headscale", "Policy geçmişi", func(r *http.Request) templ.Component {
			v := policyHistoryView{DryRun: previewPolicyDry(r), Rows: previewPolicyRevisions()}
			if r.URL.Query().Get("state") == "empty" {
				v.Rows = nil
			}
			return PolicyHistoryPage(v)
		}},
		previewPage{"/headscale/policy/history/7", "headscale", "Policy revision'ı", func(r *http.Request) templ.Component {
			p := previewPolicyPlan()
			v := policyRevisionView{DryRun: previewPolicyDry(r), Row: previewPolicyRevisions()[0], Raw: previewPolicyText, Raw2Live: p.Raw, Semantic: p.Semantic}
			switch r.URL.Query().Get("state") {
			case "error":
				v.HeadscaleErr = "Headscale bağlantısı kurulamadı."
			case "unchanged":
				v.Raw2Live, v.Semantic = nil, nil
			case "failed":
				v.Row = previewPolicyRevisions()[1]
			}
			return PolicyRevisionPage(v)
		}},
		previewPage{"/headscale/policy/history/7/rollback", "headscale", "Policy geri alma", func(r *http.Request) templ.Component {
			p := previewPolicyPlan()
			p.Text, p.ReportHash, p.SaveAction = "", "", "/headscale/policy/history/7/rollback"
			v := policyRollbackView{DryRun: previewPolicyDry(r), Row: previewPolicyRevisions()[0], Raw: previewPolicyText, Page: policyPageView{BaseHash: "preview-base"}, Preview: &p}
			if r.URL.Query().Get("state") == "error" {
				v.Blocked, v.Preview = "Canlı policy okunamadı; geri alma sunulmuyor.", nil
			}
			return PolicyRollbackPage(v, previewCSRF)
		}},
		previewPage{"/headscale/policy/recovery", "headscale", "Kontrollü recovery", func(r *http.Request) templ.Component {
			p := previewPolicyPlan()
			p.Text, p.ReportHash, p.SaveAction = "", "", "/headscale/policy/recovery"
			target := previewPolicyRevisions()[0]
			v := policyRecoveryView{DryRun: previewPolicyDry(r), Uncertain: "Son yazım geri okunamadı", Target: &target, Candidate: previewPolicyText, Preview: &p, BaseHash: "preview-base"}
			switch r.URL.Query().Get("state") {
			case "inactive":
				v.Inactive = true
			case "error":
				v.Blocked, v.SyncPending, v.Preview, v.Target = "Bekleyen grup değişikliği var.", true, nil, nil
			case "invalid":
				p.Confirm = false
				p.Report.Stages[4].State, p.Report.Stages[4].Message = policydoc.StateFail, "Kilitli test başarısız."
			}
			return PolicyRecoveryPage(v, previewCSRF)
		}},
	)
}

func previewPolicyDry(r *http.Request) bool { return r.URL.Query().Get("dry") == "1" }

const previewPolicyText = `{
  // Headscale politikası; gruplar Zitadel'den yeniden kurulur.
  "groups": {"group:devops": ["carol@example.com"]},
  "tagOwners": {"tag:web": ["group:devops"]},
  "acls": [
    {"action": "accept", "src": ["group:devops"], "dst": ["tag:web:443"]}
  ]
}
`

func previewPolicyPlan() policyPreviewView {
	return policyPreviewView{
		Report: policydoc.Report{Stages: []policydoc.StageResult{
			{Stage: policydoc.StageInput, State: policydoc.StatePass},
			{Stage: policydoc.StageSyntax, State: policydoc.StatePass},
			{Stage: policydoc.StageStructure, State: policydoc.StatePass},
			{Stage: policydoc.StageLocked, State: policydoc.StatePass},
			{Stage: policydoc.StageCheck, State: policydoc.StatePass},
		}},
		Raw:           []diffRow{{Kind: diffDel, Text: `"dst": ["tag:web:80"]`}, {Kind: diffAdd, Text: `"dst": ["tag:web:443"]`}},
		Semantic:      []semanticRow{{Section: "acls", Label: "ACL kuralı", Added: []string{`tag:web:443`}, Removed: []string{`tag:web:80`}}},
		GroupsRebuilt: true, Locked: []string{"tagcess arayüzüne erişim"}, Confirm: true,
		Text: previewPolicyText, ReportHash: "preview-report",
	}
}

func previewPolicyRevisions() []policyRevRow {
	at := time.Date(2026, 10, 6, 9, 30, 0, 0, time.UTC)
	return []policyRevRow{
		{ID: 7, At: at, Actor: "carol", Source: "rollback", Status: "applied", Reason: "ACL kuralı geri alındı", RollbackOf: 4, CanRollback: true},
		{ID: 6, At: at.Add(-time.Hour), Actor: "dave", Source: "ui", Status: "failed", Reason: "Headscale doğrulaması reddedildi", Detail: "Kilitli test başarısız."},
		{ID: 5, At: at.Add(-2 * time.Hour), Actor: "carol", Source: "ui", Status: "dry_run", Reason: "Dry-run açık: yazılmadı."},
		{ID: 4, At: at.Add(-3 * time.Hour), Actor: "carol", Source: "ui", Status: "unknown", Reason: "Geri okuma başarısız"},
	}
}
