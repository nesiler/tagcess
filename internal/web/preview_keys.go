package web

import (
	"errors"
	"net/http"

	"github.com/a-h/templ"
)

// Preview samples for the key screens (F3-017 pre-auth, F3-018 API, F3-022 personal). They render on
// fixed data without Headscale, Zitadel or a database (docs/ui-guide.md). The "state" query flag
// picks the empty, error and form-error variants each page has; "dry" shows the dry-run note.

func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/keys/preauth", "headscale", "Pre-auth key'leri", func(r *http.Request) templ.Component {
			switch r.URL.Query().Get("state") {
			case "empty":
				return KeysPage(KeysView{DryRun: previewDry(r)}, previewCSRF)
			case "expired":
				// Every key has expired: the active list shows its empty state (U-12).
				rows := previewKeyRows()
				for i := range rows {
					rows[i].Expired = true
				}
				return KeysPage(KeysView{Rows: rows, TagOptions: previewTagOptions(), DryRun: previewDry(r)}, previewCSRF)
			case "error":
				return KeysPage(KeysView{Err: errors.New("headscale: socket closed"), DryRun: previewDry(r)}, previewCSRF)
			case "tags-error":
				return KeysPage(KeysView{Rows: previewKeyRows(), TagsErr: errors.New("policy okunamadı"), DryRun: previewDry(r)}, previewCSRF)
			case "form-error":
				return KeysPage(KeysView{Rows: previewKeyRows(), TagOptions: previewTagOptions(), FormError: "En az bir tag seçilmeli.", DryRun: previewDry(r)}, previewCSRF)
			default:
				return KeysPage(KeysView{Rows: previewKeyRows(), TagOptions: previewTagOptions(), DryRun: previewDry(r)}, previewCSRF)
			}
		}},
		previewPage{"/headscale/keys/preauth/31/expire", "headscale", "Pre-auth key onayı", func(r *http.Request) templ.Component {
			return KeyConfirmPage(previewKeyConfirm("expire", previewDry(r)), previewCSRF)
		}},
		previewPage{"/headscale/keys/preauth/31/delete", "headscale", "Pre-auth key onayı", func(r *http.Request) templ.Component {
			return KeyConfirmPage(previewKeyConfirm("delete", previewDry(r)), previewCSRF)
		}},
		previewPage{"/headscale/keys/preauth/result", "headscale", "Pre-auth key sonucu", func(r *http.Request) templ.Component {
			if r.URL.Query().Get("state") == "unknown" {
				return KeyResultPage("Tag'li pre-auth key", "preauth", false, KeyOutcome{Status: keyUnknown, Message: unknownKeyCreate, KeyID: 31})
			}
			return KeyResultPage("Tag'li pre-auth key", "preauth", false, KeyOutcome{
				Status: keyApplied, Message: "Key oluşturuldu.", KeyID: 31, Secret: previewKeySecret,
			})
		}},
		previewPage{"/headscale/keys/personal", "headscale", "Kişisel pre-auth key", func(r *http.Request) templ.Component {
			switch r.URL.Query().Get("state") {
			case "empty":
				return PersonalKeyPage(PersonalKeyView{DryRun: previewDry(r)}, previewCSRF)
			case "error":
				return PersonalKeyPage(PersonalKeyView{Err: errors.New("headscale: socket closed"), DryRun: previewDry(r)}, previewCSRF)
			case "zitadel-error":
				return PersonalKeyPage(PersonalKeyView{ZitadelErr: errors.New("zitadel okunamadı: unavailable"), DryRun: previewDry(r)}, previewCSRF)
			case "form-error":
				return PersonalKeyPage(PersonalKeyView{Options: previewPersonalOptions(), FormError: "Geçersiz kullanıcı seçimi.", DryRun: previewDry(r)}, previewCSRF)
			default:
				return PersonalKeyPage(PersonalKeyView{Options: previewPersonalOptions(), DryRun: previewDry(r)}, previewCSRF)
			}
		}},
		previewPage{"/headscale/keys/personal/result", "headscale", "Kişisel pre-auth key sonucu", func(r *http.Request) templ.Component {
			return KeyResultPage("Kişisel pre-auth key", "personal", true, KeyOutcome{
				Status: keyApplied, Message: "Key oluşturuldu.", KeyID: 40, Secret: previewKeySecret,
			})
		}},
		previewPage{"/headscale/keys/api", "headscale", "API key'ler", func(r *http.Request) templ.Component {
			switch r.URL.Query().Get("state") {
			case "empty":
				return APIKeysPage(APIKeysView{DryRun: previewDry(r)}, previewCSRF)
			case "error":
				return APIKeysPage(APIKeysView{Err: errors.New("headscale/admin: ListApiKeys: down"), DryRun: previewDry(r)}, previewCSRF)
			default:
				return APIKeysPage(APIKeysView{Rows: previewAPIKeyRows(), DryRun: previewDry(r)}, previewCSRF)
			}
		}},
		previewPage{"/headscale/keys/api/4/delete", "headscale", "API key sil", func(r *http.Request) templ.Component {
			return APIKeyDeleteConfirmPage(previewAPIKeyConfirm(previewDry(r)), previewCSRF)
		}},
	)
}

// previewKeySecret is a placeholder shown only by the preview server; it is not a real key.
const previewKeySecret = "hskey-auth-preview-only-0000000000" //nolint:gosec // fixed, non-secret sample value; the preview server has no real keys

// previewDry reports whether the sample asks for the dry-run note.
func previewDry(r *http.Request) bool { return r.URL.Query().Get("dry") == "1" }

// previewKeyRows is the pre-auth key list on fixed data: an active tagged key, a used one and an
// expired one (folded away).
func previewKeyRows() []KeyRowView {
	return []KeyRowView{
		{ID: 31, Owner: "tag'li", Tags: []string{"tag:web"}, Reusable: true, Used: true, Expiry: "2026-10-05 18:44", Created: "2026-10-05 17:44", Status: "aktif"},
		{ID: 30, Owner: "alice", Expiry: "2026-10-05 18:10", Created: "2026-10-05 17:10", Status: "kullanıldı", Used: true},
		{ID: 29, Owner: "bob", Expiry: "2026-09-30 09:00", Created: "2026-09-29 09:00", Status: "süresi doldu", Expired: true},
	}
}

// previewTagOptions is the selectable tag set of the tagged key form.
func previewTagOptions() []string { return []string{"tag:web", "tag:printer"} }

// previewKeyConfirm builds the confirm page of one key action.
func previewKeyConfirm(action string, dryRun bool) KeyConfirmView {
	return KeyConfirmView{
		Row:     KeyRowView{ID: 31, Owner: "tag'li", Tags: []string{"tag:web"}, Reusable: true, Expiry: "2026-10-05 18:44", Status: "aktif"},
		Action:  action,
		Version: "ph1",
		DryRun:  dryRun,
	}
}

// previewPersonalOptions is the eligible-user list of the personal key form.
func previewPersonalOptions() []PersonalUserOption {
	return []PersonalUserOption{
		{ID: 1, Label: "alice (alice@example.com) — vpn-user"},
		{ID: 6, Label: "frank (frank@example.com) — vpn-admin"},
	}
}

// previewAPIKeyRows is the API key list on fixed data: in use, expired, no expiry and never used.
func previewAPIKeyRows() []APIKeyRowView {
	return []APIKeyRowView{
		{ID: 5, Prefix: "hskey-api-9f2Kq", CreatedAt: "2026-09-20 09:30", Expiration: "2026-12-19 09:30", LastSeen: "2026-10-05 17:42", Version: "k1"},
		{ID: 4, Prefix: "hskey-api-Lm03a", CreatedAt: "2026-07-01 10:00", Expiration: "2026-09-29 10:00", LastSeen: "2026-09-29 09:59", Expired: true, Version: "k2"},
		{ID: 3, Prefix: "hskey-api-x81Pw", CreatedAt: "2026-09-25 14:00", Expiration: "—", LastSeen: "—", NoExpiry: true, NeverUsed: true, Version: "k3"},
		{ID: 2, Prefix: "hskey-api-Tt6Rb", CreatedAt: "2026-10-01 12:00", Expiration: "2026-12-30 12:00", LastSeen: "—", NeverUsed: true, Version: "k4"},
	}
}

// previewAPIKeyConfirm builds the delete confirmation of one API key.
func previewAPIKeyConfirm(dryRun bool) APIKeyConfirmView {
	return APIKeyConfirmView{Key: APIKeyRowView{ID: 4, Prefix: "hskey-api-Lm03a"}, Version: "k2", DryRun: dryRun}
}
