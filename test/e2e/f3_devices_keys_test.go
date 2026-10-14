//go:build integration

// End-to-end scenarios for F3-026 (devices, routes, keys, users): the real tagcess binary driven
// through its interface on the unix socket, a disposable database-mode Headscale and the lab
// Zitadel. See f3_stack_test.go and `make e2e`.
package e2e_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nesiler/tagcess/test/compose/seed"
)

// deviceFields reads the hidden fields a device's detail page posts back (the version stamp the
// executor checks, the name and expiry as shown).
func (s *f3Stack) deviceFields(id uint64, extra url.Values) url.Values {
	s.t.Helper()
	form := formOf{s.ui.getOK(devicePath(id, ""))}
	v := url.Values{
		"expected":       {form.value("expected")},
		"current_name":   {form.value("current_name")},
		"current_expiry": {form.value("current_expiry")},
	}
	if v.Get("expected") == "" {
		s.t.Fatalf("the detail page of device %d offers no form version", id)
	}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

// deviceAction posts one device action with the page's own version stamp.
func (s *f3Stack) deviceAction(id uint64, suffix string, extra url.Values) (int, string) {
	s.t.Helper()
	return s.ui.post(devicePath(id, suffix), s.deviceFields(id, extra))
}

// wantApplied fails unless the result screen says the action was applied.
func wantApplied(t *testing.T, what string, code int, body string) {
	t.Helper()
	if code != http.StatusOK || !strings.Contains(body, "Apply edildi") {
		t.Fatalf("%s: status %d, want an applied result: %s", what, code, excerpt(body))
	}
}

// AC1: personal, server-tagged and shared-tagged devices are listed; the personal device can be
// renamed, given and relieved of an expiry, expired and deleted; the server device refuses delete,
// expire, expiry changes and tag changes from the interface and from a hand-made POST, while its
// rename and route approval work.
func TestE2E_F3_DeviceLifecycleAndProtection(t *testing.T) {
	var alice f3User
	var laptop, gw, kiosk uint64
	const subnet = "10.88.0.0/24"
	s := newF3Stack(t, f3Options{prepare: func(s *f3Stack) {
		alice = s.user("alice", "standart")
		s.hs.CreateUser(s.t, "f3026-ops")
		laptop = s.hs.NewNode(s.t, alice.hsName, "alice-laptop", "")
		gw = s.hs.NewNode(s.t, "f3026-ops", "gw-1", f3ServerTag)
		kiosk = s.hs.NewNode(s.t, "f3026-ops", "kiosk-1", f3SharedTag)
		s.hs.SetNodeRoutableIPs(s.t, "gw-1", []string{subnet})
	}})

	// The list shows all three kinds.
	list := s.ui.getOK("/headscale/devices")
	mustContain(t, "device list", list, "alice-laptop", "gw-1", "kiosk-1", alice.hsName, f3ServerTag, f3SharedTag)
	if got := s.mustNode(kiosk); !slices.Equal(got.Tags, []string{f3SharedTag}) {
		t.Fatalf("the shared device has tags %v", got.Tags)
	}

	s.section(t, "personal device", func(t *testing.T) {
		code, body := s.deviceAction(laptop, "/rename", url.Values{"name": {"alice-notebook"}})
		wantApplied(t, "rename", code, body)
		if n := s.mustNode(laptop); n.GivenName != "alice-notebook" {
			t.Fatalf("given name = %q, want alice-notebook", n.GivenName)
		}

		future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
		code, body = s.deviceAction(laptop, "/expiry", url.Values{"expiry": {future}})
		wantApplied(t, "set expiry", code, body)
		if n := s.mustNode(laptop); n.Expiry == nil || !n.Expiry.After(time.Now().Add(24*time.Hour)) {
			t.Fatalf("expiry = %v, want about 48h ahead", n.Expiry)
		}

		code, body = s.deviceAction(laptop, "/expiry/disable", nil)
		wantApplied(t, "disable expiry", code, body)
		if n := s.mustNode(laptop); n.Expiry != nil {
			t.Fatalf("expiry = %v, want none", n.Expiry)
		}

		code, body = s.deviceAction(laptop, "/expire", nil)
		wantApplied(t, "expire now", code, body)
		if n := s.mustNode(laptop); !expired(n) {
			t.Fatalf("expiry = %v, want a past instant", n.Expiry)
		}

		// Deleting takes the confirm page: a POST without the confirmation is refused.
		if code, _ := s.deviceAction(laptop, "/delete", nil); code != http.StatusBadRequest {
			t.Fatalf("delete without the confirmation: status %d, want 400", code)
		}
		if _, ok := s.node(laptop); !ok {
			t.Fatal("the device was deleted without the confirmation")
		}
		confirm := s.ui.getOK(devicePath(laptop, "/delete"))
		mustContain(t, "delete confirmation", confirm, "alice-notebook", "geri alınamaz")
		code, body = s.deviceAction(laptop, "/delete", url.Values{"confirm": {"evet"}})
		wantApplied(t, "delete", code, body)
		if _, ok := s.node(laptop); ok {
			t.Fatal("the device is still in Headscale after the delete")
		}
	})

	s.section(t, "server device", func(t *testing.T) {
		detail := s.ui.getOK(devicePath(gw, ""))
		mustContain(t, "server device page", detail, "korumalı sunucu", "Adı değiştir")
		mustNotContain(t, "server device page", detail, "Şimdi expire et", "Süreyi ayarla", "Expire&#39;i kapat", "Cihazı sil")

		before := s.mustNode(gw)
		future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
		for _, c := range []struct {
			name, suffix string
			extra        url.Values
		}{
			{"delete", "/delete", url.Values{"confirm": {"evet"}}},
			{"expire", "/expire", nil},
			{"set expiry", "/expiry", url.Values{"expiry": {future}}},
			{"disable expiry", "/expiry/disable", nil},
		} {
			if code, body := s.deviceAction(gw, c.suffix, c.extra); code != http.StatusConflict {
				t.Errorf("%s on a server device: status %d, want 409: %s", c.name, code, excerpt(body))
			}
		}
		// A tag change (a shared tag, and a protected one) is refused too.
		for _, tag := range []string{f3SharedTag, f3ServerTag} {
			form := formOf{s.ui.getOK(devicePath(gw, "/tags"))}
			code, body := s.ui.post(devicePath(gw, "/tags"), url.Values{"version": {form.value("version")}, "tag": {tag}})
			if code != http.StatusForbidden {
				t.Errorf("tag change to %s on a server device: status %d, want 403: %s", tag, code, excerpt(body))
			}
		}
		after, ok := s.node(gw)
		if !ok {
			t.Fatal("the server device was deleted")
		}
		if !slices.Equal(after.Tags, before.Tags) || (after.Expiry == nil) != (before.Expiry == nil) {
			t.Errorf("the server device changed: tags %v → %v, expiry %v → %v", before.Tags, after.Tags, before.Expiry, after.Expiry)
		}

		// Rename and route approval still work.
		code, body := s.deviceAction(gw, "/rename", url.Values{"name": {"gw-main"}})
		wantApplied(t, "rename of the server device", code, body)
		if n := s.mustNode(gw); n.GivenName != "gw-main" {
			t.Fatalf("given name = %q, want gw-main", n.GivenName)
		}
		routes := formOf{s.ui.getOK(devicePath(gw, "/routes"))}
		mustContain(t, "route page", routes.body, subnet)
		code, body = s.ui.post(devicePath(gw, "/routes"), url.Values{"version": {routes.value("version")}, "route": {subnet}})
		if code != http.StatusSeeOther {
			t.Fatalf("route approval: status %d: %s", code, excerpt(body))
		}
		if n := s.mustNode(gw); !slices.Equal(n.ApprovedRoutes, []string{subnet}) {
			t.Fatalf("approved routes in Headscale = %v, want [%s]", n.ApprovedRoutes, subnet)
		}
	})
}

// apiKeyIDs lists the API key ids of the disposable Headscale.
func (s *f3Stack) apiKeyIDs() []uint64 {
	s.t.Helper()
	keys, err := s.adm.ListApiKeys(context.Background())
	if err != nil {
		s.t.Fatalf("list api keys: %v", err)
	}
	ids := make([]uint64, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids
}

// AC4: API keys made through the raw API are only listed, expired and deleted in the interface;
// there is no create route.
func TestE2E_F3_APIKeysListExpireDeleteOnly(t *testing.T) {
	s := newF3Stack(t, f3Options{})
	api := s.hs.Raw()
	exp := timestamppb.New(time.Now().Add(24 * time.Hour))
	for range 2 {
		resp, err := api.CreateApiKey(context.Background(), &v1.CreateApiKeyRequest{Expiration: exp})
		if err != nil {
			t.Fatalf("raw CreateApiKey: %v", err)
		}
		if resp.GetApiKey() == "" {
			t.Fatal("the raw API returned no key value")
		}
	}
	ids := s.apiKeyIDs()
	if len(ids) != 2 {
		t.Fatalf("api keys in Headscale = %v, want 2", ids)
	}

	page := s.ui.getOK("/headscale/keys/api")
	for _, id := range ids {
		mustContain(t, "api key list", page, ">"+strconv.FormatUint(id, 10)+"<")
	}
	mustContain(t, "api key list", page, "Expire", "Sil", "Oluşturma bilinçli olarak yok")
	// No creating form: every form of the page acts on an existing key.
	for _, m := range regexpForms(page) {
		if !strings.Contains(m, "/expire") {
			t.Errorf("the API key page has a form that is not an expire form: %s", m)
		}
	}

	// A create attempt over HTTP reaches no handler: the route does not exist.
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/headscale/keys/api"},
		{http.MethodPost, "/headscale/keys/api/create"},
		{http.MethodPost, "/headscale/keys/api/new"},
		{http.MethodGet, "/headscale/keys/api/new"},
	} {
		code, _ := s.ui.do(c.method, c.path, url.Values{"expires_in": {"24h"}})
		if code < 400 {
			t.Errorf("%s %s: status %d, want an error (there is no create route)", c.method, c.path, code)
		}
	}
	if got := s.apiKeyIDs(); len(got) != 2 {
		t.Fatalf("api keys after the create attempts = %v, want still 2", got)
	}

	// Expire the first, delete the second through the confirm page.
	first := ids[0]
	version := versionOfForm(page, "/headscale/keys/api/"+strconv.FormatUint(first, 10)+"/expire")
	if code, body := s.ui.post("/headscale/keys/api/"+strconv.FormatUint(first, 10)+"/expire", url.Values{"version": {version}}); code != http.StatusSeeOther {
		t.Fatalf("expire: status %d: %s", code, excerpt(body))
	}
	keys, err := s.adm.ListApiKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.ID == first && (k.Expiration == nil || k.Expiration.After(time.Now())) {
			t.Fatalf("key %d expiry = %v, want a past instant", first, k.Expiration)
		}
	}

	second := ids[1]
	if code, _ := s.ui.post("/headscale/keys/api/"+strconv.FormatUint(second, 10)+"/delete", url.Values{"version": {"x"}}); code != http.StatusBadRequest {
		t.Fatalf("delete without the confirmation: status %d, want 400", code)
	}
	confirm := s.ui.getOK("/headscale/keys/api/" + strconv.FormatUint(second, 10) + "/delete")
	mustContain(t, "delete confirmation", confirm, "geri alınamaz")
	code, body := s.ui.post("/headscale/keys/api/"+strconv.FormatUint(second, 10)+"/delete",
		url.Values{"version": {formOf{confirm}.value("version")}, "confirm": {"1"}})
	if code != http.StatusSeeOther {
		t.Fatalf("delete: status %d: %s", code, excerpt(body))
	}
	if got := s.apiKeyIDs(); slices.Contains(got, second) {
		t.Fatalf("api key %d is still in Headscale after the delete: %v", second, got)
	}
}

var formRE = regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`)

// regexpForms lists the actions of every form on a page.
func regexpForms(page string) []string {
	var out []string
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// versionOfForm is the version stamp of the page's form with that action.
func versionOfForm(page, action string) string {
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		if html.UnescapeString(m[1]) == action {
			return inputValue(m[2], "version")
		}
	}
	return ""
}

// postRoutes posts the route form with the page's current version stamp and the checked routes.
func (s *f3Stack) postRoutes(id uint64, routes ...string) (int, string) {
	s.t.Helper()
	page := formOf{s.ui.getOK(devicePath(id, "/routes"))}
	return s.ui.post(devicePath(id, "/routes"), url.Values{"version": {page.value("version")}, "route": routes})
}

// AC2: route approval and revocation match Headscale's approved set; a stale form gets 409; the
// personal → tagged conversion needs two steps and the warning, refuses a protected tag, and the
// converted device is not expired when its owner loses the role (Y-04 bypass), while another
// personal device of the same owner is.
func TestE2E_F3_RoutesAndTagConversion(t *testing.T) {
	var bob f3User
	var edge, phone uint64
	const routeA, routeB = "10.77.0.0/24", "10.78.0.0/24"
	s := newF3Stack(t, f3Options{prepare: func(s *f3Stack) {
		bob = s.user("bob", "standart")
		s.padHolders("standart", 3)
		edge = s.hs.NewNode(s.t, bob.hsName, "bob-edge", "")
		phone = s.hs.NewNode(s.t, bob.hsName, "bob-phone", "")
		s.hs.SetNodeRoutableIPs(s.t, "bob-edge", []string{routeA, routeB})
	}})

	s.section(t, "routes", func(t *testing.T) {
		mustContain(t, "route page", s.ui.getOK(devicePath(edge, "/routes")), routeA, routeB)
		if code, body := s.postRoutes(edge, routeA, routeB); code != http.StatusSeeOther {
			t.Fatalf("approve both: status %d: %s", code, excerpt(body))
		}
		if got := s.mustNode(edge).ApprovedRoutes; !slices.Equal(got, []string{routeA, routeB}) {
			t.Fatalf("approved in Headscale = %v, want both", got)
		}
		if code, body := s.postRoutes(edge, routeA); code != http.StatusSeeOther {
			t.Fatalf("revoke one: status %d: %s", code, excerpt(body))
		}
		if got := s.mustNode(edge).ApprovedRoutes; !slices.Equal(got, []string{routeA}) {
			t.Fatalf("approved after revoking %s = %v, want [%s]", routeB, got, routeA)
		}
		if code, body := s.postRoutes(edge); code != http.StatusSeeOther {
			t.Fatalf("revoke all: status %d: %s", code, excerpt(body))
		}
		if got := s.mustNode(edge).ApprovedRoutes; len(got) != 0 {
			t.Fatalf("approved after revoking all = %v, want none", got)
		}

		// A stale form: the node changes after the page was shown.
		stale := formOf{s.ui.getOK(devicePath(edge, "/routes"))}.value("version")
		if _, err := s.adm.SetApprovedRoutes(context.Background(), edge, []string{routeB}); err != nil {
			t.Fatalf("approve out of band: %v", err)
		}
		code, body := s.ui.post(devicePath(edge, "/routes"), url.Values{"version": {stale}, "route": {routeA}})
		if code != http.StatusConflict {
			t.Fatalf("stale route form: status %d, want 409: %s", code, excerpt(body))
		}
		if got := s.mustNode(edge).ApprovedRoutes; !slices.Equal(got, []string{routeB}) {
			t.Fatalf("a stale form changed the approved routes to %v", got)
		}
	})

	s.section(t, "conversion", func(t *testing.T) {
		warn := s.ui.getOK(devicePath(edge, "/tags"))
		mustContain(t, "conversion page", warn, "geri alınamaz", "rol kaybında expire edilmez", "Devam: onay adımı")
		convert := func(tag string, extra url.Values) (int, string) {
			page := formOf{s.ui.getOK(devicePath(edge, "/tags"))}
			form := url.Values{"version": {page.value("version")}, "tag": {tag}}
			for k, v := range extra {
				form[k] = v
			}
			return s.ui.post(devicePath(edge, "/tags"), form)
		}
		untagged := func(what string) {
			t.Helper()
			if n := s.mustNode(edge); len(n.Tags) != 0 || n.UserID != bob.hsID {
				t.Fatalf("%s: the device is no longer personal: tags %v, owner %d", what, n.Tags, n.UserID)
			}
		}
		name := s.mustNode(edge).GivenName

		// Step one only shows the confirmation.
		code, body := convert(f3SharedTag, nil)
		if code != http.StatusOK {
			t.Fatalf("step 1: status %d: %s", code, excerpt(body))
		}
		mustContain(t, "step 1", body, "Son adım")
		untagged("after step 1")
		// Wrong name, then no checkbox.
		if code, body := convert(f3SharedTag, url.Values{"step": {"convert"}, "confirm_name": {"nope"}, "confirm": {"on"}}); code != http.StatusBadRequest {
			t.Fatalf("wrong device name: status %d, want 400: %s", code, excerpt(body))
		}
		if code, body := convert(f3SharedTag, url.Values{"step": {"convert"}, "confirm_name": {name}}); code != http.StatusBadRequest {
			t.Fatalf("missing checkbox: status %d, want 400: %s", code, excerpt(body))
		}
		untagged("after the refused confirmations")
		// A protected tag is refused even with every confirmation.
		if code, body := convert(f3ServerTag, url.Values{"step": {"convert"}, "confirm_name": {name}, "confirm": {"on"}}); code != http.StatusForbidden {
			t.Fatalf("protected tag: status %d, want 403: %s", code, excerpt(body))
		}
		untagged("after the protected tag")
		// The proper two-step conversion.
		code, body = convert(f3SharedTag, url.Values{"step": {"convert"}, "confirm_name": {name}, "confirm": {"on"}})
		if code != http.StatusOK || !strings.Contains(body, "apply edildi") {
			t.Fatalf("conversion: status %d: %s", code, excerpt(body))
		}
		if n := s.mustNode(edge); !slices.Equal(n.Tags, []string{f3SharedTag}) {
			t.Fatalf("tags in Headscale = %v, want [%s]", n.Tags, f3SharedTag)
		}
	})

	s.section(t, "role loss", func(t *testing.T) {
		s.waitMember("standart", bob.zitadelID, true)
		s.l.removeGrant(t, bob.zitadelID)
		if err := poll(t, 45*time.Second, func() (bool, error) {
			s.triggerSyncQuiet()
			return expired(s.mustNode(phone)), nil
		}); err != nil {
			t.Fatalf("the personal device of the user who lost the role was not expired: %v", err)
		}
		// The control above proves the reconcile ran; the converted device must have been left alone.
		if n := s.mustNode(edge); expired(n) {
			t.Errorf("the converted (tagged) device was expired at %v", n.Expiry)
		}
	})
}

// AC3: the secret of a pre-auth key is shown once, in the response that created it. It is in no
// later page, the audit log, the application log, the SQLite file or the artifact history; the
// list never carries an unmasked value; expire and delete work.
func TestE2E_F3_PreAuthSecretNeverLeaks(t *testing.T) {
	var alice f3User
	s := newF3Stack(t, f3Options{prepare: func(s *f3Stack) {
		alice = s.user("alice", "standart")
	}})

	code, body := s.ui.post("/headscale/keys/preauth/create", url.Values{"tags": {f3SharedTag}, "expires_in": {"2h"}})
	if code != http.StatusOK {
		t.Fatalf("create the tagged key: status %d: %s", code, excerpt(body))
	}
	mustContain(t, "key result", body, "bir daha gösterilmeyecek")
	tagSecret := secretOf(t, body)
	var tagKey uint64
	for _, k := range s.preAuthKeys() {
		if slices.Equal(k.Tags, []string{f3SharedTag}) {
			tagKey = k.ID
		}
	}
	if tagKey == 0 {
		t.Fatal("the tagged key is not in Headscale")
	}

	code, body = s.ui.post("/headscale/keys/personal", url.Values{"user": {strconv.FormatUint(alice.hsID, 10)}, "expires_in": {"2h"}})
	if code != http.StatusOK {
		t.Fatalf("create the personal key: status %d: %s", code, excerpt(body))
	}
	personalSecret := secretOf(t, body)

	// Every page that could list a key, a device or an operator action shows no secret.
	for _, path := range []string{"/headscale/keys", "/headscale/keys/preauth", "/headscale/keys/personal", "/headscale/keys/api", "/headscale/devices", "/headscale/users", "/audit", "/sync"} {
		code, page := s.ui.get(path)
		if code != http.StatusOK {
			t.Errorf("GET %s: status %d", path, code)
			continue
		}
		mustNotContain(t, path, page, tagSecret, personalSecret)
		if preAuthSecretRE.MatchString(page) {
			t.Errorf("GET %s shows a full pre-auth key value", path)
		}
	}
	list := s.ui.getOK("/headscale/keys")
	mustContain(t, "key list", list, f3SharedTag, alice.hsName)

	// Expire the tagged key, then delete it, both through the confirm pages.
	id := strconv.FormatUint(tagKey, 10)
	confirm := s.ui.getOK("/headscale/keys/preauth/" + id + "/expire")
	code, body = s.ui.post("/headscale/keys/preauth/"+id+"/expire", url.Values{"version": {formOf{confirm}.value("version")}})
	if code != http.StatusOK || !strings.Contains(body, "callout-ok") {
		t.Fatalf("expire the key: status %d: %s", code, excerpt(body))
	}
	if !s.keyExpired(tagKey) {
		t.Fatal("the key is still valid in Headscale after the expire")
	}
	confirm = s.ui.getOK("/headscale/keys/preauth/" + id + "/delete")
	code, body = s.ui.post("/headscale/keys/preauth/"+id+"/delete", url.Values{"version": {formOf{confirm}.value("version")}})
	if code != http.StatusOK || !strings.Contains(body, "callout-ok") {
		t.Fatalf("delete the key: status %d: %s", code, excerpt(body))
	}
	for _, k := range s.preAuthKeys() {
		if k.ID == tagKey {
			t.Fatal("the key is still listed in Headscale after the delete")
		}
	}

	s.assertNoSecrets(tagSecret, personalSecret, s.l.pat, s.l.readSecret(t, seed.WebhookSigningKeyFile))
}

// personalKey asks for a personal key through the form; it returns the status, the page and the
// listed Headscale key it made (nil when none was made).
func (s *f3Stack) personalKey(u f3User, extra url.Values) (int, string) {
	s.t.Helper()
	form := url.Values{"user": {strconv.FormatUint(u.hsID, 10)}, "expires_in": {"2h"}}
	for k, v := range extra {
		form[k] = v
	}
	return s.ui.post("/headscale/keys/personal", form)
}

// keyOf is the pre-auth key bound to the Headscale user, untagged.
func (s *f3Stack) keyOf(u f3User) (id uint64, ok bool) {
	for _, k := range s.preAuthKeys() {
		if k.UserID == u.hsID && len(k.Tags) == 0 {
			return k.ID, true
		}
	}
	return 0, false
}

// AC5: a personal key is made one-time for an eligible user and refused for a user without a role
// or a passive account; when its owner loses the role, one reconcile revokes the unused key while
// the tagged key and another user's key stay valid.
func TestE2E_F3_PersonalKeyEligibilityAndRevocation(t *testing.T) {
	var elig, other, norole, passive f3User
	s := newF3Stack(t, f3Options{prepare: func(s *f3Stack) {
		elig = s.user("elig", "standart")
		other = s.user("other", "standart")
		norole = s.user("norole", "")
		passive = s.user("passive", "standart")
		s.l.deactivate(s.t, passive.zitadelID)
	}})

	offer := s.ui.getOK("/headscale/keys/personal")
	mustContain(t, "personal key form", offer, elig.hsName, other.hsName, "OIDC giriş şartlarını baypas")
	mustNotContain(t, "personal key form", offer, norole.hsName, passive.hsName)

	// Eligible users get a one-time, untagged, bounded key.
	var eligKey, otherKey uint64
	for _, c := range []struct {
		u  f3User
		to *uint64
	}{{elig, &eligKey}, {other, &otherKey}} {
		code, body := s.personalKey(c.u, nil)
		if code != http.StatusOK || !strings.HasPrefix(secretOf(t, body), "hskey-auth-") {
			t.Fatalf("personal key for %s: status %d: %s", c.u.hsName, code, excerpt(body))
		}
		id, ok := s.keyOf(c.u)
		if !ok {
			t.Fatalf("no key bound to %s in Headscale", c.u.hsName)
		}
		*c.to = id
	}
	for _, k := range s.preAuthKeys() {
		if k.ID != eligKey {
			continue
		}
		if k.Reusable || k.Ephemeral || k.Used || len(k.Tags) != 0 {
			t.Errorf("the personal key is not one-time and untagged: %+v", k)
		}
		if k.Expiration == nil || time.Until(*k.Expiration) > 3*time.Hour || time.Until(*k.Expiration) < time.Hour {
			t.Errorf("the personal key expires at %v, want about 2h from now", k.Expiration)
		}
	}
	// A reusable personal key is not offered either.
	if code, body := s.personalKey(elig, url.Values{"reusable": {"1"}}); code != http.StatusBadRequest {
		t.Errorf("a reusable personal key: status %d, want 400: %s", code, excerpt(body))
	}

	// No role, no key; a passive account, no key.
	before := len(s.preAuthKeys())
	for _, u := range []f3User{norole, passive} {
		if code, body := s.personalKey(u, nil); code != http.StatusBadRequest {
			t.Errorf("personal key for %s: status %d, want 400: %s", u.hsName, code, excerpt(body))
		}
	}
	if after := len(s.preAuthKeys()); after != before {
		t.Fatalf("keys in Headscale %d → %d: a refused request made a key", before, after)
	}

	// A tagged key that must survive the role loss.
	if code, body := s.ui.post("/headscale/keys/preauth/create", url.Values{"tags": {f3SharedTag}, "expires_in": {"2h"}}); code != http.StatusOK {
		t.Fatalf("tagged key: status %d: %s", code, excerpt(body))
	}
	var tagKey uint64
	for _, k := range s.preAuthKeys() {
		if len(k.Tags) > 0 {
			tagKey = k.ID
		}
	}
	if tagKey == 0 {
		t.Fatal("the tagged key is not in Headscale")
	}

	// The owner loses the role: the next reconcile revokes the unused key and nothing else.
	s.waitMember("standart", elig.zitadelID, true)
	s.l.removeGrant(t, elig.zitadelID)
	if err := poll(t, 45*time.Second, func() (bool, error) {
		s.triggerSyncQuiet()
		return s.keyExpired(eligKey), nil
	}); err != nil {
		t.Fatalf("the unused personal key of the user who lost the role was not revoked: %v", err)
	}
	for name, id := range map[string]uint64{"the other user's personal key": otherKey, "the tagged key": tagKey} {
		if s.keyExpired(id) {
			t.Errorf("%s was revoked with the role loss of another user", name)
		}
	}
}

// rowOf is the table row of a page that holds needle.
func rowOf(body, needle string) string {
	for _, row := range strings.Split(body, "<tr>") {
		if strings.Contains(row, needle) {
			return row
		}
	}
	return ""
}

// AC7: the users screen matches Headscale users with the lab Zitadel users, marks the ones that do
// not match, and has no write action.
func TestE2E_F3_UsersMatchLabZitadel(t *testing.T) {
	var matched f3User
	s := newF3Stack(t, f3Options{prepare: func(s *f3Stack) {
		matched = s.user("matched", "standart")
		s.hs.CreateUser(s.t, "f3026-stranger") // never signed in through OIDC
		s.hs.CreateUser(s.t, "f3026-ghost")
		s.hs.SetProviderID(s.t, "f3026-ghost", s.l.zitadelProviderID("000000000000000001")) // no such lab user
	}})

	// The lab network is intermittently slow: until tagcess has read Zitadel the page says "could
	// not verify" for every row, so the page is read until the match shows.
	var page string
	if err := poll(t, 90*time.Second, func() (bool, error) {
		page = s.ui.getOK("/headscale/users")
		return strings.Contains(rowOf(page, matched.hsName), "eşleşti"), nil
	}); err != nil {
		t.Fatalf("the matched user never showed as matched: %v: %s", err, excerpt(page))
	}
	row := rowOf(page, matched.hsName)
	mustContain(t, "the matched row", row, "eşleşti", matched.zitadelID, "standart")
	for _, name := range []string{"f3026-stranger", "f3026-ghost"} {
		row := rowOf(page, name)
		if row == "" {
			t.Errorf("%s is not listed", name)
			continue
		}
		mustContain(t, name+" row", row, "eşleşmedi")
		mustNotContain(t, name+" row", row, "eşleşti<")
	}

	// There is no write action: no form on the page, and every write verb is refused.
	for _, action := range regexpForms(page) {
		if strings.Contains(action, "/headscale/users") {
			t.Errorf("the users page has a form posting to %s", action)
		}
	}
	users, err := s.hs.Client().ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/headscale/users"},
		{http.MethodPut, "/headscale/users"},
		{http.MethodDelete, "/headscale/users"},
		{http.MethodPost, "/headscale/users/1/delete"},
		{http.MethodPost, "/headscale/users/1/rename"},
	} {
		if code, _ := s.ui.do(c.method, c.path, url.Values{"name": {"x"}}); code < 400 {
			t.Errorf("%s %s: status %d, want an error", c.method, c.path, code)
		}
	}
	if after, err := s.hs.Client().ListUsers(context.Background()); err != nil || len(after) != len(users) {
		t.Errorf("the Headscale user list changed: %d → %d (%v)", len(users), len(after), err)
	}
}
