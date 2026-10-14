//go:build integration

// End-to-end scenarios for F3-030: the policy writer's refusals while Zitadel is unreadable, and
// the recovery of a policy write that ended uncertain because Headscale went down during the
// apply (R2 karar 21: the unit tests inject the errors, this one stops the real Headscale).
package e2e_test

import (
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/policyrev"
)

// cutApplyShort edits the live policy through the editor and saves it while the proxy is armed:
// Headscale commits the new policy and goes down before tagcess hears about it. It returns once
// the interface has answered (Headscale is still down then), with the status and body of that answer.
func (s *policyStack) cutApplyShort(edit func(string) string) (code int, body string) {
	s.t.Helper()
	text, base := s.editorState()
	_, preview := s.previewPolicy(edit(text), base)
	if inputValue(preview, "report_hash") == "" {
		s.t.Fatalf("the edited text does not pass the preview: %s", excerpt(preview))
	}
	s.proxy.dieAfterNextSetPolicy(func() { s.hs.Stop(s.t) })
	return s.ui.post("/headscale/policy/save", url.Values{
		"text": {inputValue(preview, "text")}, "base_hash": {inputValue(preview, "base_hash")}, "report_hash": {inputValue(preview, "report_hash")},
	})
}

var recoveryTextRE = regexp.MustCompile(`(?s)<textarea[^>]*\bid="recovery-text"[^>]*>(.*?)</textarea>`)

func recoveryCandidate(t *testing.T, body string) string {
	t.Helper()
	m := recoveryTextRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the recovery page shows no candidate: %s", excerpt(body))
	}
	return strings.TrimPrefix(html.UnescapeString(m[1]), "\n")
}

// gateEditor is the edit the recovery scenarios make.
func gateEditor(text string) string { return strings.Replace(text, gateRule, gateEdited, 1) }

// AC5: Headscale is stopped during a policy apply. The write is recorded as unknown, no other
// save is accepted, and once Headscale is back the recovery page offers the last applied revision
// as the candidate; an explicit approval applies it, reads it back and clears the unresolved
// state. Nothing restores anything by itself.
func TestE2E_F3_PolicyRecoveryAfterHeadscaleStop(t *testing.T) {
	s := newPolicyStack(t, f3Options{proxy: true})
	l0 := s.livePolicy()
	var written string
	var revs, target int

	s.section(t, "Headscale stops during the apply", func(t *testing.T) {
		code, body := s.cutApplyShort(gateEditor)
		if code != http.StatusBadGateway {
			t.Fatalf("the cut-short save: status %d, want 502: %s", code, excerpt(body))
		}
		mustContain(t, "result", body, "Apply belirsiz", "Kontrollü recovery")
		mustNotContain(t, "result", body, "Policy apply edildi")
		if rev := s.lastRevision(); rev.status != "unknown" || rev.source != "ui" {
			t.Fatalf("newest revision = %+v, want an unknown ui revision", revisionBrief(rev))
		}
		revs = s.revisionCount()

		// While it is down nothing can be saved or read.
		code, body = s.saveRaw(l0, policyrev.HashRaw(l0))
		if code != http.StatusBadGateway {
			t.Errorf("save while Headscale is down: status %d, want 502: %s", code, excerpt(body))
		}
		mustContain(t, "refusal", body, "Headscale okunamıyor")
		if code, body = s.ui.get("/headscale/policy"); code != http.StatusBadGateway {
			t.Errorf("editor while Headscale is down: status %d, want 502: %s", code, excerpt(body))
		}
		if n := s.revisionCount(); n != revs {
			t.Errorf("a refused save added %d revision(s)", n-revs)
		}
	})

	s.hs.Restart(t)
	written = s.livePolicy()
	if !strings.Contains(written, gateEdited) || written == l0 {
		t.Fatalf("the cut-short write never reached Headscale (this is the partial write the scenario needs):\n%s", written)
	}
	target = s.newestApplied()

	s.section(t, "the unresolved state blocks every save", func(t *testing.T) {
		page := s.ui.getOK("/headscale/policy")
		mustContain(t, "editor", page, "Önceki apply belirsiz", "Kontrollü recovery", "read-only")
		mustNotContain(t, "editor", page, `id="policy-editor"`)
		if got := policyText(t, page); got != written {
			t.Errorf("the read-only editor does not show the live policy")
		}
		code, body := s.previewPolicy(written, policyrev.HashRaw(written))
		if code != http.StatusConflict {
			t.Errorf("preview in the unresolved state: status %d, want 409: %s", code, excerpt(body))
		}
		code, body = s.saveRaw(written, policyrev.HashRaw(written))
		if code != http.StatusConflict {
			t.Errorf("save in the unresolved state: status %d, want 409: %s", code, excerpt(body))
		}
		mustContain(t, "refusal", body, "Önceki apply belirsiz")
		if n := s.revisionCount(); n != revs {
			t.Errorf("a refused save added %d revision(s)", n-revs)
		}
		if got := s.livePolicy(); got != written {
			t.Errorf("a refused save changed the live policy")
		}
	})

	var candidatePage string
	s.section(t, "the recovery page shows the candidate and writes nothing", func(t *testing.T) {
		candidatePage = s.ui.getOK("/headscale/policy/recovery")
		mustContain(t, "recovery page", candidatePage, "Önceki apply belirsiz", "Otomatik geri yükleme yoktur",
			"revision #"+revID(target), "Onayla ve apply et", "8080")
		wantSameOutsideOwned(t, "the candidate", recoveryCandidate(t, candidatePage), l0)
		// No automatic restore: the policy stays what the cut-short write left, however long we look.
		time.Sleep(3 * time.Second)
		if got := s.livePolicy(); got != written {
			t.Errorf("the live policy changed without an approval")
		}
		if n := s.revisionCount(); n != revs {
			t.Errorf("looking at the recovery page added %d revision(s)", n-revs)
		}
	})

	s.section(t, "explicit approval applies it and clears the state", func(t *testing.T) {
		code, body := s.ui.post("/headscale/policy/recovery", url.Values{"base_hash": {inputValue(candidatePage, "base_hash")}})
		wantPolicyApplied(t, "recovery", code, body)
		after := s.livePolicy()
		wantSameOutsideOwned(t, "the recovered policy", after, l0)
		if n := strings.Count(after, lockedMarker); n != 3 {
			t.Errorf("the recovered policy carries %d locked tests, want 3", n)
		}
		if strings.Contains(after, "8080") {
			t.Errorf("the cut-short write is still live")
		}
		rev := s.lastRevision()
		if rev.source != "recovery" || rev.status != "applied" || rev.rollbackOf != target || rev.raw != after {
			t.Errorf("newest revision = %+v, want an applied recovery of #%d holding the read-back text", revisionBrief(rev), target)
		}
		page := s.ui.getOK("/headscale/policy")
		mustContain(t, "editor", page, `id="policy-editor"`)
		mustNotContain(t, "editor", page, "Önceki apply belirsiz")
		mustContain(t, "recovery page", s.ui.getOK("/headscale/policy/recovery"), "belirsiz durum yok")
		// The editor works again.
		text, base := s.editorState()
		code, body = s.saveEditor(strings.Replace(text, gateRule, `"dst": ["tag:vpn-server:80,8083"] }, // gate`, 1), base)
		wantPolicyApplied(t, "save after the recovery", code, body)
	})
}

// AC3: while Zitadel cannot be read, a save, a rollback and a recovery are refused and the editor
// is read-only; nothing is written. Zitadel is taken away by the broken service key (F1-021's
// method) and brought back by restarting the binary with the real one, on the same store.
func TestE2E_F3_PolicyBlockedWhileZitadelDown(t *testing.T) {
	s := newPolicyStack(t, f3Options{proxy: true})
	rollbackTarget := s.newestApplied()
	if rollbackTarget == 0 {
		t.Fatal("no applied revision to roll back to")
	}
	text, base := s.editorState()
	code, body := s.saveEditor(gateEditor(text), base)
	wantPolicyApplied(t, "first save", code, body)
	live, revs := s.livePolicy(), s.revisionCount()
	goodKey := s.cfg.keyFile

	unchanged := func(what string) {
		t.Helper()
		if got := s.livePolicy(); got != live {
			t.Errorf("%s changed the live policy", what)
		}
		if n := s.revisionCount(); n != revs {
			t.Errorf("%s added %d revision(s)", what, n-revs)
		}
	}
	wantZitadelRefusal := func(what string, code int, body string) {
		t.Helper()
		if code != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d, want 503: %s", what, code, excerpt(body))
		}
		mustContain(t, what, body, "Zitadel okunamıyor")
		mustNotContain(t, what, body, "Policy apply edildi")
	}

	s.section(t, "Zitadel unreadable", func(t *testing.T) {
		s.restart(s.l.tamperedKeyFile(t))
		page := s.ui.getOK("/headscale/policy")
		mustContain(t, "editor", page, "Zitadel okunamıyor: düzenleme kapalı", "read-only")
		mustNotContain(t, "editor", page, `id="policy-editor"`, `action="/headscale/policy/preview"`)
		if got := policyText(t, page); got != live {
			t.Errorf("the read-only editor does not show the live policy")
		}
		hash := policyrev.HashRaw(live)
		edit := strings.Replace(live, gateEdited, `"dst": ["tag:vpn-server:80,8084"] }, // gate`, 1)

		code, body := s.previewPolicy(edit, hash)
		wantZitadelRefusal("preview", code, body)
		code, body = s.saveRaw(edit, hash)
		wantZitadelRefusal("save", code, body)

		rb := "/headscale/policy/history/" + revID(rollbackTarget) + "/rollback"
		code, body = s.ui.get(rb)
		wantZitadelRefusal("rollback page", code, body)
		code, body = s.ui.post(rb, url.Values{"base_hash": {hash}})
		wantZitadelRefusal("rollback", code, body)
		unchanged("the refused writes")
	})

	s.section(t, "Zitadel back", func(t *testing.T) {
		s.restart(goodKey)
		text, base := s.editorState()
		code, body := s.saveEditor(strings.Replace(text, gateEdited, `"dst": ["tag:vpn-server:80,8085"] }, // gate`, 1), base)
		wantPolicyApplied(t, "save after Zitadel is back", code, body)
		live, revs = s.livePolicy(), s.revisionCount()
	})

	s.section(t, "recovery while Zitadel is unreadable", func(t *testing.T) {
		// An unresolved state first (the cut-short apply), then Zitadel goes away.
		if code, body := s.cutApplyShort(func(text string) string {
			return strings.Replace(text, `"dst": ["tag:vpn-server:80,8085"] }, // gate`, `"dst": ["tag:vpn-server:80,8086"] }, // gate`, 1)
		}); code != http.StatusBadGateway {
			t.Fatalf("the cut-short save: status %d: %s", code, excerpt(body))
		}
		s.hs.Restart(t)
		live, revs = s.livePolicy(), s.revisionCount()
		if !strings.Contains(live, "8086") {
			t.Fatalf("the cut-short write never reached Headscale")
		}

		s.restart(s.l.tamperedKeyFile(t))
		code, body := s.ui.get("/headscale/policy/recovery")
		wantZitadelRefusal("recovery page", code, body)
		mustNotContain(t, "recovery page", body, "Onayla ve apply et")
		code, body = s.ui.post("/headscale/policy/recovery", url.Values{"base_hash": {policyrev.HashRaw(live)}})
		wantZitadelRefusal("recovery", code, body)
		unchanged("the refused recovery")

		// Zitadel back: the recovery works.
		s.restart(goodKey)
		page := s.ui.getOK("/headscale/policy/recovery")
		code, body = s.ui.post("/headscale/policy/recovery", url.Values{"base_hash": {inputValue(page, "base_hash")}})
		wantPolicyApplied(t, "recovery after Zitadel is back", code, body)
	})
}

// AC8: after a run (two of them, to prove it is repeatable) the lab user and its grant, the
// throwaway Headscale, the proxy in front of it and the binary's data directory are gone. The
// subtest never cleans up itself; what t.Run's return leaves behind is what the fixtures'
// own t.Cleanup did not remove.
func TestF3PolicyE2E_Cleanup(t *testing.T) {
	l := setupLab(t)
	for run := 1; run <= 2; run++ {
		var userID, dataDir, grpcAddr, proxyAddr string
		t.Run("run"+string(rune('0'+run)), func(t *testing.T) {
			s := newPolicyStack(t, f3Options{proxy: true})
			userID, dataDir, grpcAddr, proxyAddr = s.ops.zitadelID, s.proc.dataDir, s.hs.GRPCAddr(), s.proxy.addr
			// Touch the state the clean-up must remove: a policy revision, a settings row, and a
			// restart of the binary on the same data directory.
			text, base := s.editorState()
			code, body := s.saveEditor(gateEditor(text), base)
			wantPolicyApplied(t, "save", code, body)
			if code, body := s.ui.post("/headscale/settings/tags", url.Values{"action": {"add"}, "tag": {f3SharedTag}}); code != http.StatusOK {
				t.Fatalf("settings: status %d: %s", code, excerpt(body))
			}
			s.restart(s.cfg.keyFile)
		})

		if userID == "" || dataDir == "" {
			t.Fatalf("run%d: the subtest failed before it created its state", run)
		}
		if _, err := os.Stat(dataDir); err == nil {
			t.Errorf("run%d: the binary's data directory %s is still there", run, dataDir)
		}
		for what, addr := range map[string]string{"throwaway Headscale": grpcAddr, "Headscale proxy": proxyAddr} {
			if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				_ = conn.Close()
				t.Errorf("run%d: the %s at %s still answers", run, what, addr)
			}
		}
		if err := poll(t, 30*time.Second, func() (bool, error) {
			_, err := userv2.NewUserServiceClient(l.conn).GetUserByID(l.adminCtx, &userv2.GetUserByIDRequest{UserId: userID})
			return status.Code(err) == codes.NotFound, err
		}); err != nil {
			t.Errorf("run%d: the lab user %s is still in Zitadel: %v", run, userID, err)
		}
		if l.hasGrant(t, userID, "devops") {
			t.Errorf("run%d: the lab user's grant is still in Zitadel", run)
		}
	}
}
