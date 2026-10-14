package render

import (
	"net/url"
	"strings"
	"testing"
)

func TestSignOutPath(t *testing.T) {
	t.Run("fallback without client id", func(t *testing.T) {
		got, err := SignOutPath("https://auth.example.com", "", "https://t.example.com/")
		if err != nil || got != "/oauth2/sign_out?rd=%2F" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("end_session in rd", func(t *testing.T) {
		got, err := SignOutPath("https://auth.example.com", "123@vpn", "https://t.example.com/")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(got)
		if err != nil || u.Path != "/oauth2/sign_out" {
			t.Fatalf("got %q, %v", got, err)
		}
		rd := u.Query().Get("rd")
		want := "https://auth.example.com/oidc/v1/end_session?client_id=123%40vpn&post_logout_redirect_uri=https%3A%2F%2Ft.example.com%2F"
		if rd != want {
			t.Errorf("rd = %q, want %q", rd, want)
		}
		if strings.ContainsAny(got, "&{}`<>\"' ") {
			t.Errorf("unsafe character in %q", got)
		}
	})
	for _, c := range []struct{ name, issuer, id, ret string }{
		{"http issuer", "http://auth.example.com", "x", "https://t.example.com/"},
		{"issuer with query", "https://auth.example.com?a=b", "x", "https://t.example.com/"},
		{"bad client id", "https://auth.example.com", "x&y", "https://t.example.com/"},
		{"http return", "https://auth.example.com", "x", "http://t.example.com/"},
		{"empty return", "https://auth.example.com", "x", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, err := SignOutPath(c.issuer, c.id, c.ret); err == nil {
				t.Errorf("accepted: %q", got)
			}
		})
	}
}

func TestCaddyRender_ForbiddenPageSignOut(t *testing.T) {
	cfg := caddyCfg(true)
	cfg.ZitadelIssuer = "https://auth.example.com"
	cfg.GateClientID = "123@vpn"
	cfg.LogoutReturnURL = "https://t.example.com/"
	out, err := RenderCaddyfile(nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := SignOutPath(cfg.ZitadelIssuer, cfg.GateClientID, cfg.LogoutReturnURL)
	if !strings.Contains(out, `href="`+want+`">Başka hesapla giriş yap</a>`) || !strings.Contains(want, "end_session") {
		t.Errorf("403 page lacks the end_session sign-out link:\n%s", out)
	}
	cfg.GateClientID = "x&y"
	if _, err := RenderCaddyfile(nil, cfg); err == nil {
		t.Error("an unsafe client id rendered")
	}
	// Empty client id keeps today's golden-covered link.
	plain, _ := RenderCaddyfile(nil, caddyCfg(true))
	if !strings.Contains(plain, `href="/oauth2/sign_out?rd=%2F">`) {
		t.Error("fallback link missing")
	}
}
