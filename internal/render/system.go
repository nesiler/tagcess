package render

import (
	"fmt"
	"strings"

	"github.com/nesiler/tagcess/internal/site"
)

// System site templates (ADR 0010, S-05): the four special blocks are fixed text in code. A record
// only picks the host (and, for zitadel, the certificate) and flips the switches its template
// opens; everything else is a constant here. The renderer re-checks the canonical record shape
// the store enforces (site.checkSystemShape) and refuses a record that does not fit: fail
// closed, never repaired. System templates keep their own source rules; the S-06 key does not
// change them (ADR 0010 m.5).

// caddySystemOrder is the fixed block order of the system section, after the sorted user
// sites (ADR 0010 m.4).
var caddySystemOrder = []string{
	site.TemplateZitadel,
	site.TemplateHeadscale,
	site.TemplateWireGuardUI,
	site.TemplateTagcess,
}

// caddyTagcessBody is the body of the tagcess block, between the host line and the closing
// brace. With them it is byte-identical to deploy/caddy/tagcess.caddy (the F1 reference snippet); TestSystemSite_TagcessGolden
// compares the two. Only devops reaches the UI, only from the tailnet, and the client's own
// identity headers are stripped before forward_auth (security.md §3.1, S-05.2).
const caddyTagcessBody = "\t@tailnet remote_ip 100.64.0.0/10\n" +
	"\thandle @tailnet {\n" +
	"\t\t# oauth2-proxy's login endpoints (start/callback) must reach oauth2-proxy itself.\n" +
	"\t\thandle /oauth2/* {\n" +
	"\t\t\treverse_proxy 127.0.0.1:4180\n" +
	"\t\t}\n" +
	"\n" +
	"\t\t# Strip the client's own X-Auth-Request-* headers before forward_auth, so the only source of\n" +
	"\t\t# the identity headers is oauth2-proxy (security.md §3.1). `route` keeps this literal order.\n" +
	"\t\troute {\n" +
	"\t\t\trequest_header -X-Auth-Request-User\n" +
	"\t\t\trequest_header -X-Auth-Request-Email\n" +
	"\t\t\trequest_header -X-Auth-Request-Groups\n" +
	"\t\t\tforward_auth 127.0.0.1:4180 {\n" +
	"\t\t\t\turi /oauth2/auth?allowed_groups=devops\n" +
	"\t\t\t\tcopy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups\n" +
	"\t\t\t\t# oauth2-proxy returns 401 when there is no session; send the browser to sign in.\n" +
	"\t\t\t\t@unauthenticated status 401\n" +
	"\t\t\t\thandle_response @unauthenticated {\n" +
	"\t\t\t\t\tredir * /oauth2/start?rd={http.request.uri}\n" +
	"\t\t\t\t}\n" +
	"\t\t\t}\n" +
	"\t\t\treverse_proxy unix//run/tagcess/ui.sock\n" +
	"\t\t}\n" +
	"\t}\n" +
	"\thandle {\n" +
	"\t\trespond 403\n" +
	"\t}\n"

// renderCaddySystemSite renders one system block. It returns "" for a disabled wireguard_ui
// (the block is removed, nothing else changes).
func renderCaddySystemSite(s site.Site, cfg CaddyConfig) (string, error) {
	hosts, err := caddyHosts(s.Hosts)
	if err != nil {
		return "", err
	}
	if len(hosts) != 1 {
		return "", fmt.Errorf("hosts: a system site has exactly one host, got %d", len(hosts))
	}
	host := hosts[0]
	if len(s.Roles) > 0 || len(s.TargetRoles) > 0 || s.OpenReason != "" {
		return "", fmt.Errorf("roles: a system site carries no roles, target roles or open reason")
	}
	if s.TargetKind != site.TargetK8s || s.TargetURL != "" || s.TargetTLSInsecure {
		return "", fmt.Errorf("target: a system site carries no target of its own (the %s template fixes it)", s.SystemTemplate)
	}
	if len(s.Headers) > 0 || len(s.Redirects) > 0 || len(s.APIRules) > 0 {
		return "", fmt.Errorf("headers: a system site takes no headers, redirects or api rules")
	}
	settings, err := site.ParseSystemConfig(s.SystemTemplate, s.SystemConfig)
	if err != nil {
		return "", err
	}
	if s.SystemTemplate != site.TemplateZitadel && s.Cert != "auto" {
		return "", fmt.Errorf("cert: the %s template renders no tls line, cert must be auto", s.SystemTemplate)
	}

	var b strings.Builder
	switch s.SystemTemplate {
	case site.TemplateTagcess:
		// cert auto, as for user sites: a covering certbot certificate gets the tls line right
		// after the host line (where the caddy_ui phase puts it before the first import); no
		// covering certificate leaves Caddy to get its own (the F1 snippet as is).
		cert, err := caddyCert(s.Cert, hosts, cfg.Certs)
		if err != nil {
			return "", err
		}
		// The record cannot pick another certificate, so only one a browser accepts: the host itself or
		// one label below it (the wildcard). The longest covering name is the most specific, so a deeper
		// match means no certificate fits.
		if cert != "" && host != cert && strings.Contains(strings.TrimSuffix(host, "."+cert), ".") {
			cert = ""
		}
		b.WriteString(host + " {\n")
		if cert != "" {
			b.WriteString("\ttls /etc/letsencrypt/live/" + cert + "/fullchain.pem /etc/letsencrypt/live/" + cert + "/privkey.pem\n")
		}
		b.WriteString(caddyTagcessBody)
		b.WriteString("}\n")

	case site.TemplateHeadscale:
		b.WriteString(host + " {\n")
		if settings.Headplane {
			b.WriteString("\thandle /admin* {\n\t\treverse_proxy 127.0.0.1:3000\n\t}\n\n")
		}
		b.WriteString("\thandle {\n\t\treverse_proxy 127.0.0.1:8080\n\t}\n")
		b.WriteString("}\n")

	case site.TemplateWireGuardUI:
		if !settings.Enabled {
			return "", nil
		}
		b.WriteString(host + " {\n\treverse_proxy [::1]:5000\n}\n")

	case site.TemplateZitadel:
		cert, err := caddyCert(s.Cert, hosts, cfg.Certs)
		if err != nil {
			return "", err
		}
		// The S-07 no-tls fallback is for user sites only: a locked system
		// site whose certificate vanished is a problem of the stored set and
		// fails the render (fail closed), never a silent path change.
		if cert == "" {
			return "", fmt.Errorf("cert: auto: no certificate covers the %s system site", s.SystemTemplate)
		}
		b.WriteString(host + " {\n")
		b.WriteString("\ttls /etc/letsencrypt/live/" + cert + "/fullchain.pem /etc/letsencrypt/live/" + cert + "/privkey.pem\n")
		// Two handles, as in today's existing file (`import kaynaklar`): the tailnet range, then
		// the record's internal sources. The parity gate compares the adapted JSON, which tells
		// one matcher from two handles. An empty list drops the second handle (only the tailnet
		// passes). The store already validated both lists (site.ParseSystemConfig).
		b.WriteString("\t@tailnet remote_ip 100.64.0.0/10\n")
		if len(settings.InternalSources) > 0 {
			b.WriteString("\t@serbest remote_ip " + strings.Join(settings.InternalSources, " ") + "\n")
		}
		b.WriteString("\t@giris path " + strings.Join(settings.LoginPaths, " ") + "\n")
		b.WriteString("\n")
		b.WriteString("\thandle @tailnet {\n\t\timport k8s\n\t}\n")
		if len(settings.InternalSources) > 0 {
			b.WriteString("\thandle @serbest {\n\t\timport k8s\n\t}\n")
		}
		b.WriteString("\thandle @giris {\n\t\timport k8s\n\t}\n")
		b.WriteString("\thandle {\n\t\trespond \"Forbidden\" 403\n\t}\n")
		b.WriteString("}\n")

	default:
		return "", fmt.Errorf("system_template: unknown template %q", s.SystemTemplate)
	}
	return b.String(), nil
}
