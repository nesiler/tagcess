package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/netpolicy"
)

// Preview samples of the k8s connection and setup screens. Query flags pick the state:
// /k8s/connection ?state=empty|expired|mismatch|error, /k8s/setup ?state=empty|review|failed|error.

func init() {
	previewPages = append(previewPages,
		previewPage{"/k8s/connection", "k8s", "k8s bağlantısı", func(r *http.Request) templ.Component {
			return K8sConnectionPage(previewK8sConnection(r.URL.Query().Get("state")), previewCSRF)
		}},
		previewPage{"/k8s/setup", "k8s", "k8s kurulum yardımı", func(r *http.Request) templ.Component {
			return K8sSetupPage(previewK8sSetup(r.URL.Query().Get("state")), previewCSRF)
		}},
	)
}

func previewK8sConnection(state string) k8sConnectionView {
	v := k8sConnectionView{
		Profile: k8sProfileFields{
			Endpoint: "https://10.0.0.1:6443", TLSServerName: "kubernetes.default", Namespaces: "web, apps",
			Controller: "traefik.io/ingress-controller", IngressClasses: "traefik",
			Internal: "10.0.0.10 443 websecure-internal", Public: "10.0.0.11 443 websecure",
			DeclaredTokenExpiry: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		},
		ProfileSet:     true,
		CredentialSet:  true,
		Credential:     &k8s.Info{Endpoint: "https://10.0.0.1:6443", TLSServerName: "kubernetes.default", CAFingerprints: []string{"3F:9A:0C:51:7E:22:B8:D4:61:0A:EE:19:C7:5B:42:90:13:AD:77:E0:8C:F2:31:6B:5A:94:D0:2E:BB:07:C1:68"}},
		DeclaredExpiry: "2026-12-31T00:00:00Z",
		LastCheck:      "2026-10-06T08:30:12Z",
		Notice:         "bağlantı profili kaydedildi",
	}
	switch state {
	case "empty":
		return k8sConnectionView{}
	case "expired":
		v.Notice = ""
		v.DeclaredExpiry = "2026-09-30T00:00:00Z"
		v.DeclaredExpired = true
	case "mismatch":
		v.Notice = ""
		v.Mismatch = true
		v.Credential.Endpoint = "https://10.0.0.2:6443"
	case "error":
		v.Notice = ""
		v.Error = "endpoint: https şeması gerekli"
		v.ProfileErr = "bağlantı profili okunamadı veya bozuk; gösterilen değerler kullanılamaz: invalid character '}'"
		v.CredentialErr = "kayıtlı credential okunamadı; yeni yükleme önceki çalışan dosyayı ezmez: permission denied"
	}
	return v
}

func previewK8sSetup(state string) k8sSetupView {
	v := k8sSetupView{
		ProfileSet: true, Namespaces: []string{"web", "apps"}, Controller: "traefik.io/ingress-controller",
		IngressClasses: []string{"traefik"},
		SA:             k8s.ServiceAccountRef{Namespace: "tagcess", Name: k8s.DefaultServiceAccountName},
		API:            k8sPolicyForm{Scope: netpolicy.ScopeAPI, Addresses: "10.0.0.1", Ports: "6443", Stored: true},
		Probe:          k8sPolicyForm{Scope: netpolicy.ScopeProbe, Addresses: "10.0.0.0/24", Ports: "443, 8443", Stored: true},
		Notice:         "policy kaydedildi; sonraki API/probe kurulumu bu değerleri kullanır",
	}
	switch state {
	case "empty":
		return k8sSetupView{
			SA:  k8s.ServiceAccountRef{Namespace: "tagcess", Name: k8s.DefaultServiceAccountName},
			API: k8sPolicyForm{Scope: netpolicy.ScopeAPI}, Probe: k8sPolicyForm{Scope: netpolicy.ScopeProbe},
			NextStep:     "API IP policy'sini kaydedin: bağlantı ayarları buna göre doğrulanır.",
			NextStepHref: "#policy-api",
		}
	case "review", "failed":
		v.Notice = ""
		at := time.Date(2026, 10, 6, 8, 30, 15, 0, time.UTC)
		rev := k8s.Review{
			Principal: "system:serviceaccount:tagcess:tagcess-reader", At: at, Namespaces: []string{"web", "apps"},
			Required: []k8s.Check{
				{Namespace: "web", Group: "networking.k8s.io", Resource: "ingresses", Verb: "list", Want: true, Answered: true, Allowed: true},
				{Namespace: "web", Resource: "services", Verb: "get", Want: true, Answered: true, Allowed: true},
				{Resource: "ingressclasses", Group: "networking.k8s.io", Verb: "list", Want: true, Answered: true, Allowed: true},
			},
			Forbidden: []k8s.Check{
				{Namespace: "web", Resource: "secrets", Verb: "get", Want: false, Answered: true, Allowed: false},
				{Namespace: "web", Group: "networking.k8s.io", Resource: "ingresses", Verb: "delete", Want: false, Answered: true, Allowed: false},
			},
		}
		if state == "failed" {
			rev.Forbidden[0].Allowed = true
			rev.Forbidden[1].Answered = false
		}
		v.Review = &rev
	case "error":
		v.Notice = ""
		v.Error = "addresses: 169.254.169.254 metadata adresi reddedilir"
		v.ProfileErr = "invalid character '}'"
		v.ProfileSet = false
		v.Namespaces, v.IngressClasses, v.Controller = nil, nil, ""
		v.ReviewErr = "bağlantı profili okunamadı; izin testi çalıştırılmadı"
		v.API.ReadErr = "kayıtlı policy okunamadı veya bozuk: unexpected end of JSON input"
		v.API.Stored, v.API.Addresses, v.API.Ports = false, "", ""
		v.Probe.Stored, v.Probe.Addresses, v.Probe.Ports = false, "", ""
	}
	return v
}
