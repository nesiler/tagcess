package discover

import (
	"fmt"
	"regexp"
	"strings"
)

type portSpec struct {
	port  int
	proto string
}

// watchedPorts are the listeners of setup-flow.md §3.2.
var watchedPorts = []portSpec{
	{80, "tcp"}, {443, "tcp"}, {443, "udp"}, {3478, "udp"}, {2019, "tcp"}, {4180, "tcp"}, {8080, "tcp"},
	{9090, "tcp"}, {9443, "tcp"}, {50443, "tcp"}, {41641, "udp"},
}

var procRE = regexp.MustCompile(`users:\(\("([^"]+)"`)

// proxyProducts maps a process name or image repository to a reverse proxy product.
var proxyProducts = map[string]string{
	"caddy": "caddy", "nginx": "nginx", "traefik": "traefik", "haproxy": "haproxy",
	"apache2": "apache", "httpd": "apache",
}

type listener struct{ owner string }

// parseSS reads `ss -H -ltunp` lines into (port/proto) -> owner process name.
func parseSS(out string) map[portSpec]listener {
	res := map[portSpec]listener{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		i := strings.LastIndex(f[4], ":")
		if i < 0 {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(f[4][i+1:], "%d", &port); err != nil {
			continue
		}
		key := portSpec{port, f[0]}
		if _, ok := res[key]; ok {
			continue
		}
		owner := ""
		if m := procRE.FindStringSubmatch(l); m != nil {
			owner = m[1]
		}
		res[key] = listener{owner}
	}
	return res
}

func (s *scan) scanListeners() {
	out, err := s.h.Run("ss", "-H", "-ltunp")
	if err != nil {
		s.partial = true
		return
	}
	got := parseSS(out)
	proxyDone := map[string]bool{}
	for _, w := range watchedPorts {
		subject := fmt.Sprintf("listener/%d/%s", w.port, w.proto)
		l, ok := got[w]
		if !ok {
			s.add(KindListener, subject, "ss", Attrs{"port": w.port, "proto": w.proto, "listening": false})
			continue
		}
		a := Attrs{"port": w.port, "proto": w.proto, "listening": true, "owner": l.owner, "owner_kind": "process"}
		image := ""
		switch l.owner {
		case "docker-proxy":
			a["owner_kind"], a["owner"] = "unknown", ""
			for _, c := range s.cont {
				for _, p := range c.publishedPorts() {
					if p == fmt.Sprintf("%d/%s", w.port, w.proto) {
						a["owner_kind"], a["owner"], image = "container", c.Name, c.repo()+" "+c.tag()
					}
				}
			}
		case "":
			a["owner_kind"] = "unknown"
		}
		s.add(KindListener, subject, "ss", a)

		if w.port != 80 && w.port != 443 || proxyDone[fmt.Sprint(w.port)] {
			continue
		}
		proxyDone[fmt.Sprint(w.port)] = true
		s.scanProxy(w.port, l.owner, a["owner_kind"].(string), image)
	}
}

// scanProxy names the product behind 80/443 and its version. The proxy's config files are not read.
func (s *scan) scanProxy(port int, owner, ownerKind, image string) {
	a := Attrs{"port": port, "product": "unknown", "owner_kind": ownerKind}
	subject := fmt.Sprintf("reverse_proxy/%d", port)
	switch ownerKind {
	case "container":
		repo, tag, _ := strings.Cut(image, " ")
		if p, ok := proxyProducts[repo]; ok {
			a["product"], a["version"] = p, firstVersion(tag)
		}
	case "process":
		if p, ok := proxyProducts[owner]; ok {
			a["product"] = p
			a["version"] = s.proxyVersion(owner)
		}
	}
	s.add(KindReverseProxy, subject, "ss + version", a)
}

func (s *scan) proxyVersion(proc string) string {
	var out string
	var err error
	switch proc {
	case "caddy":
		out, err = s.h.Run("caddy", "version")
	case "nginx":
		out, err = s.h.Run("nginx", "-v")
	case "traefik":
		out, err = s.h.Run("traefik", "version")
	case "haproxy":
		out, err = s.h.Run("haproxy", "-v")
	case "apache2":
		out, err = s.h.Run("apache2", "-v")
	case "httpd":
		out, err = s.h.Run("httpd", "-v")
	}
	if err != nil {
		return ""
	}
	return firstVersion(firstLine(out))
}
