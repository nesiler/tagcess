package discover

import (
	"bufio"
	"bytes"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var versionRE = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.]+)?`)

// firstVersion returns the first version-looking token of s, or "".
func firstVersion(s string) string { return versionRE.FindString(s) }

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// cleanURL keeps scheme, host and path only: no user info, query or fragment.
func cleanURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

func (s *scan) scanHost() {
	a := Attrs{"systemd": s.h.Exists("/run/systemd/system")}
	osr := map[string]string{}
	b, err := s.h.ReadFile("/etc/os-release")
	if err != nil { // Debian and Ubuntu link /etc/os-release to /usr/lib/os-release, which ReadFile refuses to follow
		b, err = s.h.ReadFile("/usr/lib/os-release")
	}
	if err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if ok {
				osr[k] = strings.Trim(v, `"'`)
			}
		}
	}
	a["os_id"], a["os_version"], a["os_name"] = osr["ID"], osr["VERSION_ID"], osr["PRETTY_NAME"]
	if out, err := s.h.Run("uname", "-m"); err == nil {
		a["arch"] = firstLine(out)
	}
	if b, err := s.h.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		a["kernel"] = firstLine(string(b))
	}
	if b, err := s.h.ReadFile("/proc/cpuinfo"); err == nil {
		a["cpus"] = bytes.Count(b, []byte("\nprocessor")) + btoi(bytes.HasPrefix(b, []byte("processor")))
	}
	if b, err := s.h.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.Atoi(f[1]); err == nil {
					a["mem_mb"] = kb / 1024
				}
			}
		}
	}
	if out, err := s.h.Run("df", "-Pk", "/var/lib"); err == nil {
		if l := strings.Split(strings.TrimSpace(out), "\n"); len(l) >= 2 {
			if f := strings.Fields(l[len(l)-1]); len(f) >= 4 {
				if kb, err := strconv.Atoi(f[3]); err == nil {
					a["disk_free_mb"] = kb / 1024
				}
			}
		}
	}
	s.add(KindHost, "host", "os-release, proc, uname, df", a)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// serviceUnits are the systemd services the scan looks for; everything else on the host is not listed.
var serviceUnits = []string{
	"caddy", "headscale", "tailscaled", "k3s", "k3s-agent", "kubelet", "zitadel", "keycloak", "authentik",
	"authentik-server", "headplane", "wireguard-ui", "dnsmasq", "nftables", "oauth2-proxy", "docker", "nginx",
	"traefik", "haproxy", "apache2", "httpd",
}

// scanUnits lists the unit files once and records, for the known names, whether they exist and their state.
func (s *scan) scanUnits() {
	s.units = map[string]bool{}
	out, err := s.h.Run("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	if err != nil {
		if s.h.Exists("/run/systemd/system") {
			s.partial = true
		}
		return
	}
	present := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			present[strings.TrimSuffix(f[0], ".service")] = true
		}
	}
	for _, name := range serviceUnits {
		if present[name] {
			s.units[name] = true
		}
	}
	for n := range present {
		if strings.HasPrefix(n, "wg-quick@") {
			s.units[n] = true
		}
	}
}

// unitState is `active`, `inactive`, `failed`… for a present unit.
func (s *scan) unitState(name string) string {
	out, _ := s.h.Run("systemctl", "is-active", name+".service")
	if st := firstLine(out); st != "" {
		return st
	}
	return "unknown"
}

type container struct {
	Name, Image, State, Ports, Project string
}

// repo is the image name without registry, tag or digest: `ghcr.io/x/headscale:0.26` -> `headscale`.
func (c container) repo() string {
	img, _, _ := strings.Cut(c.Image, "@")
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		img = img[:i]
	}
	return img[strings.LastIndex(img, "/")+1:]
}

func (c container) tag() string {
	img, _, _ := strings.Cut(c.Image, "@")
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		return img[i+1:]
	}
	return ""
}

// publishedPorts turns `0.0.0.0:443->443/tcp, :::443->443/tcp` into the sorted-unique host ports `443/tcp`.
func (c container) publishedPorts() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(c.Ports, ",") {
		host, rest, ok := strings.Cut(p, "->")
		if !ok {
			continue
		}
		_, proto, _ := strings.Cut(rest, "/")
		i := strings.LastIndex(host, ":")
		if i < 0 {
			continue
		}
		if r, _, ok := strings.Cut(host[i+1:], "-"); ok { // a range: keep the first port
			host = host[:i+1] + r
		}
		hp := strings.TrimSpace(host[i+1:]) + "/" + proto
		if !seen[hp] {
			seen[hp] = true
			out = append(out, hp)
		}
	}
	return out
}

func (s *scan) scanDocker() {
	if _, err := s.h.Run("docker", "version", "--format", "{{.Server.Version}}"); err != nil {
		// Without a reachable daemon there is nothing to list; a missing Docker is not a partial scan.
		if _, err2 := s.h.Run("docker", "--version"); err2 == nil {
			s.add(KindDocker, "docker/engine", "docker daemon not reachable", Attrs{"installed": true, "running": false})
		}
		return
	}
	a := Attrs{"installed": true, "running": true}
	if out, err := s.h.Run("docker", "version", "--format", "{{.Server.Version}}"); err == nil {
		a["version"] = firstVersion(out)
	}
	if out, err := s.h.Run("docker", "compose", "version", "--short"); err == nil {
		a["compose_version"] = firstVersion(out)
	}
	s.add(KindDocker, "docker/engine", "docker version", a)

	// Only these fields are requested: no environment, mounts or other labels ever leave Docker.
	format := `{{.Names}}` + "\t" + `{{.Image}}` + "\t" + `{{.State}}` + "\t" + `{{.Ports}}` + "\t" + `{{.Label "com.docker.compose.project"}}`
	out, err := s.h.Run("docker", "ps", "-a", "--no-trunc", "--format", format)
	if err != nil {
		s.partial = true
		return
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 5 {
			continue
		}
		c := container{f[0], f[1], f[2], f[3], f[4]}
		s.cont = append(s.cont, c)
		s.add(KindContainer, "container/"+c.Name, "docker ps", Attrs{
			"name": c.Name, "image": c.Image, "state": c.State, "ports": c.publishedPorts(), "compose_project": c.Project,
		})
	}
}

// containerFor returns the first container whose image repository is one of repos.
func (s *scan) containerFor(repos ...string) (container, bool) {
	for _, c := range s.cont {
		for _, r := range repos {
			if c.repo() == r {
				return c, true
			}
		}
	}
	return container{}, false
}
