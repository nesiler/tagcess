package adopttarget

// AdoptVars are the installer settings of the adopt-shaped target (the adopt column of the runbook's
// variable table, with example.test names). Tests add or override keys per case.
func AdoptVars() map[string]any {
	return map[string]any{
		"install_env":             "adopttest",
		"install_mode":            "adopt",
		"tagcess_domain":          "c.example.test",
		"cert_names":              []string{"internal.a.example.test", "b.example.test", "c.example.test"},
		"caddy_sites_dir":         "/etc/caddy/sites",
		"caddy_version":           "2.8",
		"oauth2_proxy_runtime":    "systemd",
		"k8s_tailnet_ip":          "100.64.0.5",
		"k8s_target_addr":         "https://100.64.0.5:8443",
		"traefik_entrypoint":      "internal",
		"traefik_port":            8443,
		"zitadel_discovery_url":   "http://127.0.0.1:18080/.well-known/openid-configuration",
		"zitadel_install_enabled": false,
	}
}

// BareVars are the installer settings of the empty target (lab/fresh column, example.test names).
func BareVars() map[string]any {
	return map[string]any{
		"install_env":             "baretest",
		"install_mode":            "fresh",
		"tagcess_domain":          "lab.example.test",
		"cert_names":              []string{"lab.example.test"},
		"caddy_sites_dir":         "",
		"oauth2_proxy_runtime":    "container",
		"zitadel_install_enabled": false,
		"zitadel_discovery_url":   "http://127.0.0.1:18080/.well-known/openid-configuration",
	}
}

// Merge returns base with the keys of over replaced.
func Merge(base map[string]any, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
