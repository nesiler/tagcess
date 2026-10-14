// Command seed bootstraps the test stack: `go run ./test/compose/seed/cmd -phase=zitadel`
// after the lab Zitadel is healthy, then `-phase=headscale` after Headscale is up (test/lab/up.sh).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nesiler/tagcess/test/compose/seed"
)

func main() {
	phase := flag.String("phase", "zitadel", `which half to run: "zitadel" or "headscale"`)
	composeDir := flag.String("compose-dir", ".", "directory holding compose.yaml, headscale/, .secrets/")
	flag.Parse()

	dir, err := filepath.Abs(*composeDir)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}
	ep, err := seed.EndpointFromEnv(dir)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	switch *phase {
	case "zitadel":
		patBytes, err := os.ReadFile(ep.PATFile) // #nosec G304 -- dev-tool path from -compose-dir/env, not user input
		if err != nil {
			log.Fatalf("seed: read bootstrap PAT at %s (is Zitadel up and healthy?): %v", ep.PATFile, err)
		}
		// TAGCESS_WEBHOOK_URL (F1-020) and TAGCESS_GROUPS_URL (F1-026) are the Actions v2 target
		// endpoints; when unset the matching target and executions are skipped, so the seed still
		// works for tasks that only need the base stack.
		cfg := seed.Config{
			ZitadelAddr:              ep.Addr,
			ZitadelTLS:               ep.TLS,
			BootstrapPAT:             strings.TrimSpace(string(patBytes)),
			SecretsDir:               ep.SecretsDir,
			EnvFile:                  filepath.Join(dir, ".env"),
			HeadscaleRedirectURI:     envOr("TAGCESS_HEADSCALE_REDIRECT_URI", "http://localhost:8090/oidc/callback"),
			OAuth2ProxyRedirectURI:   envOr("TAGCESS_OAUTH2PROXY_REDIRECT_URI", "http://localhost:8080/oauth2/callback"),
			OAuth2ProxyPostLogoutURI: strings.TrimSpace(os.Getenv("TAGCESS_OAUTH2PROXY_POST_LOGOUT_URI")),
			WebhookURL:               strings.TrimSpace(os.Getenv("TAGCESS_WEBHOOK_URL")),
			GroupsURL:                strings.TrimSpace(os.Getenv("TAGCESS_GROUPS_URL")),
		}
		res, err := seed.SeedZitadel(ctx, cfg)
		if err != nil {
			log.Fatalf("seed: %v", err)
		}
		fmt.Printf("zitadel: org=%s project=%s(%v) users=%d service_user=%s key=%s\n",
			res.OrgID, res.ProjectID, res.RoleKeys, len(res.Users), res.ServiceUserID, res.KeyFilePath)
		if res.OAuth2ProxyApp != nil {
			fmt.Printf("oauth2-proxy: app=%s client_id=%s\n", res.OAuth2ProxyApp.AppID, res.OAuth2ProxyApp.ClientID)
		}
		if res.WebhookTargetID != "" {
			fmt.Printf("webhook: target=%s endpoint=%s key=%s\n", res.WebhookTargetID, cfg.WebhookURL, filepath.Join(cfg.SecretsDir, seed.WebhookSigningKeyFile))
		}
		if res.GroupsTargetID != "" {
			fmt.Printf("groups: target=%s endpoint=%s key=%s\n", res.GroupsTargetID, cfg.GroupsURL, filepath.Join(cfg.SecretsDir, seed.GroupsSigningKeyFile))
		}

	case "headscale":
		res, err := seed.SeedHeadscale(ctx, filepath.Join(dir, "compose.yaml"))
		if err != nil {
			log.Fatalf("seed: %v", err)
		}
		fmt.Printf("headscale: user=%s preauthkey=<cached in .secrets/headscale-preauthkey.json>\n", res.UserID)

	default:
		log.Fatalf("seed: unknown -phase %q", *phase)
	}
}

// envOr returns the trimmed environment value of key, or def when it is unset or empty. The F5 host lab
// (test/f5) points the redirect URIs at its real hostnames instead of the compose-stack localhost ones.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
