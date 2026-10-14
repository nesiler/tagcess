package labenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLabEnv_Resolution(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "lab.env")
	t.Setenv(EnvFile, filepath.Join(dir, "missing.env"))
	t.Setenv(EnvDomain, "")
	t.Setenv(EnvZitadelHost, "")

	if Domain() != DefaultDomain || ZitadelHost() != "tagcess-zitadel.lab.example.com" {
		t.Errorf("defaults: %q %q", Domain(), ZitadelHost())
	}
	if ZitadelIssuer() != "https://tagcess-zitadel.lab.example.com" {
		t.Errorf("issuer %q", ZitadelIssuer())
	}

	body := "# my lab\nexport TAGCESS_LAB_DOMAIN=\"old.example.net\"\nTAGCESS_LAB_DOMAIN='dev.example.net'\nOTHER=x\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvFile, file)
	if Domain() != "dev.example.net" || ZitadelHost() != "tagcess-zitadel.dev.example.net" {
		t.Errorf("file: %q %q", Domain(), ZitadelHost())
	}

	t.Setenv(EnvDomain, "env.example.org")
	if Domain() != "env.example.org" {
		t.Errorf("the environment must win over the file: %q", Domain())
	}
	t.Setenv(EnvZitadelHost, "auth.env.example.org")
	if ZitadelHost() != "auth.env.example.org" {
		t.Errorf("explicit host: %q", ZitadelHost())
	}
}
