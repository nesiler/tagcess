package seed

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nesiler/tagcess/test/labenv"
)

// Environment variables that override where the seed tool and the integration tests find Zitadel.
// Zitadel only exists in the lab (ADR 0014: the developer's k3s lab, namespace tagcess-lab), so all are
// optional and the defaults are the lab.
const (
	// EnvZitadelAddr is host:port of Zitadel's gRPC/HTTP endpoint (default the lab host, labenv.ZitadelHost(), on 443).
	EnvZitadelAddr = "TAGCESS_ZITADEL_ADDR"
	// EnvZitadelTLS is "true" when that endpoint speaks TLS (default "true"; "false" means plaintext h2c, loopback only).
	EnvZitadelTLS = "TAGCESS_ZITADEL_TLS"
	// EnvSecretsDir is where the PAT, service user key and pre-auth key live; a relative path
	// resolves against the compose dir (default ".secrets/lab").
	EnvSecretsDir = "TAGCESS_SECRETS_DIR" // #nosec G101 -- the name of a directory variable, not a credential
)

// Endpoint is the resolved Zitadel target and the secrets directory that goes with it.
type Endpoint struct {
	Addr       string // host:port
	Host, Port string
	TLS        bool
	SecretsDir string
	// PATFile holds the IAM_OWNER machine user's PAT: <SecretsDir>/bootstrap-pat.
	PATFile string
}

// EndpointFromEnv reads the Env* variables. baseDir is the compose dir that relative paths and
// the defaults resolve against.
func EndpointFromEnv(baseDir string) (Endpoint, error) {
	ep := Endpoint{Addr: labenv.ZitadelHost() + ":443", TLS: true, SecretsDir: ".secrets/lab"}
	if v := os.Getenv(EnvZitadelAddr); v != "" {
		ep.Addr = v
	}
	host, port, err := net.SplitHostPort(ep.Addr)
	if err != nil {
		return Endpoint{}, fmt.Errorf("seed: %s=%q must be host:port: %w", EnvZitadelAddr, ep.Addr, err)
	}
	ep.Host, ep.Port = host, port
	if v := os.Getenv(EnvZitadelTLS); v != "" {
		if ep.TLS, err = strconv.ParseBool(v); err != nil {
			return Endpoint{}, fmt.Errorf("seed: %s=%q must be true or false: %w", EnvZitadelTLS, v, err)
		}
	}
	if !ep.TLS && !isLoopback(host) {
		return Endpoint{}, fmt.Errorf("seed: %s=%q is not a loopback host, so %s must be true (the PAT would travel in clear)", EnvZitadelAddr, ep.Addr, EnvZitadelTLS)
	}
	if v := os.Getenv(EnvSecretsDir); v != "" {
		ep.SecretsDir = v
	}
	if !filepath.IsAbs(ep.SecretsDir) {
		ep.SecretsDir = filepath.Join(baseDir, ep.SecretsDir)
	}
	ep.PATFile = filepath.Join(ep.SecretsDir, "bootstrap-pat")
	return ep, nil
}

// DialOption is the gRPC transport credential matching the endpoint.
func (e Endpoint) DialOption() grpc.DialOption {
	if e.TLS {
		return grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
	}
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
