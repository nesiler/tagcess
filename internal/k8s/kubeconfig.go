package k8s

import (
	"encoding/base64"
	"strings"

	"go.yaml.in/yaml/v3"
)

const maxKubeconfigSize = 1 << 20 // [Ö] a narrow kubeconfig is a few KiB; anything bigger is not narrow

// ParseKubeconfig turns an uploaded kubeconfig into the narrow credential model: the HTTPS endpoint,
// embedded CA data, TLS server name and token of one context (contextName, or current-context when
// empty). The file is only parsed. Nothing it names is executed or opened: exec, auth-provider,
// tokenFile, file-path CA, client certificates and disabled verification are rejected anywhere in
// the file, so a multi-user admin kubeconfig is not accepted by accident. Errors never repeat file
// content.
func ParseKubeconfig(data []byte, contextName string) (Credential, error) {
	var verr ValidationError
	reject := func(msg string) { verr.Fields = append(verr.Fields, FieldError{"kubeconfig", msg}) }

	if len(data) > maxKubeconfigSize {
		reject("is too large")
		return Credential{}, &verr
	}
	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		// yaml errors can quote values, so none of the text is passed on.
		reject("is not valid YAML of the expected shape")
		return Credential{}, &verr
	}

	for _, c := range kc.Clusters {
		if present(c.Cluster.CertificateAuthority) {
			reject("certificate-authority file paths are not allowed; embed the CA data")
		}
		if c.Cluster.InsecureSkipTLSVerify {
			reject("insecure-skip-tls-verify is not allowed")
		}
	}
	for _, u := range kc.Users {
		for _, f := range []struct {
			node yaml.Node
			msg  string
		}{
			{u.User.Exec, "exec is not allowed"},
			{u.User.AuthProvider, "auth-provider is not allowed"},
			{u.User.TokenFile, "tokenFile is not allowed; upload the token itself"},
			{u.User.ClientCertificate, "client certificates are not allowed"},
			{u.User.ClientCertificateData, "client certificates are not allowed"},
			{u.User.ClientKey, "client keys are not allowed"},
			{u.User.ClientKeyData, "client keys are not allowed"},
		} {
			if present(f.node) {
				reject(f.msg)
			}
		}
	}
	if len(verr.Fields) > 0 {
		return Credential{}, &verr
	}

	if contextName == "" {
		contextName = kc.CurrentContext
	}
	if contextName == "" {
		reject("has no current-context; name the context to use")
		return Credential{}, &verr
	}
	var ctx *kcContext
	for i := range kc.Contexts {
		if kc.Contexts[i].Name == contextName {
			ctx = &kc.Contexts[i].Context
			break
		}
	}
	if ctx == nil {
		reject("does not contain the selected context")
		return Credential{}, &verr
	}
	var cluster *kcCluster
	for i := range kc.Clusters {
		if kc.Clusters[i].Name == ctx.Cluster {
			cluster = &kc.Clusters[i].Cluster
			break
		}
	}
	var user *kcUser
	for i := range kc.Users {
		if kc.Users[i].Name == ctx.User {
			user = &kc.Users[i].User
			break
		}
	}
	if cluster == nil || user == nil {
		reject("the selected context refers to a cluster or user that is not defined")
		return Credential{}, &verr
	}

	cred := Credential{Endpoint: cluster.Server, TLSServerName: cluster.TLSServerName, Token: user.Token}
	if cluster.CertificateAuthorityData != "" {
		// kubeconfig stores the PEM base64-encoded; line breaks from folded YAML are tolerated.
		clean := strings.Join(strings.Fields(cluster.CertificateAuthorityData), "")
		pemBytes, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			reject("certificate-authority-data is not valid base64")
			return Credential{}, &verr
		}
		cred.CAData = string(pemBytes)
	}
	return normalizeCredential(cred)
}

func present(n yaml.Node) bool { return n.Kind != 0 }

type kubeconfigFile struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string    `yaml:"name"`
		Cluster kcCluster `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User kcUser `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string    `yaml:"name"`
		Context kcContext `yaml:"context"`
	} `yaml:"contexts"`
}

type kcCluster struct {
	Server                   string    `yaml:"server"`
	TLSServerName            string    `yaml:"tls-server-name"`
	InsecureSkipTLSVerify    bool      `yaml:"insecure-skip-tls-verify"`
	CertificateAuthority     yaml.Node `yaml:"certificate-authority"`
	CertificateAuthorityData string    `yaml:"certificate-authority-data"`
}

// kcUser lists the mechanisms the importer refuses as yaml.Node so that a key that is present but
// empty (`exec:`) still counts.
type kcUser struct {
	Token                 string    `yaml:"token"`
	TokenFile             yaml.Node `yaml:"tokenFile"`
	Exec                  yaml.Node `yaml:"exec"`
	AuthProvider          yaml.Node `yaml:"auth-provider"`
	ClientCertificate     yaml.Node `yaml:"client-certificate"`
	ClientCertificateData yaml.Node `yaml:"client-certificate-data"`
	ClientKey             yaml.Node `yaml:"client-key"`
	ClientKeyData         yaml.Node `yaml:"client-key-data"`
}

type kcContext struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}
