package web

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/nesiler/tagcess/internal/k8s"
)

// Per-field errors of the k8s connection profile form (2026-10-06 item 11). The validation itself
// stays where it was (the form parser and k8s.ProfileStore.Save); this only places each refusal next
// to the field it concerns, in plain Turkish, so the person sees what to fix.

// k8sFieldError is a form parse error that belongs to one field.
type k8sFieldError struct {
	field string
	err   error
}

func (e k8sFieldError) Error() string { return e.err.Error() }
func (e k8sFieldError) Unwrap() error { return e.err }

// k8sFieldMessages are the Turkish texts of the profile validator's messages (k8s/profile.go).
var k8sFieldMessages = map[string]string{
	"is required":                                "zorunlu",
	"must be a DNS name, not an IP address":      "IP değil, bir DNS adı olmalı",
	"must look like example.com/name":            "örnek.com/ad biçiminde olmalı (ör. traefik.io/ingress-controller)",
	"must be an https URL without fragment":      "https:// ile başlayan bir URL olmalı",
	"is not a valid URL":                         "geçerli bir URL değil",
	"must use https":                             "https:// ile başlamalı",
	"must not contain user info":                 "kullanıcı adı/parola içermemeli",
	"must not contain a query or fragment":       "? veya # içermemeli",
	"is not a valid https URL":                   "geçerli bir https adresi değil",
	"has an invalid port":                        "port geçersiz",
	"must not contain an IP zone":                "IP zone içermemeli",
	"has an invalid host":                        "host geçersiz",
	"has an invalid path":                        "path geçersiz",
	"at least one entry is required":             "en az bir değer gerekli",
	"is not a valid name":                        "geçersiz ad (küçük harf, rakam ve - kullanın)",
	"duplicate entry":                            "aynı değer iki kez yazılmış",
	"at least one listener is required":          "en az bir listener gerekli",
	"address must be an IP address":              "IP olmalı",
	"address must be a concrete unicast address": "somut bir unicast IP olmalı",
	"port must be between 1 and 65535":           "port 1–65535 arasında olmalı",
	"entry point is not a valid name":            "entrypoint adı geçersiz",
	"duplicate listener":                         "aynı listener iki kez yazılmış",
}

var k8sIndexedField = regexp.MustCompile(`^([a-z_]+)\[(\d+)\]$`)

// k8sProfileFieldErrors maps a refusal to the form's fields. ok is false when the error does not
// name a field; the page then shows it as a whole.
func k8sProfileFieldErrors(err error) (map[string]string, bool) {
	var fe k8sFieldError
	if errors.As(err, &fe) {
		return map[string]string{fe.field: fe.err.Error()}, true
	}
	var ve *k8s.ValidationError
	if !errors.As(err, &ve) || len(ve.Fields) == 0 {
		return nil, false
	}
	out := map[string]string{}
	for _, f := range ve.Fields {
		field, prefix := f.Field, ""
		if m := k8sIndexedField.FindStringSubmatch(f.Field); m != nil {
			n, _ := strconv.Atoi(m[2])
			field, prefix = m[1], strconv.Itoa(n+1)+". değer: "
			if field == "internal" || field == "public" {
				prefix = strconv.Itoa(n+1) + ". satır: "
			}
		}
		msg := f.Message
		if tr, ok := k8sFieldMessages[msg]; ok {
			msg = tr
		} else if strings.HasSuffix(msg, " is also an internal listener") {
			msg = strings.TrimSuffix(msg, " is also an internal listener") + " aynı zamanda internal listener"
		}
		if prev := out[field]; prev != "" {
			out[field] = prev + "; " + prefix + msg
		} else {
			out[field] = prefix + msg
		}
	}
	return out, true
}
