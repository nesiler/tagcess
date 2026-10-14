// Package hostpatch is the wire contract between the tagcess container and the Headscale host
// helper for H-07 (ADR 0021 a/b/c): the request, the secret-free `base_rev` projection, and the
// `result.json` / `status.json` / marker documents. Both sides import it, so a document is built
// and checked by one set of rules. It is stdlib only and does no file or network I/O.
//
// The only patch is `{"oidc":{"allowed_groups":[...]}}`, a full replacement list. Every reader
// here is strict: unknown or duplicate JSON keys, extra fields, bad UTF-8, trailing data and
// oversize input are rejected, because encoding/json would silently accept all of them.
package hostpatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"unicode/utf8"
)

const (
	// Version is the only supported document version.
	Version = 1
	// MaxRequestBytes bounds a request; MaxResultBytes bounds result.json and status.json.
	MaxRequestBytes = 4 << 10
	MaxResultBytes  = 4 << 10
	// MaxMarkerBytes bounds requests/request.ready.
	MaxMarkerBytes = 64
)

// The allowed VPN role groups, in the canonical order used by the projection and the candidate.
const (
	GroupDevops    = "devops"
	GroupDeveloper = "developer"
	GroupStandart  = "standart"
)

var canonicalGroups = [...]string{GroupDevops, GroupDeveloper, GroupStandart}

var (
	uuidRE    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	baseRevRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrInvalidRequest wraps every request/group/base_rev validation failure. Messages are static
// reasons; they never echo the offending input.
var ErrInvalidRequest = errors.New("invalid request")

// Request is the version 1 request document (ADR 0021 a). There is deliberately no time field and
// no recovery_of.
type Request struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	BaseRev   string `json:"base_rev"`
	Patch     Patch  `json:"patch"`
}

// Patch is the single supported patch shape.
type Patch struct {
	OIDC OIDCPatch `json:"oidc"`
}

// OIDCPatch holds the full new value of oidc.allowed_groups.
type OIDCPatch struct {
	AllowedGroups []string `json:"allowed_groups"`
}

// ValidRequestID reports whether s is a lowercase UUID.
func ValidRequestID(s string) bool { return uuidRE.MatchString(s) }

func validBaseRev(s string) bool { return baseRevRE.MatchString(s) }

func invalidRequest(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidRequest, reason) }

// normalizeGroups checks that groups are unique members of the closed set and returns them in
// canonical order. It accepts an empty list; callers add their own size rules. The input is not
// modified.
func normalizeGroups(groups []string) ([]string, error) {
	if len(groups) > len(canonicalGroups) {
		return nil, errors.New("too many groups")
	}
	out := make([]string, 0, len(groups))
	for _, want := range canonicalGroups {
		n := 0
		for _, g := range groups {
			if g == want {
				n++
			}
		}
		if n > 1 {
			return nil, errors.New("duplicate group")
		}
		if n == 1 {
			out = append(out, want)
		}
	}
	if len(out) != len(groups) {
		return nil, errors.New("unknown group")
	}
	return out, nil
}

// ValidateGroups applies ADR 0021 a to a new allowed_groups value: 1–3 unique values from the
// closed set, `devops` required.
func ValidateGroups(groups []string) error {
	if len(groups) == 0 {
		return invalidRequest("allowed_groups is empty")
	}
	norm, err := normalizeGroups(groups)
	if err != nil {
		return invalidRequest(err.Error())
	}
	if !slices.Contains(norm, GroupDevops) {
		return invalidRequest("allowed_groups must include devops")
	}
	return nil
}

// BuildRequest returns the request document for a new allowed_groups value. The list is written in
// canonical order, so equal sets give equal bytes.
func BuildRequest(requestID, baseRev string, groups []string) ([]byte, error) {
	if !ValidRequestID(requestID) {
		return nil, invalidRequest("bad request_id")
	}
	if !validBaseRev(baseRev) {
		return nil, invalidRequest("bad base_rev")
	}
	if err := ValidateGroups(groups); err != nil {
		return nil, err
	}
	norm, _ := normalizeGroups(groups)
	return json.Marshal(Request{
		Version:   Version,
		RequestID: requestID,
		BaseRev:   baseRev,
		Patch:     Patch{OIDC: OIDCPatch{AllowedGroups: norm}},
	})
}

// ParseRequest strictly decodes and validates a request document. The returned list is in
// canonical order.
func ParseRequest(b []byte) (Request, error) {
	if len(b) > MaxRequestBytes {
		return Request{}, invalidRequest("request too large")
	}
	top, err := members(b, "version", "request_id", "base_rev", "patch")
	if err != nil {
		return Request{}, invalidRequest(err.Error())
	}
	patch, err := members(top["patch"], "oidc")
	if err != nil {
		return Request{}, invalidRequest("patch: " + err.Error())
	}
	oidc, err := members(patch["oidc"], "allowed_groups")
	if err != nil {
		return Request{}, invalidRequest("patch.oidc: " + err.Error())
	}

	var req Request
	if req.Version, err = jsonInt(top["version"]); err != nil {
		return Request{}, invalidRequest("version: " + err.Error())
	}
	if req.RequestID, err = jsonString(top["request_id"]); err != nil {
		return Request{}, invalidRequest("request_id: " + err.Error())
	}
	if req.BaseRev, err = jsonString(top["base_rev"]); err != nil {
		return Request{}, invalidRequest("base_rev: " + err.Error())
	}
	if req.Version != Version {
		return Request{}, invalidRequest("unsupported version")
	}
	if !ValidRequestID(req.RequestID) {
		return Request{}, invalidRequest("bad request_id")
	}
	if !validBaseRev(req.BaseRev) {
		return Request{}, invalidRequest("bad base_rev")
	}
	var groups []string
	if bytes.Equal(oidc["allowed_groups"], []byte("null")) {
		return Request{}, invalidRequest("allowed_groups is null")
	}
	if err := json.Unmarshal(oidc["allowed_groups"], &groups); err != nil {
		return Request{}, invalidRequest("allowed_groups must be a list of strings")
	}
	if err := ValidateGroups(groups); err != nil {
		return Request{}, err
	}
	req.Patch.OIDC.AllowedGroups, _ = normalizeGroups(groups)
	return req, nil
}

// Projection is the canonical secret-free view of the config that base_rev hashes:
// `{"oidc":{"allowed_groups":[...]}}`, values in canonical order, no whitespace. A missing or empty
// field projects to `[]`. Values outside the closed set or duplicates are an error.
func Projection(groups []string) ([]byte, error) {
	norm, err := normalizeGroups(groups)
	if err != nil {
		return nil, fmt.Errorf("allowed_groups outside the supported set: %w", err)
	}
	return json.Marshal(Patch{OIDC: OIDCPatch{AllowedGroups: norm}})
}

// BaseRev is the lowercase hex SHA-256 of the projection.
func BaseRev(groups []string) (string, error) {
	proj, err := Projection(groups)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(proj)
	return hex.EncodeToString(sum[:]), nil
}

// members splits a JSON object into its raw member values. It is the strict reader encoding/json
// lacks: keys must be exactly one of allowed (case-sensitive), none may repeat, all must be
// present, bytes must be valid UTF-8, and nothing but whitespace may follow the object. Errors are
// static reasons and never quote the input.
func members(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := make(map[string]json.RawMessage, len(allowed))
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return nil, errors.New("malformed JSON object")
		}
		if !slices.Contains(allowed, key) {
			return nil, errors.New("unknown key")
		}
		if _, dup := out[key]; dup {
			return nil, errors.New("duplicate key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("malformed JSON value")
		}
		out[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("malformed JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	for _, k := range allowed {
		if _, ok := out[k]; !ok {
			return nil, errors.New("missing key")
		}
	}
	return out, nil
}

func jsonString(raw json.RawMessage) (string, error) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", errors.New("not a string")
	}
	return s, nil
}

func jsonInt(raw json.RawMessage) (int, error) {
	var n int
	if len(raw) == 0 || raw[0] == 'n' || json.Unmarshal(raw, &n) != nil {
		return 0, errors.New("not an integer")
	}
	return n, nil
}

func jsonBool(raw json.RawMessage) (bool, error) {
	switch string(raw) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errors.New("not a boolean")
}
