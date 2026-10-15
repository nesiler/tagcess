// Package stack renders the Compose project and service configs of a fresh tagcess server from typed parameters
// and the release's version manifest (setup-flow.md §5.1, §5.5). Only the host helper imports it: nothing here
// reads or writes the host, and the manifest is embedded by internal/stack/manifest, which the tagcess binary
// must never import.
package stack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// Component is a service of the managed stack (setup-flow.md §5.2).
type Component string

const (
	Caddy       Component = "caddy"
	Headscale   Component = "headscale"
	Tagcess     Component = "tagcess"
	OAuth2Proxy Component = "oauth2-proxy"
	Tailscale   Component = "tailscale"
)

// AllComponents lists every component in the fixed render order.
func AllComponents() []Component {
	return []Component{Caddy, Headscale, Tagcess, OAuth2Proxy, Tailscale}
}

// Image pins one service image by tag and digest, so a moved tag cannot change what runs.
type Image struct {
	Name   string `json:"name"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

var (
	imageNameRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+$|^[a-z0-9]+([._-][a-z0-9]+)*$`)
	imageTagRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Validate checks that the image has a name, a tag and a sha256 digest.
func (i Image) Validate() error {
	switch {
	case !imageNameRe.MatchString(i.Name) || len(i.Name) > 255:
		return fmt.Errorf("image name %q is invalid", i.Name)
	case !imageTagRe.MatchString(i.Tag):
		return fmt.Errorf("image tag %q is invalid", i.Tag)
	case !digestRe.MatchString(i.Digest):
		return fmt.Errorf("image digest %q is not a sha256 digest", i.Digest)
	}
	return nil
}

// Ref is the pinned reference `name:tag@digest`.
func (i Image) Ref() string { return i.Name + ":" + i.Tag + "@" + i.Digest }

// Manifest lists the images a tagcess release was tested with.
type Manifest struct {
	Release string              `json:"release"`
	Images  map[Component]Image `json:"images"`
}

// Load parses and validates a manifest: unknown fields and components are errors, and every component must be
// present.
func Load(b []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate checks that every component has exactly one valid image and no other component exists.
func (m Manifest) Validate() error {
	if m.Release == "" {
		return fmt.Errorf("manifest: release is empty")
	}
	known := map[Component]bool{}
	for _, c := range AllComponents() {
		known[c] = true
		img, ok := m.Images[c]
		if !ok {
			return fmt.Errorf("manifest: no image for %s", c)
		}
		if err := img.Validate(); err != nil {
			return fmt.Errorf("manifest: %s: %w", c, err)
		}
	}
	var extra []string
	for c := range m.Images {
		if !known[c] {
			extra = append(extra, string(c))
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("manifest: unknown components %v", extra)
	}
	return nil
}
