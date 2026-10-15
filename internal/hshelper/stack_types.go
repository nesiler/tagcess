package hshelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/stack"
)

// The stack channel (setup-flow.md §5.3): typed operations in /var/lib/tagcess-host, validated here again. The
// wire documents live in this package until the container side exists (a later issue extracts them).

const (
	// StackVersion is the only supported stack document version.
	StackVersion = 1
	// MaxStackRequestBytes bounds a stack request (the typed settings make it larger than an ADR 0021 patch).
	MaxStackRequestBytes = 8 << 10
	// MaxHandoffBytes bounds one handoff drop file (setup-flow.md §5.4).
	MaxHandoffBytes = 4 << 10
)

// StackOp is one operation of setup-flow.md §5.3. The list is closed.
type StackOp string

const (
	OpDiscover       StackOp = "discover"
	OpStackApply     StackOp = "stack.apply"
	OpStackRemove    StackOp = "stack.remove"
	OpServiceRestart StackOp = "service.restart"
	OpStackUpgrade   StackOp = "stack.upgrade"
	OpHandoffCleanup StackOp = "handoff.cleanup"
)

var stackOps = []StackOp{OpDiscover, OpStackApply, OpStackRemove, OpServiceRestart, OpStackUpgrade, OpHandoffCleanup}

// HandoffKind is a secret kind tagcess may hand to the helper (setup-flow.md §5.4). The list is closed.
type HandoffKind string

const (
	KindOIDCSecretHeadscale   HandoffKind = "oidc_secret_headscale"
	KindOIDCSecretOAuth2Proxy HandoffKind = "oidc_secret_oauth2_proxy" //nolint:gosec // a kind name, not a credential
	KindHookSigningKey        HandoffKind = "hook_signing_key"
	KindGroupsSigningKey      HandoffKind = "groups_signing_key"
	KindZitadelServiceKey     HandoffKind = "zitadel_service_key"
)

// kindOwner is the component a kind is installed for.
var kindOwner = map[HandoffKind]stack.Component{
	KindOIDCSecretHeadscale:   stack.Headscale,
	KindOIDCSecretOAuth2Proxy: stack.OAuth2Proxy,
	KindHookSigningKey:        stack.Tagcess,
	KindGroupsSigningKey:      stack.Tagcess,
	KindZitadelServiceKey:     stack.Tagcess,
}

// StackPhase is the last step of a stack operation.
type StackPhase string

const (
	StackPhaseValidate StackPhase = "validate"
	StackPhaseSaveCopy StackPhase = "backup"
	StackPhaseWrite    StackPhase = "write"
	StackPhasePull     StackPhase = "pull"
	StackPhaseStart    StackPhase = "start"
)

var stackPhases = []StackPhase{StackPhaseValidate, StackPhaseSaveCopy, StackPhaseWrite, StackPhasePull, StackPhaseStart}

// StackCode is the closed list of failure reasons a stack result carries.
type StackCode string

const (
	StackInvalidRequest StackCode = "invalid_request"
	StackStaleBase      StackCode = "stale_base"
	StackBusy           StackCode = "busy"
	StackSettings       StackCode = "settings_conflict"
	StackConfigInvalid  StackCode = "config_invalid"
	StackHandoffFailed  StackCode = "handoff_failed"
	StackSaveCopyFailed StackCode = "backup_failed"
	StackWriteFailed    StackCode = "write_failed"
	StackPullFailed     StackCode = "pull_failed"
	StackStartFailed    StackCode = "start_failed"
	StackServiceDown    StackCode = "service_down"
	StackUnsupported    StackCode = "unsupported"
	StackInterrupted    StackCode = "interrupted"
	StackJournalCorrupt StackCode = "journal_corrupt"
)

var stackCodes = []StackCode{
	StackInvalidRequest, StackStaleBase, StackBusy, StackSettings, StackConfigInvalid, StackHandoffFailed,
	StackSaveCopyFailed, StackWriteFailed, StackPullFailed, StackStartFailed, StackServiceDown, StackUnsupported, StackInterrupted,
	StackJournalCorrupt,
}

// StackRequest is the version 1 stack request. A request carries typed values only: no path, image, command or
// free text.
type StackRequest struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	Op        StackOp         `json:"op"`
	BaseRev   string          `json:"base_rev,omitempty"`
	Component stack.Component `json:"component,omitempty"`
	Settings  *stack.Params   `json:"settings,omitempty"`
	Handoff   []HandoffKind   `json:"handoff,omitempty"`
	TargetID  string          `json:"target_id,omitempty"`
}

// StackResult is results/result.json of the stack channel. It carries IDs, states and the kinds installed,
// never a value.
type StackResult struct {
	Version    int             `json:"version"`
	RequestID  string          `json:"request_id"`
	Op         StackOp         `json:"op"`
	State      hostpatch.State `json:"state"`
	Phase      StackPhase      `json:"phase"`
	FinishedAt time.Time       `json:"finished_at"`
	ErrorCode  StackCode       `json:"error_code"`
	// Changed is nil when the helper cannot tell whether the stack changed.
	Changed   *bool         `json:"changed"`
	Installed []HandoffKind `json:"installed"`
	// Service is "down" when the restored service did not start again; empty otherwise.
	Service string `json:"service,omitempty"`
}

var (
	baseRevRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// ErrStackRequest wraps every stack request validation failure; messages are static reasons.
	ErrStackRequest = errors.New("invalid stack request")
)

func badStack(reason string) error { return fmt.Errorf("%w: %s", ErrStackRequest, reason) }

func (o StackOp) valid() bool { return slices.Contains(stackOps, o) }

// writes reports whether the operation changes the stack and so needs a fresh base_rev.
func (o StackOp) writes() bool {
	return o == OpStackApply || o == OpStackRemove || o == OpServiceRestart || o == OpStackUpgrade
}

func validKinds(kinds []HandoffKind) error {
	seen := map[HandoffKind]bool{}
	for _, k := range kinds {
		if _, ok := kindOwner[k]; !ok {
			return badStack("unknown handoff kind")
		}
		if seen[k] {
			return badStack("duplicate handoff kind")
		}
		seen[k] = true
	}
	return nil
}

func knownComponent(c stack.Component) bool { return slices.Contains(stack.AllComponents(), c) }

// ParseStackRequest strictly decodes and validates a stack request: exact key names, no duplicate or unknown
// key, one JSON document, valid UTF-8, the per-operation field rules and the typed settings rules.
func ParseStackRequest(b []byte) (StackRequest, error) {
	var r StackRequest
	if len(b) > MaxStackRequestBytes {
		return r, badStack("request too large")
	}
	if !utf8.Valid(b) {
		return r, badStack("invalid UTF-8")
	}
	if err := strictKeys(b, reflect.TypeOf(r)); err != nil {
		return r, badStack(err.Error())
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return StackRequest{}, badStack("not a stack request document")
	}
	if _, err := dec.Token(); err != io.EOF {
		return StackRequest{}, badStack("data after the document")
	}
	if err := r.validate(); err != nil {
		return StackRequest{}, err
	}
	return r, nil
}

func (r StackRequest) validate() error {
	switch {
	case r.Version != StackVersion:
		return badStack("unsupported version")
	case !hostpatch.ValidRequestID(r.RequestID):
		return badStack("bad request_id")
	case !r.Op.valid():
		return badStack("unknown operation")
	}
	has := func(c bool, what string) error {
		if !c {
			return badStack(what)
		}
		return nil
	}
	if r.Op.writes() {
		if err := has(baseRevRE.MatchString(r.BaseRev), "bad base_rev"); err != nil {
			return err
		}
		if err := has(knownComponent(r.Component), "unknown component"); err != nil {
			return err
		}
	} else if r.BaseRev != "" || r.Component != "" {
		return badStack("base_rev and component are not allowed here")
	}
	if r.Op != OpStackApply && (r.Settings != nil || len(r.Handoff) > 0) {
		return badStack("settings and handoff belong to stack.apply")
	}
	if (r.Op == OpHandoffCleanup) != (r.TargetID != "") {
		return badStack("target_id belongs to handoff.cleanup only")
	}
	if r.TargetID != "" && !hostpatch.ValidRequestID(r.TargetID) {
		return badStack("bad target_id")
	}
	if r.Op == OpStackApply {
		if r.Settings == nil {
			return badStack("settings are required")
		}
		if len(r.Settings.Components) != 0 {
			return badStack("settings carry no component list")
		}
		if err := validKinds(r.Handoff); err != nil {
			return err
		}
		for _, k := range r.Handoff {
			if kindOwner[k] != r.Component {
				return badStack("handoff kind belongs to another component")
			}
		}
	}
	return nil
}

// strictKeys checks that the JSON object in raw uses exactly the json tag names of t, each at most once, and
// (for a struct field that is a pointer to a struct) does the same one level down. encoding/json alone accepts
// duplicate keys and case-variant names.
func strictKeys(raw []byte, t reflect.Type) error {
	allowed := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		ft := f.Type
		if ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct {
			allowed[name] = ft.Elem()
		} else {
			allowed[name] = nil
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return errors.New("malformed JSON object")
		}
		sub, known := allowed[key]
		if !known {
			return errors.New("unknown key")
		}
		if seen[key] {
			return errors.New("duplicate key")
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return errors.New("malformed JSON value")
		}
		if sub != nil && !bytes.Equal(v, []byte("null")) {
			if err := strictKeys(v, sub); err != nil {
				return err
			}
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return errors.New("malformed JSON object")
	}
	return nil
}

// EncodeStackRequest validates r and returns its document.
func EncodeStackRequest(r StackRequest) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStackRequestBytes {
		return nil, badStack("request too large")
	}
	return b, nil
}

func (r StackResult) validate() error {
	switch {
	case r.Version != StackVersion || !hostpatch.ValidRequestID(r.RequestID):
		return errors.New("bad stack result identity")
	case r.Op != "" && !r.Op.valid():
		return errors.New("unknown operation")
	case !r.State.Terminal():
		return errors.New("state is not final")
	case r.Phase != "" && !slices.Contains(stackPhases, r.Phase):
		return errors.New("unknown phase")
	case r.ErrorCode != "" && !slices.Contains(stackCodes, r.ErrorCode):
		return errors.New("unknown error_code")
	case (r.State == hostpatch.StateSucceeded) != (r.ErrorCode == ""):
		return errors.New("error_code must be set exactly when the state is not succeeded")
	case r.FinishedAt.IsZero():
		return errors.New("finished_at is missing")
	}
	return nil
}

func encodeStackResult(r StackResult) ([]byte, error) {
	r.FinishedAt = r.FinishedAt.UTC().Truncate(time.Second)
	if r.Installed == nil {
		r.Installed = []HandoffKind{}
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
