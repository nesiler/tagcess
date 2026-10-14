package hostpatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// State is a journal state (ADR 0021 c). The five states are closed.
type State string

const (
	StateAccepted    State = "accepted"
	StateApplying    State = "applying"
	StateSucceeded   State = "succeeded"
	StateFailed      State = "failed"
	StateInterrupted State = "interrupted"
)

// Phase is the last step reached (ADR 0021 c).
type Phase string

const (
	PhaseValidate Phase = "validate"
	PhaseBackup   Phase = "backup"
	PhaseReplace  Phase = "replace"
	PhaseRestart  Phase = "restart"
	PhaseCheck    Phase = "check"
)

// ErrorCode is the closed list of failure reasons a result can carry.
type ErrorCode string

const (
	CodeInvalidRequest   ErrorCode = "invalid_request"
	CodeStaleBase        ErrorCode = "stale_base"
	CodeDuplicateID      ErrorCode = "duplicate_id"
	CodeBusy             ErrorCode = "busy"
	CodeConfigUnreadable ErrorCode = "config_unreadable"
	CodeConfigtestFailed ErrorCode = "configtest_failed"
	CodeBackupFailed     ErrorCode = "backup_failed"
	CodeReplaceFailed    ErrorCode = "replace_failed"
	CodeRestartFailed    ErrorCode = "restart_failed"
	CodeHealthFailed     ErrorCode = "health_failed"
	CodeInterrupted      ErrorCode = "interrupted"
	CodeJournalCorrupt   ErrorCode = "journal_corrupt"
)

var (
	states = []State{StateAccepted, StateApplying, StateSucceeded, StateFailed, StateInterrupted}
	phases = []Phase{PhaseValidate, PhaseBackup, PhaseReplace, PhaseRestart, PhaseCheck}
	codes  = []ErrorCode{
		CodeInvalidRequest, CodeStaleBase, CodeDuplicateID, CodeBusy, CodeConfigUnreadable, CodeConfigtestFailed,
		CodeBackupFailed, CodeReplaceFailed, CodeRestartFailed, CodeHealthFailed, CodeInterrupted, CodeJournalCorrupt,
	}
)

// Valid reports whether s is one of the five states.
func (s State) Valid() bool { return slices.Contains(states, s) }

// Terminal reports whether s is a final state (what result.json may carry).
func (s State) Terminal() bool {
	return s == StateSucceeded || s == StateFailed || s == StateInterrupted
}

// Valid reports whether p is a known phase.
func (p Phase) Valid() bool { return slices.Contains(phases, p) }

// Valid reports whether c is in the closed error-code list.
func (c ErrorCode) Valid() bool { return slices.Contains(codes, c) }

var (
	// ErrInvalidResult wraps every result.json validation failure.
	ErrInvalidResult = errors.New("invalid result")
	// ErrInvalidStatus wraps every status.json validation failure.
	ErrInvalidStatus = errors.New("invalid status")
	// ErrInvalidMarker wraps every request.ready validation failure.
	ErrInvalidMarker = errors.New("invalid marker")
)

// Result is results/result.json: the final outcome of one request. Only terminal states are
// published. Phase is empty when it is unknown (e.g. a lost journal); ErrorCode is empty exactly
// when the state is succeeded. ConfigChanged is nil when the helper does not know whether the live
// config changed, and that "unknown" is kept through encode and decode.
type Result struct {
	Version        int       `json:"version"`
	RequestID      string    `json:"request_id"`
	State          State     `json:"state"`
	Phase          Phase     `json:"phase"`
	FinishedAt     time.Time `json:"finished_at"`
	ErrorCode      ErrorCode `json:"error_code"`
	ConfigChanged  *bool     `json:"config_changed"`
	HealthVerified bool      `json:"health_verified"`
}

func (r Result) validate() error {
	invalid := func(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidResult, reason) }
	switch {
	case r.Version != Version:
		return invalid("unsupported version")
	case !ValidRequestID(r.RequestID):
		return invalid("bad request_id")
	case !r.State.Terminal():
		return invalid("state is not a final state")
	case r.Phase != "" && !r.Phase.Valid():
		return invalid("unknown phase")
	case r.ErrorCode != "" && !r.ErrorCode.Valid():
		return invalid("unknown error_code")
	case (r.State == StateSucceeded) != (r.ErrorCode == ""):
		return invalid("error_code must be set exactly when the state is not succeeded")
	case r.FinishedAt.IsZero():
		return invalid("finished_at is missing")
	}
	return nil
}

// EncodeResult validates r and returns its document. finished_at is written in UTC to the second.
func EncodeResult(r Result) ([]byte, error) {
	r.FinishedAt = r.FinishedAt.UTC().Truncate(time.Second)
	if err := r.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxResultBytes {
		return nil, fmt.Errorf("%w: document too large", ErrInvalidResult)
	}
	return b, nil
}

// DecodeResult strictly decodes and validates a result.json document.
func DecodeResult(b []byte) (Result, error) {
	r, err := decodeResult(b)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInvalidResult, err)
	}
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	return r, nil
}

func decodeResult(b []byte) (r Result, err error) {
	if len(b) > MaxResultBytes {
		return r, errors.New("document too large")
	}
	m, err := members(b, "version", "request_id", "state", "phase", "finished_at", "error_code", "config_changed", "health_verified")
	if err != nil {
		return r, err
	}
	var state, phase, code, finished string
	if r.Version, err = jsonInt(m["version"]); err != nil {
		return r, errors.New("version: " + err.Error())
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"request_id", &r.RequestID}, {"state", &state}, {"phase", &phase}, {"finished_at", &finished}, {"error_code", &code}} {
		if *f.dst, err = jsonString(m[f.key]); err != nil {
			return r, errors.New(f.key + ": " + err.Error())
		}
	}
	r.State, r.Phase, r.ErrorCode = State(state), Phase(phase), ErrorCode(code)
	if r.FinishedAt, err = time.Parse(time.RFC3339, finished); err != nil {
		return r, errors.New("finished_at: not an RFC 3339 time")
	}
	if string(m["config_changed"]) != "null" {
		v, err := jsonBool(m["config_changed"])
		if err != nil {
			return r, errors.New("config_changed: " + err.Error())
		}
		r.ConfigChanged = &v
	}
	if r.HealthVerified, err = jsonBool(m["health_verified"]); err != nil {
		return r, errors.New("health_verified: " + err.Error())
	}
	return r, nil
}

// Status is results/status.json: the helper's last request and the current secret-free config
// view. A helper that has not handled a request yet publishes empty RequestID, State and Phase.
// BaseRev always matches AllowedGroups, which is in canonical order and never null. When the
// helper could not read the live config, ConfigError is config_unreadable and AllowedGroups is
// null and BaseRev empty: an unreadable config is never published as an empty list.
type Status struct {
	Version       int       `json:"version"`
	RequestID     string    `json:"request_id"`
	State         State     `json:"state"`
	Phase         Phase     `json:"phase"`
	AllowedGroups []string  `json:"allowed_groups"`
	BaseRev       string    `json:"base_rev"`
	ConfigError   ErrorCode `json:"config_error"`
}

func (s Status) validate() error {
	invalid := func(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidStatus, reason) }
	if s.Version != Version {
		return invalid("unsupported version")
	}
	if s.RequestID == "" {
		if s.State != "" || s.Phase != "" {
			return invalid("state or phase without a request_id")
		}
	} else if !ValidRequestID(s.RequestID) {
		return invalid("bad request_id")
	} else if !s.State.Valid() {
		return invalid("unknown state")
	}
	if s.Phase != "" && !s.Phase.Valid() {
		return invalid("unknown phase")
	}
	switch s.ConfigError {
	case "":
	case CodeConfigUnreadable:
		if s.AllowedGroups != nil || s.BaseRev != "" {
			return invalid("config_error with a config view")
		}
		return nil
	default:
		return invalid("unknown config_error")
	}
	if s.AllowedGroups == nil {
		return invalid("allowed_groups is null")
	}
	norm, err := normalizeGroups(s.AllowedGroups)
	if err != nil {
		return invalid("allowed_groups: " + err.Error())
	}
	if !slices.Equal(norm, s.AllowedGroups) {
		return invalid("allowed_groups is not in canonical order")
	}
	if rev, _ := BaseRev(s.AllowedGroups); rev != s.BaseRev {
		return invalid("base_rev does not match allowed_groups")
	}
	return nil
}

// EncodeStatus validates s and returns its document; a nil AllowedGroups is written as `[]`,
// except with ConfigError, where it is `null`.
func EncodeStatus(s Status) ([]byte, error) {
	if s.AllowedGroups == nil && s.ConfigError == "" {
		s.AllowedGroups = []string{}
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxResultBytes {
		return nil, fmt.Errorf("%w: document too large", ErrInvalidStatus)
	}
	return b, nil
}

// DecodeStatus strictly decodes and validates a status.json document.
func DecodeStatus(b []byte) (Status, error) {
	s, err := decodeStatus(b)
	if err != nil {
		return Status{}, fmt.Errorf("%w: %w", ErrInvalidStatus, err)
	}
	if err := s.validate(); err != nil {
		return Status{}, err
	}
	return s, nil
}

func decodeStatus(b []byte) (s Status, err error) {
	if len(b) > MaxResultBytes {
		return s, errors.New("document too large")
	}
	m, err := members(b, "version", "request_id", "state", "phase", "allowed_groups", "base_rev", "config_error")
	if err != nil {
		return s, err
	}
	var state, phase, configErr string
	if s.Version, err = jsonInt(m["version"]); err != nil {
		return s, errors.New("version: " + err.Error())
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"request_id", &s.RequestID}, {"state", &state}, {"phase", &phase}, {"base_rev", &s.BaseRev}, {"config_error", &configErr}} {
		if *f.dst, err = jsonString(m[f.key]); err != nil {
			return s, errors.New(f.key + ": " + err.Error())
		}
	}
	s.State, s.Phase, s.ConfigError = State(state), Phase(phase), ErrorCode(configErr)
	if string(m["allowed_groups"]) != "null" {
		if json.Unmarshal(m["allowed_groups"], &s.AllowedGroups) != nil {
			return s, errors.New("allowed_groups must be a list of strings")
		}
	}
	return s, nil
}

// ParseMarker reads requests/request.ready: one lowercase UUID, optionally followed by a single
// newline, at most MaxMarkerBytes in all. It returns the UUID.
func ParseMarker(b []byte) (string, error) {
	if len(b) > MaxMarkerBytes {
		return "", fmt.Errorf("%w: too large", ErrInvalidMarker)
	}
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if !ValidRequestID(string(b)) {
		return "", fmt.Errorf("%w: not a lowercase UUID on one line", ErrInvalidMarker)
	}
	return string(b), nil
}

// FormatMarker returns the marker content for id.
func FormatMarker(id string) ([]byte, error) {
	if !ValidRequestID(id) {
		return nil, fmt.Errorf("%w: not a lowercase UUID", ErrInvalidMarker)
	}
	return []byte(id), nil
}
