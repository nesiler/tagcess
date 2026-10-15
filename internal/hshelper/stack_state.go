package hshelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/stack"
)

const (
	stackJournalName = "stack-journal.json"
	stackRequestName = "stack-request.json"
	stackStateName   = "stack-state.json"
	maxStackState    = 64 << 10
)

// stackState is what the helper applied: the typed settings and the image of every enabled component. It holds no
// secret, so base_rev can hash it.
type stackState struct {
	Version int                             `json:"version"`
	Params  stack.Params                    `json:"params"`
	Images  map[stack.Component]stack.Image `json:"images"`
}

func newStackState() stackState {
	return stackState{Version: StackVersion, Images: map[stack.Component]stack.Image{}}
}

func (s stackState) enabled(c stack.Component) bool { return slices.Contains(s.Params.Components, c) }

// rev is the stack revision: SHA-256 of the canonical secret-free projection (enabled components with their
// images, and the settings).
func (s stackState) rev() string {
	type comp struct {
		Name  stack.Component `json:"name"`
		Image string          `json:"image"`
	}
	comps := []comp{}
	for _, c := range stack.AllComponents() {
		if s.enabled(c) {
			comps = append(comps, comp{c, s.Images[c].Ref()})
		}
	}
	settings := s.Params
	settings.Components = nil
	b, _ := json.Marshal(struct {
		Components []comp       `json:"components"`
		Settings   stack.Params `json:"settings"`
	}{comps, settings})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readStackState(priv string) (stackState, error) {
	f, err := os.Open(filepath.Join(priv, stackStateName)) //nolint:gosec // root-owned private dir
	if errors.Is(err, os.ErrNotExist) {
		return newStackState(), nil
	}
	if err != nil {
		return stackState{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxStackState+1))
	if err != nil || len(b) > maxStackState {
		return stackState{}, errors.New("stack state unreadable")
	}
	s := newStackState()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.Version != StackVersion {
		return stackState{}, errors.New("stack state corrupt")
	}
	return s, nil
}

func writeStackState(priv string, s stackState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicWrite(priv, stackStateName, b, 0o600)
}

// stackJournal is the one record of the current or last stack request. IDs, states and codes only.
type stackJournal struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	Op        StackOp         `json:"op"`
	State     hostpatch.State `json:"state"`
	Phase     StackPhase      `json:"phase"`
	ErrorCode StackCode       `json:"error_code"`
}

func (j stackJournal) validate() error {
	switch {
	case j.Version != StackVersion:
		return errors.New("unsupported version")
	case !hostpatch.ValidRequestID(j.RequestID):
		return errors.New("bad request_id")
	case j.Op != "" && !j.Op.valid():
		return errors.New("unknown operation")
	case !j.State.Valid():
		return errors.New("unknown state")
	case j.Phase != "" && !slices.Contains(stackPhases, j.Phase):
		return errors.New("unknown phase")
	case j.ErrorCode != "" && !slices.Contains(stackCodes, j.ErrorCode):
		return errors.New("unknown error_code")
	}
	return nil
}

// readStackJournal returns (zero, false, nil) when there is none; anything untrustworthy is ErrJournalCorrupt.
func readStackJournal(priv string) (stackJournal, bool, error) {
	f, err := os.Open(filepath.Join(priv, stackJournalName)) //nolint:gosec // root-owned private dir
	if errors.Is(err, os.ErrNotExist) {
		return stackJournal{}, false, nil
	}
	if err != nil {
		return stackJournal{}, false, fmt.Errorf("open stack journal: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxJournal+1))
	if err != nil {
		return stackJournal{}, false, fmt.Errorf("read stack journal: %w", err)
	}
	var j stackJournal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if len(b) > maxJournal || dec.Decode(&j) != nil {
		return stackJournal{}, false, fmt.Errorf("%w: not a stack journal document", ErrJournalCorrupt)
	}
	if _, err := dec.Token(); err != io.EOF {
		return stackJournal{}, false, fmt.Errorf("%w: data after the document", ErrJournalCorrupt)
	}
	if err := j.validate(); err != nil {
		return stackJournal{}, false, fmt.Errorf("%w: %w", ErrJournalCorrupt, err)
	}
	return j, true, nil
}

func writeStackJournal(priv string, j stackJournal) error {
	if err := j.validate(); err != nil {
		return fmt.Errorf("stack journal: %w", err)
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return atomicWrite(priv, stackJournalName, b, 0o600)
}

func writeStackResult(resultsDir string, r StackResult) error {
	b, err := encodeStackResult(r)
	if err != nil {
		return err
	}
	return atomicWrite(resultsDir, resultName, b, 0o644)
}

// readStackResultID returns the request ID of the published result.json, or "".
func readStackResultID(resultsDir string) string {
	f, err := os.Open(filepath.Join(resultsDir, resultName)) //nolint:gosec // root-owned results dir
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, hostpatch.MaxResultBytes+1))
	if err != nil {
		return ""
	}
	var r struct {
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(b, &r) != nil || !hostpatch.ValidRequestID(r.RequestID) {
		return ""
	}
	return r.RequestID
}

// StackStatus is results/status.json of the stack channel: the stack revision, the last request and, per
// component, the image running and the one in the helper's manifest. No secret, no settings value.
type StackStatus struct {
	Version    int              `json:"version"`
	RequestID  string           `json:"request_id"`
	State      hostpatch.State  `json:"state"`
	Phase      StackPhase       `json:"phase"`
	BaseRev    string           `json:"base_rev"`
	Release    string           `json:"release"`
	Components []StackComponent `json:"components"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// StackComponent is one component's row of StackStatus.
type StackComponent struct {
	Name     stack.Component `json:"name"`
	Enabled  bool            `json:"enabled"`
	Running  string          `json:"running"`
	Manifest string          `json:"manifest"`
}

// PublishStackStatus writes results/status.json. It runs under the lock at the end of every mode. If the state
// or journal cannot be read nothing is written, so the last status stays.
func PublishStackStatus(cfg StackConfig) error {
	priv := filepath.Join(cfg.Root, privateDir)
	st, err := readStackState(priv)
	if err != nil {
		return err
	}
	j, found, err := readStackJournal(priv)
	if err != nil {
		return err
	}
	s := StackStatus{Version: StackVersion, BaseRev: st.rev(), Release: cfg.Manifest.Release, UpdatedAt: cfg.now().UTC().Truncate(time.Second), Components: []StackComponent{}}
	if found {
		s.RequestID, s.State, s.Phase = j.RequestID, j.State, j.Phase
	}
	for _, c := range stack.AllComponents() {
		row := StackComponent{Name: c, Enabled: st.enabled(c), Manifest: cfg.Manifest.Images[c].Ref()}
		if row.Enabled {
			row.Running = st.Images[c].Ref()
		}
		s.Components = append(s.Components, row)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(cfg.Root, resultsDir), statusName, b, 0o644)
}
