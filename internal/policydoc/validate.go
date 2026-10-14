package policydoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/headscale"
)

// MaxSize is the largest policy text accepted (1 MiB).
const MaxSize = 1 << 20

// Checker is Headscale's CheckPolicy; *headscale.Client satisfies it.
type Checker interface {
	CheckPolicy(ctx context.Context, policy string) error
}

// Stage is one validation layer, in running order.
type Stage string

const (
	StageInput     Stage = "input"     // size and UTF-8
	StageSyntax    Stage = "syntax"    // HuJSON
	StageStructure Stage = "structure" // local structure rules
	StageLocked    Stage = "locked"    // locked mandatory tests present and canonical
	StageCheck     Stage = "check"     // Headscale CheckPolicy
)

var stageOrder = []Stage{StageInput, StageSyntax, StageStructure, StageLocked, StageCheck}

// State is the outcome of one stage.
type State string

const (
	StatePass       State = "pass"
	StateFail       State = "fail"       // the document is wrong (for StageCheck: Headscale rejected it)
	StateUnverified State = "unverified" // StageCheck only: Headscale could not be asked
	StateSkipped    State = "skipped"    // an earlier stage failed
)

// StageResult is one stage's outcome. Line and Column (1-based, bytes) are set only when the
// parser gave an exact position; they are never guessed.
type StageResult struct {
	Stage   Stage
	State   State
	Message string
	Line    int
	Column  int
}

// Report is the layered result for one text, bound to it by Hash.
type Report struct {
	Hash   string
	Stages []StageResult
	// Locked is set when CheckPolicy rejected the document because a locked test failed.
	Locked *LockedTestError
}

// Valid reports whether every stage passed. Only then may the text be saved.
func (r Report) Valid() bool {
	for _, s := range r.Stages {
		if s.State != StatePass {
			return false
		}
	}
	return len(r.Stages) == len(stageOrder)
}

// Unverified reports that Headscale could not be asked: neither valid nor rejected.
func (r Report) Unverified() bool { return r.Stage(StageCheck).State == StateUnverified }

// Stage returns one stage's result; a stage not in the report counts as skipped.
func (r Report) Stage(s Stage) StageResult {
	for _, st := range r.Stages {
		if st.Stage == s {
			return st
		}
	}
	return StageResult{Stage: s, State: StateSkipped}
}

// Matches reports whether the report was produced for exactly this text.
func (r Report) Matches(text string) bool { return r.Hash != "" && r.Hash == hashText(text) }

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

var positionRE = regexp.MustCompile(`^hujson: line (\d+), column (\d+): (.*)$`)

// Validate runs the layers over text, stopping at the first failure; later stages are reported
// as skipped. It does not change the text: a document without the current locked tests fails the
// locked stage (the writer runs Inject first). A CheckPolicy error that is not a Headscale
// rejection (timeout, unreachable) leaves the report unverified, never valid.
func Validate(ctx context.Context, text string, cfg LockedConfig, c Checker) Report {
	rep := Report{Hash: hashText(text)}
	var obj *hujson.Object

	run := map[Stage]func() StageResult{
		StageInput: func() StageResult {
			switch {
			case strings.TrimSpace(text) == "":
				return fail("the policy is empty")
			case len(text) > MaxSize:
				return fail(fmt.Sprintf("the policy is larger than %d bytes", MaxSize))
			case !utf8.ValidString(text):
				return fail("the policy is not valid UTF-8")
			}
			return StageResult{State: StatePass}
		},
		StageSyntax: func() StageResult {
			root, err := hujson.Parse([]byte(text))
			if err != nil {
				return syntaxFailure(err)
			}
			obj, _ = root.Value.(*hujson.Object) // a non-object root is reported by the structure stage
			return StageResult{State: StatePass}
		},
		StageStructure: func() StageResult {
			if obj == nil {
				return fail("the policy root must be a JSON object")
			}
			if err := checkStructure(obj); err != nil {
				return fail(err.Error())
			}
			return StageResult{State: StatePass}
		},
		StageLocked: func() StageResult {
			changes, err := reconcileLocked(obj, cfg)
			if err != nil {
				return fail(err.Error())
			}
			if len(changes) > 0 {
				names := make([]string, 0, len(changes))
				for _, ch := range changes {
					if ch.Rule != "" {
						names = append(names, ch.Rule)
					}
				}
				return fail("locked tests are missing or changed: " + strings.Join(names, ", "))
			}
			return StageResult{State: StatePass}
		},
		StageCheck: func() StageResult {
			err := c.CheckPolicy(ctx, text)
			if err == nil {
				return StageResult{State: StatePass}
			}
			err = ClassifyCheckError(cfg, err)
			var le *LockedTestError
			if errors.As(err, &le) {
				rep.Locked = le
				return fail(le.Error())
			}
			var pe *headscale.PolicyError
			if errors.As(err, &pe) {
				return fail(pe.Message)
			}
			return StageResult{State: StateUnverified, Message: err.Error()}
		},
	}

	failed := false
	for _, s := range stageOrder {
		if failed {
			rep.Stages = append(rep.Stages, StageResult{Stage: s, State: StateSkipped})
			continue
		}
		res := run[s]()
		res.Stage = s
		rep.Stages = append(rep.Stages, res)
		failed = res.State != StatePass
	}
	return rep
}

func fail(msg string) StageResult { return StageResult{State: StateFail, Message: msg} }

// syntaxFailure turns a hujson parse error into a result. The parser's message carries the exact
// line and byte column of the offending character; when it does not, only the message is given.
func syntaxFailure(err error) StageResult {
	m := positionRE.FindStringSubmatch(err.Error())
	if m == nil {
		return fail(err.Error())
	}
	line, _ := strconv.Atoi(m[1])
	col, _ := strconv.Atoi(m[2])
	return StageResult{State: StateFail, Message: m[3], Line: line, Column: col}
}

// checkStructure applies the local rules: known top-level sections, no duplicates, and an acls or
// grants array so the document cannot mean allow-all (R2 B-02).
func checkStructure(obj *hujson.Object) error {
	seen := map[string]bool{}
	for _, m := range obj.Members {
		name, ok := literalString(m.Name)
		if !ok {
			return errors.New("a top-level member name is not a string")
		}
		if isMetadata(name) {
			continue
		}
		known := slices.ContainsFunc(topFields, func(f string) bool { return strings.EqualFold(f, name) })
		if !known {
			return fmt.Errorf("unknown top-level field %q", name)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return fmt.Errorf("duplicate top-level field %q", name)
		}
		seen[key] = true
	}
	hasList := false
	for _, key := range []string{aclsKey, grantsKey} {
		if idx := memberIndexes(obj, key); len(idx) == 1 {
			if _, ok := obj.Members[idx[0]].Value.Value.(*hujson.Array); !ok {
				return fmt.Errorf("%s must be an array", key)
			}
			hasList = true
		}
	}
	if !hasList {
		return errors.New(`the policy has neither "acls" nor "grants": Headscale treats that as allow-all ` +
			`(use "grants": [] for deny-all)`)
	}
	return nil
}
