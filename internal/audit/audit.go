// Package audit is tagcess's change log (A-01, security.md 9). Every change is written with its
// actor, time, event, target, a masked diff and the result. The log is append-only: this package
// only inserts and reads, and the SQL layer defines no mutating statement for the table.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Mask replaces the value of a field marked secret. It is the only thing ever written for such a
// value (security.md 7).
const Mask = "***"

// Change is one field of a diff. Before and After hold the values. Secret marks a value that must
// never reach the database; it is masked on write.
type Change struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	Secret bool   `json:"secret,omitempty"`
}

// Diff is the ordered list of field changes recorded with an event. It is stored as JSON.
type Diff []Change

// Masked returns a copy with every secret value replaced by Mask. The receiver is not modified.
func (d Diff) Masked() Diff {
	out := make(Diff, len(d))
	copy(out, d)
	for i := range out {
		if out[i].Secret {
			out[i].Before = Mask
			out[i].After = Mask
		}
	}
	return out
}

// marshal serializes the masked diff for storage. A nil diff stores as an empty string.
func (d Diff) marshal() (string, error) {
	if len(d) == 0 {
		return "", nil
	}
	body, err := json.Marshal(d.Masked())
	if err != nil {
		return "", fmt.Errorf("audit: marshal diff: %w", err)
	}
	return string(body), nil
}

// unmarshalDiff parses a stored diff. An empty string means "no diff".
func unmarshalDiff(stored string) (Diff, error) {
	if stored == "" {
		return nil, nil
	}
	var d Diff
	if err := json.Unmarshal([]byte(stored), &d); err != nil {
		return nil, fmt.Errorf("audit: unmarshal diff: %w", err)
	}
	return d, nil
}

// Entry is an event as a caller submits it. The time is set by the logger.
type Entry struct {
	Actor  string
	Event  string
	Target string
	Diff   Diff
	Result string
}

// Event is a stored audit event.
type Event struct {
	ID     int64
	At     time.Time
	Actor  string
	Event  string
	Target string
	Diff   Diff
	Result string
}

// ErrNoActor is returned when an event has no actor (A-01.1: every record says who).
var ErrNoActor = errors.New("audit: actor is required")

// timeFormat stores the timestamp with fixed-width milliseconds. Unlike time.RFC3339Nano, the
// field width is constant, so the text sorts chronologically in SQLite. It matches the
// strftime('%Y-%m-%dT%H:%M:%fZ') form the migration seeds use.
const timeFormat = "2006-01-02T15:04:05.000Z"

// Recorder is the append-only storage the logger writes to and reads back from. It is satisfied by
// *db.Queries.
type Recorder interface {
	InsertAuditEvent(ctx context.Context, arg db.InsertAuditEventParams) (db.AuditEvent, error)
	GetAuditEvent(ctx context.Context, id int64) (db.AuditEvent, error)
	ListAuditEvents(ctx context.Context, arg db.ListAuditEventsParams) ([]db.AuditEvent, error)
}

// Logger writes audit events.
type Logger struct {
	rec   Recorder
	clock func() time.Time
}

// New returns a logger writing to rec.
func New(rec Recorder) *Logger {
	return &Logger{rec: rec, clock: time.Now}
}

// Write validates and stores an event, returning the stored row. The diff is masked before it is
// serialized. An empty or whitespace-only actor is refused.
func (l *Logger) Write(ctx context.Context, e Entry) (Event, error) {
	actor := strings.TrimSpace(e.Actor)
	if actor == "" {
		return Event{}, ErrNoActor
	}
	diff, err := e.Diff.marshal()
	if err != nil {
		return Event{}, err
	}
	at := l.clock().UTC()
	row, err := l.rec.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		At:     at.Format(timeFormat),
		Actor:  actor,
		Event:  e.Event,
		Target: e.Target,
		Diff:   diff,
		Result: e.Result,
	})
	if err != nil {
		return Event{}, fmt.Errorf("audit: insert %s: %w", e.Event, err)
	}
	return fromRow(row)
}

// Get reads one stored event by id.
func (l *Logger) Get(ctx context.Context, id int64) (Event, error) {
	row, err := l.rec.GetAuditEvent(ctx, id)
	if err != nil {
		return Event{}, fmt.Errorf("audit: get %d: %w", id, err)
	}
	return fromRow(row)
}

// ErrInvalidFilter is returned when a list request has a non-positive limit. SQLite treats a negative
// LIMIT as "no limit", so refusing it keeps a listing request from accidentally reading the whole
// table.
var ErrInvalidFilter = errors.New("audit: limit must be positive")

// Filter selects which events List returns. Actor and Event are exact matches; an empty value matches
// every row. Offset and Limit page the result, which is always newest first. Limit must be positive.
type Filter struct {
	Actor  string
	Event  string
	Offset int
	Limit  int
}

// List returns the events matching f, newest first. An empty Actor or Event is not filtered. It is
// read-only: the package exposes no way to change or delete a stored event (A-01.2).
func (l *Logger) List(ctx context.Context, f Filter) ([]Event, error) {
	if f.Limit < 1 {
		return nil, ErrInvalidFilter
	}
	rows, err := l.rec.ListAuditEvents(ctx, db.ListAuditEventsParams{
		Actor:  nullString(f.Actor),
		Event:  nullString(f.Event),
		Offset: int64(f.Offset),
		Limit:  int64(f.Limit),
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	events := make([]Event, 0, len(rows))
	for _, row := range rows {
		e, err := fromRow(row)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

// nullString turns an empty filter value into SQL NULL, which the query's COALESCE treats as
// "match anything".
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func fromRow(row db.AuditEvent) (Event, error) {
	at, err := time.Parse(timeFormat, row.At)
	if err != nil {
		return Event{}, fmt.Errorf("audit: parse time %q: %w", row.At, err)
	}
	diff, err := unmarshalDiff(row.Diff)
	if err != nil {
		return Event{}, err
	}
	return Event{
		ID:     row.ID,
		At:     at,
		Actor:  row.Actor,
		Event:  row.Event,
		Target: row.Target,
		Diff:   diff,
		Result: row.Result,
	}, nil
}
