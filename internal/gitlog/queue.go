package gitlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// fileQueue is the default Queue: one JSON object per line in a file, appended in order. It is
// durable (each write is flushed to disk) and survives a restart; Complete rewrites the file so a
// drained intent is not retried again. Access is serialized in-process, matching tagcess's single
// writer.
type fileQueue struct {
	mu   sync.Mutex
	path string
	// quarantined are the reasons of lines read() set aside since the last TakeQuarantined.
	quarantined []string
}

// NewFileQueue returns a queue stored at path, creating its directory if needed.
func NewFileQueue(path string) (Queue, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("gitlog: queue path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("gitlog: create queue dir: %w", err)
	}
	return &fileQueue{path: path}, nil
}

func (q *fileQueue) Enqueue(_ context.Context, r Retry) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	pending, err := q.read()
	if err != nil {
		return 0, err
	}
	var next int64
	for _, p := range pending {
		if p.ID >= next {
			next = p.ID + 1
		}
	}
	r.ID = next
	line, err := json.Marshal(r)
	if err != nil {
		return 0, fmt.Errorf("gitlog: encode retry: %w", err)
	}
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, fmt.Errorf("gitlog: open retry queue: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return 0, fmt.Errorf("gitlog: append retry: %w", err)
	}
	if err := f.Sync(); err != nil {
		return 0, fmt.Errorf("gitlog: flush retry queue: %w", err)
	}
	return r.ID, nil
}

// TakeQuarantined returns, and forgets, why lines were set aside since the last call. The Log
// reports them (audit + alert); the raw lines are kept in <queue>.corrupt.
func (q *fileQueue) TakeQuarantined() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.quarantined
	q.quarantined = nil
	return out
}

func (q *fileQueue) Pending(context.Context) ([]Retry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.read()
}

func (q *fileQueue) Complete(_ context.Context, id int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	pending, err := q.read()
	if err != nil {
		return err
	}
	kept := make([]Retry, 0, len(pending))
	for _, r := range pending {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(pending) {
		return nil
	}
	return q.rewrite(kept)
}

// rewrite replaces the queue file with kept (removing it when kept is empty), atomically.
func (q *fileQueue) rewrite(kept []Retry) error {
	if len(kept) == 0 {
		if err := os.Remove(q.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("gitlog: clear retry queue: %w", err)
		}
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(q.path), ".retry-*")
	if err != nil {
		return fmt.Errorf("gitlog: rewrite retry queue: %w", err)
	}
	tmpName := tmp.Name()
	for _, r := range kept {
		line, err := json.Marshal(r)
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return fmt.Errorf("gitlog: encode retry: %w", err)
		}
		if _, err := tmp.Write(append(line, '\n')); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return fmt.Errorf("gitlog: rewrite retry queue: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: flush retry queue: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: rewrite retry queue: %w", err)
	}
	if err := os.Rename(tmpName, q.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("gitlog: replace retry queue: %w", err)
	}
	return nil
}

func (q *fileQueue) read() ([]Retry, error) {
	data, err := os.ReadFile(q.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gitlog: open retry queue: %w", err)
	}
	var out []Retry
	var corrupt [][]byte
	consumed := 0 // bytes of complete, newline-terminated records
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			break // a record without its newline: a torn append, not yet durable
		}
		line := data[:nl]
		consumed += nl + 1
		data = data[nl+1:]
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r Retry
		if err := json.Unmarshal(line, &r); err != nil {
			// One unreadable line must not stop every later commit for good: it is set aside below
			// and the intents around it keep their order.
			corrupt = append(corrupt, append([]byte(nil), line...))
			q.quarantined = append(q.quarantined, "unparsable retry queue line: "+err.Error())
			continue
		}
		out = append(out, r)
	}
	if len(corrupt) > 0 {
		if err := q.setAside(corrupt, out); err != nil {
			return nil, err
		}
		return out, nil
	}
	// A crash mid-append can leave a partial trailing record (no newline). Drop it so the queue
	// keeps working and later intents are not lost (MEDIUM 5).
	if len(data) > 0 {
		if err := os.Truncate(q.path, int64(consumed)); err != nil {
			return nil, fmt.Errorf("gitlog: truncate retry queue: %w", err)
		}
	}
	return out, nil
}

// setAside keeps the unparsable lines in <queue>.corrupt for the operator and rewrites the queue
// with the intents that did parse, in their original order.
func (q *fileQueue) setAside(corrupt [][]byte, good []Retry) error {
	f, err := os.OpenFile(q.path+".corrupt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("gitlog: open corrupt retry lines: %w", err)
	}
	for _, line := range corrupt {
		if _, err := f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			return fmt.Errorf("gitlog: keep corrupt retry line: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("gitlog: keep corrupt retry lines: %w", err)
	}
	return q.rewrite(good)
}
