package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
)

// The reader is one full read (F4-007): the narrow client (client.go) over the stored profile's
// namespaces, the runtime credential, and the snapshot store (snapshot.go). A snapshot is published
// only when every page of every resource was read; anything else records a failed attempt and leaves
// the last good snapshot as it is. Token expiry (401) is such a failure: it is neither a widening of
// access nor an empty inventory, and the operator renews the credential file by hand. Who calls Read
// and how often is the loop of F4-038, not this file.

// Failure classes recorded with a failed attempt.
const (
	ClassCredentialExpired  = "credential_expired" //nolint:gosec // G101: a label, not a secret; HTTP 401, the API no longer accepts the token
	ClassForbidden          = "forbidden"          // HTTP 403
	ClassHTTP               = "http_error"         // any other HTTP status
	ClassTimeout            = "timeout"
	ClassCanceled           = "canceled"
	ClassDecode             = "decode"
	ClassTLS                = "tls"
	ClassConnect            = "connect"
	ClassDenied             = "address_denied"      // the API address policy refused the connection
	ClassCredential         = "credential"          // not set or not readable
	ClassCredentialMismatch = "credential_mismatch" //nolint:gosec // G101: a label, not a secret
	ClassRead               = "read_failed"
)

// ProfileSource and CredentialSource are the parts of *ProfileStore and *CredentialStore the reader
// uses.
type ProfileSource interface {
	Get(ctx context.Context) (Profile, error)
}

type CredentialSource interface {
	Load() (Credential, error)
}

// inventoryClient is the read surface of *Client.
type inventoryClient interface {
	ListIngresses(ctx context.Context, namespace string) ([]Ingress, error)
	ListServices(ctx context.Context, namespace string) ([]Service, error)
	ListIngressClasses(ctx context.Context) ([]IngressClass, error)
	Close()
}

// FailedReadError is a read that did not publish a snapshot. Class and Message are what was recorded
// as the attempt; neither carries the token, a URL or a response body. Unwrap exposes the sanitized
// cause (a *ReadError, a context error, ErrCredentialNotSet...).
type FailedReadError struct {
	Class   string
	Message string
	Err     error
}

func (e *FailedReadError) Error() string {
	return fmt.Sprintf("k8s: full read failed (%s): %s", e.Class, e.Message)
}

func (e *FailedReadError) Unwrap() error { return e.Err }

// Reader performs full reads one at a time.
type Reader struct {
	profiles  ProfileSource
	creds     CredentialSource
	snaps     *SnapshotStore
	newClient func(Credential) (inventoryClient, error)
	now       func() time.Time
	mu        sync.Mutex
}

// NewReader returns the production reader: the narrow client behind the API address policy. A nil
// now uses time.Now.
func NewReader(profiles *ProfileStore, creds *CredentialStore, snaps *SnapshotStore, policy *netpolicy.Store, now func() time.Time) *Reader {
	return NewReaderWithGuard(profiles, creds, snaps, netpolicy.NewGuard(policy, nil, nil), now)
}

// NewReaderWithGuard is NewReader over an explicit guard (see NewClientWithGuard).
func NewReaderWithGuard(profiles *ProfileStore, creds *CredentialStore, snaps *SnapshotStore, guard *netpolicy.Guard, now func() time.Time) *Reader {
	return newReader(profiles, creds, snaps, func(c Credential) (inventoryClient, error) {
		return NewClientWithGuard(c, guard)
	}, now)
}

func newReader(profiles ProfileSource, creds CredentialSource, snaps *SnapshotStore, newClient func(Credential) (inventoryClient, error), now func() time.Time) *Reader {
	if now == nil {
		now = time.Now
	}
	return &Reader{profiles: profiles, creds: creds, snaps: snaps, newClient: newClient, now: now}
}

// pairOf is the snapshot identity of a canonical profile: the sorted namespaces as the scope, and a
// digest of what else decides which objects are read from where. Listeners and the declared token
// expiry do not change what is read, so they do not change the pair.
func pairOf(p Profile) snapshotPair {
	ident, _ := json.Marshal([]any{p.Endpoint, p.TLSServerName, p.Controller, p.IngressClasses, p.Namespaces})
	sum := sha256.Sum256(ident)
	return snapshotPair{
		Scope:   strings.Join(slices.Sorted(slices.Values(p.Namespaces)), ","),
		Version: hex.EncodeToString(sum[:16]),
	}
}

// State is what the UI shows for the stored profile: the last good snapshot with its observation
// time, whether it is stale, the last attempt, and old-scope data while the new scope has no snapshot.
func (r *Reader) State(ctx context.Context) (State, error) {
	p, err := r.profiles.Get(ctx)
	if err != nil {
		return State{}, err
	}
	return r.snaps.State(ctx, pairOf(p))
}

// Read reads every selected resource completely and publishes one snapshot. On any failure it records
// a failed attempt for the profile's scope and returns a *FailedReadError; the previous snapshot is
// untouched. Without a readable profile there is no scope to attribute an attempt to: the profile
// error is returned and nothing is read.
func (r *Reader) Read(ctx context.Context) (Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, err := r.profiles.Get(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	pair := pairOf(p)
	at := r.now()

	fail := func(class, message string, cause error) (Snapshot, error) {
		fe := &FailedReadError{Class: class, Message: message, Err: cause}
		// The attempt is recorded even if the caller's context is already done.
		if err := r.snaps.RecordFailure(context.WithoutCancel(ctx), pair, at, class, message); err != nil {
			return Snapshot{}, errors.Join(fe, err)
		}
		return Snapshot{}, fe
	}

	cred, err := r.creds.Load()
	if err != nil {
		return fail(ClassCredential, credentialMessage(err), err)
	}
	// The profile is the authority: the token only goes where the profile says.
	if checkCredential(p, cred) != nil {
		return fail(ClassCredentialMismatch, "the credential's endpoint or TLS server name differs from the profile", nil)
	}
	cl, err := r.newClient(cred)
	if err != nil {
		return fail(ClassCredential, "the credential could not be used", nil)
	}
	defer cl.Close()

	inv, err := readInventory(ctx, cl, p.Namespaces)
	if err != nil {
		class, message := classifyRead(err)
		return fail(class, message, err)
	}
	snap, err := r.snaps.Publish(ctx, pair, at, inv)
	if err != nil {
		return fail(ClassRead, "the snapshot could not be stored", err)
	}
	return snap, nil
}

// readInventory reads everything or returns an error; a partial inventory is never returned.
func readInventory(ctx context.Context, cl inventoryClient, namespaces []string) (Inventory, error) {
	inv := Inventory{Ingresses: []Ingress{}, Services: []Service{}, IngressClasses: []IngressClass{}}
	for _, ns := range namespaces {
		ings, err := cl.ListIngresses(ctx, ns)
		if err != nil {
			return Inventory{}, err
		}
		inv.Ingresses = append(inv.Ingresses, ings...)
		svcs, err := cl.ListServices(ctx, ns)
		if err != nil {
			return Inventory{}, err
		}
		inv.Services = append(inv.Services, svcs...)
	}
	classes, err := cl.ListIngressClasses(ctx)
	if err != nil {
		return Inventory{}, err
	}
	inv.IngressClasses = classes

	// Deterministic payload: the same cluster state always stores the same bytes.
	slices.SortStableFunc(inv.Ingresses, func(a, b Ingress) int { return compareMeta(a.Metadata, b.Metadata) })
	slices.SortStableFunc(inv.Services, func(a, b Service) int { return compareMeta(a.Metadata, b.Metadata) })
	slices.SortStableFunc(inv.IngressClasses, func(a, b IngressClass) int { return compareMeta(a.Metadata, b.Metadata) })
	return inv, nil
}

func compareMeta(a, b ObjectMeta) int {
	if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
		return c
	}
	return strings.Compare(a.Name, b.Name)
}

// classifyRead maps a failed list read to its recorded class and message. The message is the
// client's own sanitized text, or a fixed one.
func classifyRead(err error) (class, message string) {
	var re *ReadError
	if errors.As(err, &re) {
		message = re.Error()
	} else {
		message = "reading the inventory failed"
	}
	switch {
	case re != nil && re.Status == 401:
		return ClassCredentialExpired, message
	case re != nil && re.Status == 403:
		return ClassForbidden, message
	case errors.Is(err, errTimeout):
		return ClassTimeout, message
	case errors.Is(err, errCanceled):
		return ClassCanceled, message
	case errors.Is(err, errDenied):
		return ClassDenied, message
	case errors.Is(err, errTLS):
		return ClassTLS, message
	case errors.Is(err, errConnect):
		return ClassConnect, message
	case errors.Is(err, errBadJSON), errors.Is(err, errTrailingData), errors.Is(err, errWrongKind), errors.Is(err, errNoItems):
		return ClassDecode, message
	case re != nil && re.Status != 0:
		return ClassHTTP, message
	}
	return ClassRead, message
}

func credentialMessage(err error) string {
	if errors.Is(err, ErrCredentialNotSet) {
		return "no credential is set"
	}
	return "the stored credential is not usable"
}
