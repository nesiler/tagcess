package site

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/store/db"
)

// SettingManualDNS is the settings key of the manual MagicDNS records (H-06): the extra-records
// that are not derived from a site. The first import writes it (F2-022); every DNS render reads it
// so those records are never dropped from the file. The value is a JSON array of dns.Record.
const SettingManualDNS = "site.manual_dns"

// ManualDNS returns the stored manual records. No stored value means none. A stored value that
// does not parse or holds a record tagcess could not have written is an error, never an empty
// set: rendering without it would silently drop live records.
func (s *Store) ManualDNS(ctx context.Context) ([]dns.Record, error) {
	v, err := s.q.GetSetting(ctx, SettingManualDNS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("site: read setting %s: %w", SettingManualDNS, err)
	}
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	recs, err := dns.Unmarshal([]byte(v))
	if err != nil {
		return nil, fmt.Errorf("site: setting %s: %w", SettingManualDNS, err)
	}
	return recs, nil
}

// SetManualDNS replaces the stored manual records with the sorted set. Every record is validated
// first: an invalid one is refused and the stored value stays as it was.
func (s *Store) SetManualDNS(ctx context.Context, recs []dns.Record) error {
	for i, r := range recs {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("site: manual dns record %d: %w", i, err)
		}
	}
	sorted := append([]dns.Record{}, recs...)
	dns.Sort(sorted)
	body, err := json.Marshal(sorted)
	if err != nil {
		return fmt.Errorf("site: marshal manual dns records: %w", err)
	}
	err = s.q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: SettingManualDNS, Value: string(body), UpdatedAt: time.Now().UTC().Format(timeFormat),
	})
	if err != nil {
		return fmt.Errorf("site: write setting %s: %w", SettingManualDNS, err)
	}
	return nil
}
