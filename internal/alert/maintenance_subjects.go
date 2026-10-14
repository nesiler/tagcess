package alert

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// MaintenanceSubjects lists the sites whose monitoring maintenance is on, sorted. It reads the
// persistent preference, so a site stays listed after its alerts have resolved.
func (s *Service) MaintenanceSubjects(ctx context.Context) ([]string, error) {
	var out []string
	err := s.store.withTx(ctx, func(t *tx) error {
		rows, err := t.q.ListSettings(ctx)
		if err != nil {
			return fmt.Errorf("alert: list settings: %w", err)
		}
		for _, r := range rows {
			if subject, ok := strings.CutPrefix(r.Key, maintenanceKeyPrefix); ok && subject != "" && (r.Value == "1" || r.Value == "true") {
				out = append(out, subject)
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}
