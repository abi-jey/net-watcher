package database

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// HostTotal is a ranked address/name and its retained observation totals.
type HostTotal struct {
	Host       string `json:"host"`
	EventCount int64  `json:"eventCount"`
	ByteCount  int64  `json:"byteCount"`
	Total      int64  `json:"-"`
}

// TrafficBucket holds observed traffic for one UTC-aligned chart interval.
type TrafficBucket struct {
	Hour       int64
	EventCount int64
	BytesIn    int64
	BytesOut   int64
}

func bucketSQL(value string, seconds int64) string {
	// Unlike integer division, this also rounds timestamps before 1970 down.
	return fmt.Sprintf("(%s - ((%s %% %d + %d) %% %d))", value, value, seconds, seconds, seconds)
}

// summarySource combines complete summary hours with raw boundary fragments.
// During backfill, only IDs not yet summarized contribute raw interior rows.
func summarySource(tx *gorm.DB, kind string, start, end time.Time, seconds int64) (string, []interface{}, error) {
	status, err := SummaryStatus(tx)
	if err != nil {
		return "", nil, err
	}
	column := ""
	switch kind {
	case "":
	case "srcIP":
		column = "src_ip"
	case "dstIP":
		column = "dst_ip"
	case "hostname":
		column = "hostname"
	default:
		return "", nil, fmt.Errorf("unsupported host dimension %q", kind)
	}
	hour := bucketSQL("CAST(strftime('%s', timestamp) AS INTEGER)", seconds)
	raw := "SELECT " + hour + " AS hour, event_type, 1 AS event_count, COALESCE(byte_count, 0) AS byte_count FROM network_events WHERE 1=1"
	summary := "SELECT hour, event_type, event_count, byte_count FROM hourly_events WHERE 1=1"
	var summaryArgs []interface{}
	if column != "" {
		raw = "SELECT " + hour + " AS hour, " + column + " AS host, 1 AS event_count, COALESCE(byte_count, 0) AS byte_count FROM network_events WHERE " + column + " != ''"
		summary = "SELECT hour, host, event_count, byte_count FROM hourly_hosts WHERE kind = ?"
		summaryArgs = append(summaryArgs, kind)
	}
	rawBase := raw
	var rawArgs []interface{}
	if !start.IsZero() {
		raw += " AND timestamp >= ?"
		rawArgs = append(rawArgs, start.UTC())
	}
	if !end.IsZero() {
		raw += " AND timestamp < ?"
		rawArgs = append(rawArgs, end.UTC())
	}
	if !status.Enabled || status.Paused || seconds < 3600 || seconds%3600 != 0 {
		return raw, rawArgs, nil
	}
	if start.IsZero() && end.IsZero() {
		if !status.Ready {
			return summary + " UNION ALL " + raw + " AND id > ? AND id <= ?", append(summaryArgs, status.Cursor, status.Target), nil
		}
		return summary, summaryArgs, nil
	}
	if start.IsZero() || end.IsZero() {
		return raw, rawArgs, nil
	}
	fullStart := start.UTC().Truncate(time.Hour)
	if fullStart.Before(start) {
		fullStart = fullStart.Add(time.Hour)
	}
	fullEnd := end.UTC().Truncate(time.Hour)
	if !fullStart.Before(fullEnd) {
		return raw, rawArgs, nil
	}
	summary += " AND hour >= ? AND hour < ?"
	summaryArgs = append(summaryArgs, fullStart.Unix(), fullEnd.Unix())
	// Separate index range scans prevent the planner from scanning the entire
	// requested raw interval just to discard its already-summarized interior.
	parts := []string{summary}
	if !status.Ready {
		parts = append(parts, rawBase+" AND id > ? AND id <= ? AND timestamp >= ? AND timestamp < ?")
		summaryArgs = append(summaryArgs, status.Cursor, status.Target, fullStart, fullEnd)
	}
	// A partial boundary hour is answered either by scanning its rows inside
	// the window, or by its complete summary minus the rows outside the window,
	// whichever covers less time. Both are exact. A window ending now therefore
	// costs almost nothing for the current hour: nothing lies after now.
	negated := strings.Replace(rawBase, "1 AS event_count, COALESCE(byte_count, 0) AS byte_count", "-1 AS event_count, -COALESCE(byte_count, 0) AS byte_count", 1)
	edge := func(hour, from, to time.Time, inside bool) {
		if inside || !status.Ready {
			parts = append(parts, rawBase+" AND timestamp >= ? AND timestamp < ?")
			summaryArgs = append(summaryArgs, from, to)
			return
		}
		parts = append(parts, summaryHour(column != ""))
		if column != "" {
			summaryArgs = append(summaryArgs, kind)
		}
		summaryArgs = append(summaryArgs, hour.Unix())
		if from.Before(to) {
			parts = append(parts, negated+" AND timestamp >= ? AND timestamp < ?")
			summaryArgs = append(summaryArgs, from, to)
		}
	}
	if start.Before(fullStart) {
		// Rows in [start, fullStart), or summary(fullStart-1h) minus [fullStart-1h, start).
		hour := fullStart.Add(-time.Hour)
		inside := fullStart.Sub(start) <= start.Sub(hour)
		if inside {
			edge(hour, start.UTC(), fullStart, true)
		} else {
			edge(hour, hour, start.UTC(), false)
		}
	}
	if fullEnd.Before(end) {
		// Rows in [fullEnd, end), or summary(fullEnd) minus [end, fullEnd+1h).
		next := fullEnd.Add(time.Hour)
		inside := end.Sub(fullEnd) <= next.Sub(end)
		if inside {
			edge(fullEnd, fullEnd, end.UTC(), true)
		} else {
			edge(fullEnd, end.UTC(), next, false)
		}
	}
	return strings.Join(parts, " UNION ALL "), summaryArgs, nil
}

// summaryHour selects one summary hour with the same columns as summarySource.
func summaryHour(hosts bool) string {
	if hosts {
		return "SELECT hour, host, event_count, byte_count FROM hourly_hosts WHERE kind = ? AND hour = ?"
	}
	return "SELECT hour, event_type, event_count, byte_count FROM hourly_events WHERE hour = ?"
}

// EventCounts returns exact retained counts, using summaries once backfill ends.
func EventCounts(tx *gorm.DB) (map[string]int64, int64, error) {
	source, args, err := summarySource(tx, "", time.Time{}, time.Time{}, 3600)
	if err != nil {
		return nil, 0, err
	}
	var rows []HourlyEvent
	if err := tx.Raw("SELECT event_type, SUM(event_count) AS event_count FROM ("+source+") GROUP BY event_type", args...).Scan(&rows).Error; err != nil {
		return nil, 0, err
	}
	counts := make(map[string]int64, len(rows))
	var total int64
	for _, row := range rows {
		counts[string(row.EventType)] = row.EventCount
		total += row.EventCount
	}
	return counts, total, nil
}

// TopHosts ranks sparse hourly source/destination/name totals. start and end may
// both be zero for all retained history; boundary fragments remain exact.
func TopHosts(tx *gorm.DB, kind string, start, end time.Time, limit int, traffic bool) ([]HostTotal, int64, error) {
	if limit < 1 || limit > 100 {
		return nil, 0, fmt.Errorf("invalid host limit")
	}
	source, args, err := summarySource(tx, kind, start, end, 3600)
	if err != nil {
		return nil, 0, err
	}
	metric := "event_count"
	if traffic {
		metric = "byte_count"
	}
	var hosts []HostTotal
	query := "SELECT host, SUM(event_count) AS event_count, SUM(byte_count) AS byte_count, COUNT(*) OVER() AS total FROM (" + source + ") GROUP BY host HAVING SUM(event_count) > 0 ORDER BY " + metric + " DESC, host ASC LIMIT ?"
	if err := tx.Raw(query, append(args, limit)...).Scan(&hosts).Error; err != nil {
		return nil, 0, err
	}
	var total int64
	if len(hosts) > 0 {
		total = hosts[0].Total
	}
	return hosts, total, nil
}

// TrafficTotals reads hourly summaries for coarse charts and bounded raw detail
// for sub-hour charts. isLocal applies the current network configuration at read
// time, so changing owned CIDRs does not require rewriting historical summaries.
func TrafficTotals(tx *gorm.DB, start, end time.Time, seconds int64, isLocal func(string) bool) (map[int64]*TrafficBucket, error) {
	if seconds <= 0 || !start.Before(end) {
		return nil, fmt.Errorf("invalid traffic interval")
	}
	source, args, err := summarySource(tx, "", start, end, seconds)
	if err != nil {
		return nil, err
	}
	bucket := bucketSQL("hour", seconds)
	var counts []TrafficBucket
	if err := tx.Raw("SELECT "+bucket+" AS hour, SUM(event_count) AS event_count FROM ("+source+") GROUP BY 1", args...).Scan(&counts).Error; err != nil {
		return nil, err
	}
	result := make(map[int64]*TrafficBucket, len(counts))
	for i := range counts {
		row := counts[i]
		result[row.Hour] = &row
	}
	local := make(map[string]bool)
	for _, kind := range []string{"srcIP", "dstIP"} {
		source, args, err := summarySource(tx, kind, start, end, seconds)
		if err != nil {
			return nil, err
		}
		var rows []HourlyHost
		if err := tx.Raw("SELECT "+bucket+" AS hour, host, SUM(byte_count) AS byte_count FROM ("+source+") GROUP BY 1, host HAVING SUM(byte_count) != 0", args...).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			owned, found := local[row.Host]
			if !found {
				owned = isLocal(row.Host)
				local[row.Host] = owned
			}
			if !owned {
				continue
			}
			if result[row.Hour] == nil {
				result[row.Hour] = &TrafficBucket{Hour: row.Hour}
			}
			if kind == "srcIP" {
				result[row.Hour].BytesOut += row.ByteCount
			} else {
				result[row.Hour].BytesIn += row.ByteCount
			}
		}
	}
	return result, nil
}
