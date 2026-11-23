package ingest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/charmbracelet/log"
)

var errQueueFull = errors.New("ingestion queue is full")

// Queue durably buffers acknowledged batches independently of the central writer.
// Its capacity bounds live payload bytes; SQLite pages and WAL add disk overhead.
type Queue struct {
	db       *sql.DB
	maxBytes int64
	wake     chan struct{}

	// Tracks the head batch's failures so one poison batch cannot block the
	// spool indefinitely.
	failingID    int64
	failures     int
	firstFailure time.Time
	now          func() time.Time
}

const (
	deadLetterAttempts = 10
	deadLetterAfter    = 10 * time.Minute
	deadLetterRetry    = time.Hour
)

// OpenQueue opens a persistent spool. FULL synchronization makes acknowledgments
// durable before collectors are permitted to discard their local observations.
func OpenQueue(path string, maxBytes int64) (*Queue, error) {
	if maxBytes <= 0 {
		return nil, errors.New("queue capacity must be positive")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute, RawQuery: "_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000"}
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pending_batches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		digest BLOB NOT NULL UNIQUE,
		payload BLOB NOT NULL,
		created_at INTEGER NOT NULL
	)`)
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS dead_batches (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			payload BLOB NOT NULL,
			error TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			attempts INTEGER NOT NULL
		)`)
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Queue{db: db, maxBytes: maxBytes, wake: make(chan struct{}, 1), now: time.Now}, nil
}

// Close releases the spool after its worker has stopped. Pending batches remain.
func (q *Queue) Close() error { return q.db.Close() }

func (q *Queue) enqueue(ctx context.Context, batch Batch) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pending_batches WHERE digest = ?)", digest[:]).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	var used int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(payload)), 0) FROM pending_batches").Scan(&used); err != nil {
		return err
	}
	if int64(len(payload)) > q.maxBytes-used {
		return errQueueFull
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO pending_batches(digest, payload, created_at) VALUES (?, ?, ?)", digest[:], payload, time.Now().Unix()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *Queue) drainOne(ctx context.Context, receiver *Receiver) (bool, error) {
	var id int64
	var payload []byte
	err := q.db.QueryRowContext(ctx, "SELECT id, payload FROM pending_batches ORDER BY id LIMIT 1").Scan(&id, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var batch Batch
	if err := json.Unmarshal(payload, &batch); err != nil {
		return q.deadLetter(ctx, id, payload, fmt.Errorf("decode queued batch %d: %w", id, err))
	}
	// No spool connection is held while maintenance occupies the central writer.
	// A crash between store and delete replays safely through ingest source keys.
	if err := receiver.store(ctx, batch); err != nil {
		if ctx.Err() != nil {
			return false, err
		}
		if q.failingID != id {
			q.failingID, q.failures, q.firstFailure = id, 0, q.now()
		}
		q.failures++
		if q.failures >= deadLetterAttempts && q.now().Sub(q.firstFailure) >= deadLetterAfter {
			return q.deadLetter(ctx, id, payload, err)
		}
		return false, err
	}
	q.failingID, q.failures = 0, 0
	_, err = q.db.ExecContext(ctx, "DELETE FROM pending_batches WHERE id = ?", id)
	return err == nil, err
}

// deadLetter moves a batch out of the head of the spool. It is kept, not
// deleted, and retried periodically by retryDeadLetters.
func (q *Queue) deadLetter(ctx context.Context, id int64, payload []byte, cause error) (bool, error) {
	log.Error("Setting aside ingest batch that repeatedly failed; later batches continue", "batch", id, "error", cause)
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO dead_batches(payload, error, created_at, attempts) VALUES (?, ?, ?, ?)", payload, truncate(cause.Error(), 1024), q.now().Unix(), q.failures); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM pending_batches WHERE id = ?", id); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	q.failingID, q.failures = 0, 0
	return true, nil
}

// retryDeadLetters attempts each set-aside batch once, directly, so a transient
// cause (disk full, schema mismatch fixed by an upgrade) heals without blocking
// the live spool.
func (q *Queue) retryDeadLetters(ctx context.Context, receiver *Receiver) {
	rows, err := q.db.QueryContext(ctx, "SELECT id, payload FROM dead_batches ORDER BY id LIMIT 100")
	if err != nil {
		return
	}
	type entry struct {
		id      int64
		payload []byte
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if rows.Scan(&e.id, &e.payload) == nil {
			entries = append(entries, e)
		}
	}
	rows.Close()
	for _, e := range entries {
		var batch Batch
		err := json.Unmarshal(e.payload, &batch)
		if err == nil {
			err = receiver.store(ctx, batch)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			_, _ = q.db.ExecContext(ctx, "UPDATE dead_batches SET attempts = attempts + 1, error = ? WHERE id = ?", truncate(err.Error(), 1024), e.id)
			continue
		}
		_, _ = q.db.ExecContext(ctx, "DELETE FROM dead_batches WHERE id = ?", e.id)
		log.Info("Recovered set-aside ingest batch", "dead_batch", e.id)
	}
}

// DeadLetters reports how many batches are set aside.
func (q *Queue) DeadLetters(ctx context.Context) (int64, error) {
	var count int64
	err := q.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dead_batches").Scan(&count)
	return count, err
}

func (q *Queue) report(ctx context.Context) {
	var count, bytes, oldest int64
	err := q.db.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0), COALESCE(MIN(created_at), 0) FROM pending_batches").Scan(&count, &bytes, &oldest)
	if err != nil {
		if ctx.Err() == nil {
			log.Error("Could not read ingestion queue status", "error", err)
		}
		return
	}
	var age int64
	if count > 0 {
		age = max(0, time.Now().Unix()-oldest)
	}
	dead, _ := q.DeadLetters(ctx)
	log.Info("Ingestion queue status", "batches", count, "bytes", bytes, "capacity_bytes", q.maxBytes, "oldest_age_seconds", age, "dead_letters", dead)
}

// Run drains the spool in the background until cancellation, retaining failed or
// interrupted batches for retry. Run only one worker for a queue; the central
// writer must use synchronous=FULL before removing durably acknowledged entries.
func (q *Queue) Run(ctx context.Context, receiver *Receiver) {
	done := make(chan struct{})
	reporterDone := make(chan struct{})
	defer func() {
		close(done)
		<-reporterDone
	}()
	go func() {
		defer close(reporterDone)
		q.report(ctx)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				q.report(ctx)
			}
		}
	}()
	lastDeadRetry := q.now()
	for ctx.Err() == nil {
		if q.now().Sub(lastDeadRetry) >= deadLetterRetry {
			lastDeadRetry = q.now()
			q.retryDeadLetters(ctx, receiver)
		}
		sent, err := q.drainOne(ctx, receiver)
		if ctx.Err() != nil {
			return
		}
		if sent {
			continue
		}
		if err != nil {
			log.Warn("Queued ingestion failed; retaining batch for retry", "error", err)
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
		case <-timer.C:
		case <-q.wake:
		}
		timer.Stop()
	}
}
