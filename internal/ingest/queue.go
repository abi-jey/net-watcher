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
}

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
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Queue{db: db, maxBytes: maxBytes, wake: make(chan struct{}, 1)}, nil
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
		return false, fmt.Errorf("decode queued batch %d: %w", id, err)
	}
	// No spool connection is held while maintenance occupies the central writer.
	// A crash between store and delete replays safely through ingest source keys.
	if err := receiver.store(ctx, batch); err != nil {
		return false, err
	}
	_, err = q.db.ExecContext(ctx, "DELETE FROM pending_batches WHERE id = ?", id)
	return err == nil, err
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
	log.Info("Ingestion queue status", "batches", count, "bytes", bytes, "capacity_bytes", q.maxBytes, "oldest_age_seconds", age)
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
	for ctx.Err() == nil {
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
