package database

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestReadOnlyPoolDoesNotBlockWALWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	writer, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	err = reader.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&NetworkEvent{}).Count(&count).Error; err != nil {
			return err
		}
		written := make(chan error, 1)
		go func() {
			written <- writer.InsertEvent(&NetworkEvent{Timestamp: time.Now(), EventType: EventTCPStart})
		}()
		select {
		case err := <-written:
			return err
		case <-time.After(2 * time.Second):
			return fmt.Errorf("writer blocked behind reader")
		}
	})
	if err != nil {
		t.Fatalf("a read transaction stalled ingestion: %v", err)
	}
	if err := reader.InsertEvent(&NetworkEvent{Timestamp: time.Now(), EventType: EventTCPEnd}); err == nil {
		t.Fatal("read-only pool accepted a write")
	}
}
