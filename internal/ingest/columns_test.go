package ingest

import (
	"sync"
	"testing"

	"github.com/abja/net-watcher/internal/database"
	"gorm.io/gorm/schema"
)

func TestIngestInsertsStayWithinBindLimit(t *testing.T) {
	for _, c := range []struct {
		model any
		rows  int
	}{{&database.NetworkEvent{}, eventInsertSize}, {&database.DNSResolution{}, resolutionInsertSize}} {
		parsed, err := schema.Parse(c.model, &sync.Map{}, schema.NamingStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		if c.rows*len(parsed.DBNames) > 999 {
			t.Fatalf("%T: %d rows of %d columns bind %d variables", c.model, c.rows, len(parsed.DBNames), c.rows*len(parsed.DBNames))
		}
	}
}
