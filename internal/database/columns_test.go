package database

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// EventColumns is the number of columns a stored event binds on insert.
func EventColumns(t *testing.T) int {
	t.Helper()
	parsed, err := schema.Parse(&NetworkEvent{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	return len(parsed.DBNames)
}

// A multi-row insert binds every column of every row; SQLite builds may
// allow only 999 variables in a statement.
func TestEventInsertsStayWithinBindLimit(t *testing.T) {
	columns := EventColumns(t)
	t.Logf("%d columns, %d rows per insert", columns, eventInsertBatch)
	if eventInsertBatch*columns > 999 {
		t.Fatalf("%d rows of %d columns bind %d variables; lower eventInsertBatch", eventInsertBatch, columns, eventInsertBatch*columns)
	}
}
