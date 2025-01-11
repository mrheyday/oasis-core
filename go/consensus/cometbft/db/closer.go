package db

import (
	"sync"

	dbm "github.com/cometbft/cometbft-db"
)

// Closer manages closing of multiple CometBFT Core databases.
type Closer struct {
	l   sync.Mutex
	dbs []dbm.DB
}

// Close closes all the managed databases.
func (c *Closer) Close() {
	c.l.Lock()
	defer c.l.Unlock()

	for _, db := range c.dbs {
		_ = db.Close()
	}
}

// NewCloser creates a new empty database closer.
func NewCloser() *Closer {
	return &Closer{}
}

type dbWithCloser struct {
	dbm.DB
}

func (d *dbWithCloser) Close() error {
	// Do nothing unless explicitly closed via the closer.
	return nil
}

// WithCloser wraps a CometBFT Core database instance so that it can only be closed by the given
// closer instance. Direct attempts to close the returned database instance will be ignored.
func WithCloser(db dbm.DB, closer *Closer) dbm.DB {
	closer.l.Lock()
	defer closer.l.Unlock()

	closer.dbs = append(closer.dbs, db)

	return &dbWithCloser{db}
}
