package ese

import (
	"fmt"
	"io"
	"os"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/go-ese/parser"
)

type DB struct {
	file    *os.File
	ctx     *parser.ESEContext
	catalog *parser.Catalog
}

func OpenDB(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ESE file %s: %w", path, err)
	}

	ctx, err := parser.NewESEContext(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to initialize ESE context: %w", err)
	}

	catalog, err := parser.ReadCatalog(ctx)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to read ESE catalog: %w", err)
	}

	return &DB{
		file:    f,
		ctx:     ctx,
		catalog: catalog,
	}, nil
}

func (db *DB) Close() error {
	if db.file != nil {
		return db.file.Close()
	}
	return nil
}

func (db *DB) TableNames() []string {
	if db.catalog == nil || db.catalog.Tables == nil {
		return nil
	}
	return db.catalog.Tables.Keys()
}

func (db *DB) StreamTable(name string, cb func(row *ordereddict.Dict) error) error {
	if db.catalog == nil {
		return fmt.Errorf("database catalog is nil")
	}
	return db.catalog.DumpTable(name, cb)
}

func (db *DB) Reader() io.ReaderAt {
	return db.file
}
