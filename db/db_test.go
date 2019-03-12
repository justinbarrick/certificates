package db

import (
	"errors"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/nosql"
)

type MockNoSQLDB struct {
	err         error
	ret1, ret2  interface{}
	get         func(bucket, key []byte) ([]byte, error)
	set         func(bucket, key, value []byte) error
	open        func(path string) error
	close       func() error
	createTable func(bucket []byte) error
	deleteTable func(bucket []byte) error
	del         func(bucket, key []byte) error
	list        func(bucket []byte) ([]*nosql.Entry, error)
	update      func(tx *nosql.Tx) error
}

func (m *MockNoSQLDB) Get(bucket, key []byte) ([]byte, error) {
	if m.get != nil {
		return m.get(bucket, key)
	}
	if m.ret1 == nil {
		return nil, m.err
	}
	return m.ret1.([]byte), m.err
}

func (m *MockNoSQLDB) Set(bucket, key, value []byte) error {
	if m.set != nil {
		return m.set(bucket, key, value)
	}
	return m.err
}

func (m *MockNoSQLDB) Open(path string) error {
	if m.open != nil {
		return m.open(path)
	}
	return m.err
}

func (m *MockNoSQLDB) Close() error {
	if m.close != nil {
		return m.close()
	}
	return m.err
}

func (m *MockNoSQLDB) CreateTable(bucket []byte) error {
	if m.createTable != nil {
		return m.createTable(bucket)
	}
	return m.err
}

func (m *MockNoSQLDB) DeleteTable(bucket []byte) error {
	if m.deleteTable != nil {
		return m.deleteTable(bucket)
	}
	return m.err
}

func (m *MockNoSQLDB) Del(bucket, key []byte) error {
	if m.del != nil {
		return m.del(bucket, key)
	}
	return m.err
}

func (m *MockNoSQLDB) List(bucket []byte) ([]*nosql.Entry, error) {
	if m.list != nil {
		return m.list(bucket)
	}
	return m.ret1.([]*nosql.Entry), m.err
}

func (m *MockNoSQLDB) Update(tx *nosql.Tx) error {
	if m.update != nil {
		return m.update(tx)
	}
	return m.err
}

func TestIsRevoked(t *testing.T) {
	tests := map[string]struct {
		key       string
		db        *DB
		isRevoked bool
		err       error
	}{
		"false/nil db": {
			key: "sn",
		},
		"false/ErrNotFound": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{err: nosql.ErrNotFound, ret1: nil}},
		},
		"error/checking bucket": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{err: errors.New("force"), ret1: nil}},
			err: errors.New("error checking revocation bucket: force"),
		},
		"true": {
			key:       "sn",
			db:        &DB{&MockNoSQLDB{ret1: []byte("value")}},
			isRevoked: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			isRevoked, err := tc.db.IsRevoked(tc.key)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Fatal(t, isRevoked == tc.isRevoked)
			}
		})
	}
}

func TestRevoke(t *testing.T) {
	tests := map[string]struct {
		rci *RevokedCertificateInfo
		db  *DB
		err error
	}{
		"error/database set": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db:  &DB{&MockNoSQLDB{err: errors.New("force")}},
			err: errors.New("database Set error: force"),
		},
		"ok": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db:  &DB{&MockNoSQLDB{}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tc.db.Revoke(tc.rci); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
