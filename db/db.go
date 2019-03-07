package db

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

var revokedCertsTable = []byte("revoked_x509_certs")

// Config represents the JSON attributes used for configuring a step-ca DB.
type Config struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// DB is a wrapper over the nosql.DB interface.
type DB struct {
	nosql.DB
}

// New returns a new database client that implements the nosql.DB interface.
func New(c *Config) (*DB, error) {
	switch strings.ToLower(c.Type) {
	case "bbolt":
		db := &nosql.BoltDB{}
		err := db.Open(c.Path)
		return &DB{db}, err
	default:
		return nil, errors.Errorf("unsupported db.type '%s'", c.Type)
	}
}

// Init database with all necessary tables.
func (db *DB) Init(c *Config) (*DB, error) {
	var err error
	if db == nil {
		if db, err = New(c); err != nil {
			return nil, err
		}
	}
	tables := [][]byte{revokedCertsTable}
	for _, b := range tables {
		if err = db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}
	return db, nil
}

// RevokedCertificateInfo contains information regarding the certificate
// revocation action.
type RevokedCertificateInfo struct {
	Serial        string
	ProvisionerID string
	Reason        int
	RevokedAt     time.Time
}

// IsRevoked returns whether or not a certificate with the given identifier
// has been revoked.
// In the case of an X509 Certificate the `id` should be the Serial Number of
// the Certificate.
func (db *DB) IsRevoked(sn string) (bool, error) {
	// If the DB is nil then act as pass through.
	if db == nil {
		return false, nil
	}

	// If the error is `Not Found` then the certificate has not been revoked.
	// Any other error should be propagated to the caller.
	if _, err := db.Get(revokedCertsTable, []byte(sn)); err != nil {
		if nosql.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "error checking revocation bucket")
	}

	// This certificate has been revoked.
	return true, nil
}

// Revoke adds a certificate to the revocation table.
func (db *DB) Revoke(rci *RevokedCertificateInfo) error {
	rcib, err := json.Marshal(rci)
	if err != nil {
		return errors.Wrap(err, "error marshaling revoked certificate info")
	}

	if db.Set(revokedCertsTable, []byte(rci.Serial), rcib); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}
