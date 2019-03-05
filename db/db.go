package db

import (
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

// dbConfig represents the JSON attributes used for configuration. At
// this moment only fields for NewRelic are supported.
type dbConfig struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// New returns a new database client that implements the nosql.DB interface.
func New(raw json.RawMessage) (nosql.DB, error) {
	var config dbConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling db attribute")
	}

	switch strings.ToLower(config.Type) {
	case "bbolt":
		db := &nosql.BoltDB{}
		err := db.Open(config.Path)
		return db, err
	default:
		return nil, errors.Errorf("unsupported db.type '%s'", config.Type)
	}
}
