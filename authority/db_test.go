package authority

import "github.com/smallstep/certificates/db"

type MockAuthDB struct {
	err        error
	ret1, ret2 interface{}
	init       func(*db.Config) (db.AuthDB, error)
	isRevoked  func(string) (bool, error)
	revoke     func(rci *db.RevokedCertificateInfo) error
}

func (m *MockAuthDB) Init(c *db.Config) (db.AuthDB, error) {
	if m.init != nil {
		return m.init(c)
	}
	if m.ret1 == nil {
		return nil, m.err
	}
	return m.ret1.(*db.DB), m.err
}

func (m *MockAuthDB) IsRevoked(sn string) (bool, error) {
	if m.isRevoked != nil {
		return m.isRevoked(sn)
	}
	return m.ret1.(bool), m.err
}

func (m *MockAuthDB) Revoke(rci *db.RevokedCertificateInfo) error {
	if m.revoke != nil {
		return m.revoke(rci)
	}
	return m.err
}
