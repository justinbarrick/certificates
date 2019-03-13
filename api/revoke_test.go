package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/logging"
)

func TestRevokeRequestValidate(t *testing.T) {
	type test struct {
		rr  *RevokeRequest
		err *Error
		rts authority.RevocationTypeSelector
	}
	tests := map[string]test{
		"error/missing serial": {
			rr:  &RevokeRequest{},
			err: &Error{Err: errors.New("missing serial"), Status: http.StatusBadRequest},
		},
		"error/bad reasonCode": {
			rr: &RevokeRequest{
				Serial:     "sn",
				ReasonCode: 15,
			},
			err: &Error{Err: errors.New("reasonCode out of bounds"), Status: http.StatusBadRequest},
		},
		"ok/all false": {
			rr: &RevokeRequest{
				Serial:     "sn",
				ReasonCode: 9,
			},
			rts: authority.RevocationTypeSelector{All: true, Passive: false, CRL: false, OCSP: false},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tc.rr.Validate(); err != nil {
				switch v := err.(type) {
				case *Error:
					assert.HasPrefix(t, v.Error(), tc.err.Error())
					assert.Equals(t, v.StatusCode(), tc.err.Status)
				default:
					t.Errorf("unexpected error type: %T", v)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.rts, tc.rr.RTS)
				}
			}
		})
	}
}

func Test_caHandler_Revoke(t *testing.T) {
	type test struct {
		input      string
		auth       Authority
		tls        *tls.ConnectionState
		err        error
		statusCode int
		expected   []byte
	}
	tests := map[string]func(*testing.T) test{
		"400/json read error": func(t *testing.T) test {
			return test{
				input:      "{",
				statusCode: http.StatusBadRequest,
			}
		},
		"400/invalid request body": func(t *testing.T) test {
			input, err := json.Marshal(RevokeRequest{})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusBadRequest,
			}
		},
		"401/invalid ott": func(t *testing.T) test {
			input, err := json.Marshal(RevokeRequest{
				Serial:     "sn",
				ReasonCode: 4,
				OTT:        "invalid",
			})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusUnauthorized,
				auth: &mockAuthority{
					err: &Error{Err: errors.New("authorize: error parsing token"),
						Status: http.StatusUnauthorized},
				},
			}
		},
		"501/ott revocation type not implemented": func(t *testing.T) test {
			input, err := json.Marshal(RevokeRequest{
				Serial:     "sn",
				ReasonCode: 4,
				OTT:        "valid",
				CRL:        true,
			})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusNotImplemented,
				auth: &mockAuthority{
					err: &Error{Err: errors.New("revoke CRL unimplemented"),
						Status: http.StatusNotImplemented},
					authorizeRevoke: func(ott string) (string, error) {
						return "provisioner-id", nil
					},
				},
			}
		},
		"200/ott": func(t *testing.T) test {
			input, err := json.Marshal(RevokeRequest{
				Serial:     "sn",
				ReasonCode: 4,
				OTT:        "valid",
				CRL:        true,
			})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusOK,
				auth: &mockAuthority{
					authorizeRevoke: func(ott string) (string, error) {
						return "provisioner-id", nil
					},
					revoke: func(rts authority.RevocationTypeSelector, serial, provisionerID string, reasonCode int) error {
						return nil
					},
				},
				expected: []byte(`{"status":"ok"}`),
			}
		},
		"400/no OTT and no peer certificate": func(t *testing.T) test {
			input, err := json.Marshal(RevokeRequest{
				Serial:     "sn",
				ReasonCode: 4,
			})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusBadRequest,
			}
		},
		"401/peer certificate serial does not match input": func(t *testing.T) test {
			cs := &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{parseCertificate(certPEM)},
			}
			input, err := json.Marshal(RevokeRequest{
				Serial:     "sn",
				ReasonCode: 4,
			})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusUnauthorized,
				tls:        cs,
			}
		},
		"200/no ott": func(t *testing.T) test {
			cs := &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{parseCertificate(certPEM)},
			}
			input, err := json.Marshal(RevokeRequest{
				Serial:     "1404354960355712309",
				ReasonCode: 4,
			})
			assert.FatalError(t, err)
			return test{
				input:      string(input),
				statusCode: http.StatusOK,
				tls:        cs,
				auth: &mockAuthority{
					revoke: func(rts authority.RevocationTypeSelector, serial, provisionerID string, reasonCode int) error {
						return nil
					},
				},
				expected: []byte(`{"status":"ok"}`),
			}
		},
	}

	for name, _tc := range tests {
		tc := _tc(t)
		t.Run(name, func(t *testing.T) {
			h := New(tc.auth).(*caHandler)
			req := httptest.NewRequest("POST", "http://example.com/revoke", strings.NewReader(tc.input))
			if tc.tls != nil {
				req.TLS = tc.tls
			}
			w := httptest.NewRecorder()
			h.Revoke(logging.NewResponseLogger(w), req)
			res := w.Result()

			assert.Equals(t, tc.statusCode, res.StatusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if tc.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tc.expected) {
					t.Errorf("caHandler.Root Body = %s, wants %s", body, tc.expected)
				}
			}
		})
	}
}
