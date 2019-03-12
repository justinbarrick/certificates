package api

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority"
)

func TestRevokeRequestValidate(t *testing.T) {
	type test struct {
		rr  *RevokeRequest
		err *Error
		rts authority.RevocationTypeSelector
	}
	tests := map[string]test{
		"error/missing serial": test{
			rr:  &RevokeRequest{},
			err: &Error{Err: errors.New("missing serial"), Status: http.StatusBadRequest},
		},
		"error/bad reasonCode": test{
			rr: &RevokeRequest{
				Serial:     "sn",
				ReasonCode: 15,
			},
			err: &Error{Err: errors.New("reasonCode out of bounds"), Status: http.StatusBadRequest},
		},
		"ok/all false": test{
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
