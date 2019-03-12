package api

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/logging"
	"golang.org/x/crypto/ocsp"
)

/*
// RevocationReasonCodes is a map between string reason codes
// to integers as defined in RFC 5280
var RevocationReasonCodes = map[string]int{
	"unspecified":          ocsp.Unspecified,
	"keycompromise":        ocsp.KeyCompromise,
	"cacompromise":         ocsp.CACompromise,
	"affiliationchanged":   ocsp.AffiliationChanged,
	"superseded":           ocsp.Superseded,
	"cessationofoperation": ocsp.CessationOfOperation,
	"certificatehold":      ocsp.CertificateHold,
	"removefromcrl":        ocsp.RemoveFromCRL,
	"privilegewithdrawn":   ocsp.PrivilegeWithdrawn,
	"aacompromise":         ocsp.AACompromise,
}

// ReasonStringToCode tries to convert a reason string to an integer code
func ReasonStringToCode(reason string) (int, error) {
	// default to 0
	if reason == "" {
		return 0, nil
	}

	code, found := RevocationReasonCodes[strings.ToLower(reason)]
	if !found {
		return 0, errors.Errorf("unrecognized revocation reason '%s'", reason)
	}

	return code, nil
}
*/

// RevokeResponse is the response object that returns the health of the server.
type RevokeResponse struct {
	Status string `json:"status"`
}

// RevokeRequest is the request body for a revocation request.
type RevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	ReasonCode int    `json:"reasonCode"`
	Passive    bool   `json:"passive"`
	CRL        bool   `json:"crl"`
	OCSP       bool   `json:"ocsp"`
	RTS        authority.RevocationTypeSelector
}

// Validate checks the fields of the RevokeRequest and returns nil if they are ok
// or an error if something is wrong.
func (r *RevokeRequest) Validate() (err error) {
	if r.Serial == "" {
		return BadRequest(errors.New("missing serial"))
	}
	if r.ReasonCode < ocsp.Unspecified || r.ReasonCode > ocsp.AACompromise {
		return BadRequest(errors.New("reasonCode out of bounds"))
	}

	r.RTS = authority.RevocationTypeSelector{
		Passive: r.Passive,
		CRL:     r.CRL,
		OCSP:    r.OCSP,
	}

	// If no revocation type is selected then assume 'All'.
	if !(r.RTS.Passive || r.RTS.CRL || r.RTS.OCSP) {
		r.RTS.All = true
	}

	return
}

// Revoke supports handful of different methods that revoke a Certificate.
//
// NOTE: currently only Passive revocation is supported.
//
// TODO: Add CRL and OCSP support.
func (h *caHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var body RevokeRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	var (
		err           error
		provisionerID string
	)

	// A token indicates that we are using the api via a provisioner token,
	// otherwise it is assumed that the certificate is revoking itself over mTLS.
	if len(body.OTT) > 0 {
		// If a token is passed then Authorize the token.
		logOtt(w, body.OTT)
		if provisionerID, err = h.Authority.AuthorizeRevoke(body.OTT); err != nil {
			WriteError(w, Unauthorized(err))
			return
		}
	} else {
		// If no token is present, then the request must be made over mTLS and
		// the client certificate Serial Number must match the serial number
		// being revoked.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			WriteError(w, BadRequest(errors.New("missing peer certificate")))
			return
		}
		clientCrt := r.TLS.PeerCertificates[0]
		if clientCrt.SerialNumber.String() != body.Serial {
			WriteError(w, Unauthorized(errors.New("client certificate serial number does not match request body")))
			return
		}
	}

	logRevoke(w, body.Serial, provisionerID, body.ReasonCode)

	if err := h.Authority.Revoke(body.RTS, body.Serial, provisionerID, body.ReasonCode); err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusOK)
	JSON(w, &RevokeResponse{Status: "ok"})
}

func logRevoke(w http.ResponseWriter, serial, provisionerID string, reasonCode int) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"serial":        serial,
			"provisionerID": provisionerID,
			"reasonCode":    reasonCode,
		})
	}
}
