package api

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

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

// RevokeResponse is the response object that returns the health of the server.
type RevokeResponse struct {
	Status string `json:"status"`
}

// RevokeRequest is the request body for a revocation request.
type RevokeRequest struct {
	Serial     string `json:"serial"`
	OTT        string `json:"ott"`
	Reason     string `json:"reason"`
	ReasonCode int
}

// Validate checks the fields of the RevokeRequest and returns nil if they are ok
// or an error if something is wrong.
func (r *RevokeRequest) Validate() (err error) {
	if r.Serial == "" {
		return BadRequest(errors.New("missing serial"))
	}
	if r.ReasonCode, err = ReasonStringToCode(r.Reason); err != nil {
		return BadRequest(err)
	}

	return
}

// Revoke prevents a certificate from being renewed in the future.
// TODO: Add CRL and OCSP support to prevent certificate from being used in present.
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

	if len(body.OTT) > 0 {
		// If a token is passed then Authorize the token.
		logOtt(w, body.OTT)
		if provisionerID, err = h.Authority.AuthorizeRevoke(body.OTT); err != nil {
			WriteError(w, Unauthorized(err))
		}
	} else {
		// If no token is present, then the request must be made over mTLS and
		// the client certificate Serial Number must match the serial number '
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

	logRevoke(w, body.Serial, provisionerID, body.Reason)

	if err := h.Authority.Revoke(body.Serial, provisionerID, body.ReasonCode); err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusOK)
	JSON(w, &RevokeResponse{Status: "ok"})
}