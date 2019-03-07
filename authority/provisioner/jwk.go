package provisioner

import (
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
)

// jwtPayload extends jwt.Claims with step attributes.
type jwtPayload struct {
	jose.Claims
	SANs []string `json:"sans,omitempty"`
}

// JWT is the default provisioner, an entity that can sign tokens necessary for
// signature requests.
type JWT struct {
	Name         string           `json:"name,omitempty"`
	Type         string           `json:"type,omitempty"`
	Key          *jose.JSONWebKey `json:"key,omitempty"`
	EncryptedKey string           `json:"encryptedKey,omitempty"`
	Claims       *Claims          `json:"claims,omitempty"`
	audiences    []string
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any JWT provisioner.
func (p *JWT) GetID() string {
	return p.Name + ":" + p.Key.KeyID
}

// GetName returns the name of the provisioner
func (p *JWT) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *JWT) GetType() Type {
	return TypeJWK
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (p *JWT) GetEncryptedKey() (string, string, bool) {
	return p.Key.KeyID, p.EncryptedKey, len(p.EncryptedKey) > 0
}

// Init initializes and validates a the fields of Provisioner type.
func (p *JWT) Init(config Config) (err error) {
	switch {
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")

	case p.Type == "":
		return errors.New("provisioner type cannot be empty")

	case p.Key == nil:
		return errors.New("provisioner key cannot be empty")
	}
	p.Claims, err = p.Claims.Init(&config.Claims)
	p.audiences = config.Audiences
	return err
}

// Authorize validates the given token.
func (p *JWT) Authorize(token string) ([]SignOption, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing token")
	}

	var claims jwtPayload
	if err = jwt.Claims(p.Key, &claims); err != nil {
		return nil, errors.Wrap(err, "error parsing claims")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: p.Name,
	}, time.Minute); err != nil {
		return nil, errors.Wrapf(err, "invalid token")
	}

	// validate audiences with the defaults
	if !matchesAudience(claims.Audience, p.audiences) {
		return nil, errors.New("invalid token: invalid audience claim (aud)")
	}

	if claims.Subject == "" {
		return nil, errors.New("token subject cannot be empty")
	}

	// NOTE: This is for backwards compatibility with older versions of cli
	// and certificates. Older versions added the token subject as the only SAN
	// in a CSR by default.
	if len(claims.SANs) == 0 {
		claims.SANs = []string{claims.Subject}
	}

	dnsNames, ips := x509util.SplitSANs(claims.SANs)
	if err != nil {
		return nil, err
	}

	signOps := []SignOption{
		commonNameValidator(claims.Subject),
		dnsNamesValidator(dnsNames),
		ipAddressesValidator(ips),
		// profileWithOption(x509util.WithNotBeforeAfterDuration(so.NotBefore, so.NotAfter, p.Claims.DefaultTLSCertDuration())),
		newProvisionerExtensionOption(TypeJWK, p.Name, p.Key.KeyID),
		newValidityValidator(p.Claims.MinTLSCertDuration(), p.Claims.MaxTLSCertDuration()),
	}

	return signOps, nil
}

// AuthorizeRenewal returns an error if the renewal is disabled.
func (p *JWT) AuthorizeRenewal(cert *x509.Certificate) error {
	if p.Claims.IsDisableRenewal() {
		return errors.Errorf("renew is disabled for provisioner %s", p.GetID())
	}
	return nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *JWT) AuthorizeRevoke(token string) error {
	return errors.New("not implemented")
}

// // getTLSApps returns a list of modifiers and validators that will be applied to
// // the certificate.
// func (p *JWT) getTLSApps(so SignOptions) ([]x509util.WithOption, []certClaim, error) {
// 	c := p.Claims
// 	return []x509util.WithOption{
// 			x509util.WithNotBeforeAfterDuration(so.NotBefore, so.NotAfter, c.DefaultTLSCertDuration()),
// 			withProvisionerOID(p.Name, p.Key.KeyID),
// 		}, []certClaim{
// 			&certTemporalClaim{
// 				min: c.MinTLSCertDuration(),
// 				max: c.MaxTLSCertDuration(),
// 			},
// 		}, nil
// }