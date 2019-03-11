package authority

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	stepJOSE "github.com/smallstep/cli/jose"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestMatchesAudience(t *testing.T) {
	type matchesTest struct {
		a, b []string
		exp  bool
	}
	tests := map[string]matchesTest{
		"false arg1 empty": {
			a:   []string{},
			b:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com/sign"},
			exp: false,
		},
		"false arg2 empty": {
			a:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com/sign"},
			b:   []string{},
			exp: false,
		},
		"false arg1,arg2 empty": {
			a:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com/sign"},
			b:   []string{"step-gateway", "step-cli"},
			exp: false,
		},
		"false": {
			a:   []string{"step-gateway", "step-cli"},
			b:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com/sign"},
			exp: false,
		},
		"true": {
			a:   []string{"step-gateway", "https://test.ca.smallstep.com/sign"},
			b:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com/sign"},
			exp: true,
		},
		"true,portsA": {
			a:   []string{"step-gateway", "https://test.ca.smallstep.com:9000/sign"},
			b:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com/sign"},
			exp: true,
		},
		"true,portsB": {
			a:   []string{"step-gateway", "https://test.ca.smallstep.com/sign"},
			b:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com:9000/sign"},
			exp: true,
		},
		"true,portsAB": {
			a:   []string{"step-gateway", "https://test.ca.smallstep.com:9000/sign"},
			b:   []string{"https://127.0.0.1:0/sign", "https://test.ca.smallstep.com:8000/sign"},
			exp: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equals(t, tc.exp, matchesAudience(tc.a, tc.b))
		})
	}
}

func TestStripPort(t *testing.T) {
	type args struct {
		rawurl string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"with port", args{"https://ca.smallstep.com:9000/sign"}, "https://ca.smallstep.com/sign"},
		{"with no port", args{"https://ca.smallstep.com/sign/"}, "https://ca.smallstep.com/sign/"},
		{"bad url", args{"https://a bad url:9000"}, "https://a bad url:9000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPort(tt.args.rawurl); got != tt.want {
				t.Errorf("stripPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizeRevoke(t *testing.T) {
	a := testAuthority(t)
	jwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_priv.jwk",
		stepJOSE.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/revoke"}

	type authorizeTest struct {
		auth      *Authority
		ott       string
		audiences []string
		err       *apiError
		res       []interface{}
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail invalid ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:      a,
				ott:       "foo",
				audiences: a.revokeAudiences,
				err: &apiError{errors.New("authorize: error parsing token"),
					http.StatusUnauthorized, context{"ott": "foo"}},
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			assert.FatalError(t, err)

			pid, err := tc.auth.AuthorizeRevoke(tc.ott)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, pid, "step-cli:4UELJx8e0aS9m0CH3fZ0EB7D5aUPICb759zALHFejvc")
				}
			}
		})
	}
}

func TestAuthorizeSign(t *testing.T) {
	a := testAuthority(t)
	jwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_priv.jwk",
		stepJOSE.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/sign"}

	type authorizeTest struct {
		auth        *Authority
		ott         string
		audiences   []string
		err         *apiError
		successTest func(*testing.T, []interface{})
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail invalid ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:      a,
				ott:       "foo",
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: error parsing token"),
					http.StatusUnauthorized, context{"ott": "foo"}},
			}
		},
		"ok/subject takes places of empty SANs": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				successTest: func(t *testing.T, certClaims []interface{}) {
					cnc, ok := certClaims[0].(*commonNameClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, cnc.name, "test.smallstep.com")
					dnc, ok := certClaims[1].(*dnsNamesClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, dnc.names, []string{"test.smallstep.com"})
					iac, ok := certClaims[2].(*ipAddressesClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, iac.ips, []net.IP{})
					p, ok := certClaims[3].(*Provisioner)
					assert.Fatal(t, ok)
					assert.Equals(t, p.Name, "step-cli")
				},
			}
		},
		"ok/one SAN": func(t *testing.T) *authorizeTest {
			cl := Claims{
				Claims: jwt.Claims{
					Subject:   "test.smallstep.com",
					Issuer:    validIssuer,
					NotBefore: jwt.NewNumericDate(now),
					Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
					Audience:  validAudience,
					ID:        "44",
				},
				SANs: []string{"foo"},
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				successTest: func(t *testing.T, certClaims []interface{}) {
					cnc, ok := certClaims[0].(*commonNameClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, cnc.name, "test.smallstep.com")
					dnc, ok := certClaims[1].(*dnsNamesClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, dnc.names, []string{"foo"})
					iac, ok := certClaims[2].(*ipAddressesClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, iac.ips, []net.IP{})
					p, ok := certClaims[3].(*Provisioner)
					assert.Fatal(t, ok)
					assert.Equals(t, p.Name, "step-cli")
				},
			}
		},
		"ok/multiple SANs": func(t *testing.T) *authorizeTest {
			cl := Claims{
				Claims: jwt.Claims{
					Subject:   "test.smallstep.com",
					Issuer:    validIssuer,
					NotBefore: jwt.NewNumericDate(now),
					Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
					Audience:  validAudience,
					ID:        "45",
				},
				SANs: []string{"foo", "1.1.1.1", "bar"},
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth: a,
				ott:  raw,
				successTest: func(t *testing.T, certClaims []interface{}) {
					cnc, ok := certClaims[0].(*commonNameClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, cnc.name, "test.smallstep.com")
					dnc, ok := certClaims[1].(*dnsNamesClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, dnc.names, []string{"foo", "bar"})
					iac, ok := certClaims[2].(*ipAddressesClaim)
					assert.Fatal(t, ok)
					assert.Equals(t, len(iac.ips), 1)
					assert.Equals(t, iac.ips[0].String(), "1.1.1.1")
					p, ok := certClaims[3].(*Provisioner)
					assert.Fatal(t, ok)
					assert.Equals(t, p.Name, "step-cli")
				},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			assert.FatalError(t, err)

			certClaims, err := tc.auth.Authorize(tc.ott)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					if assert.NotNil(t, tc.successTest) {
						tc.successTest(t, certClaims)
					}
				}
			}
		})
	}
}

func TestAuthorizeToken(t *testing.T) {
	a := testAuthority(t)
	jwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_priv.jwk",
		stepJOSE.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)

	now := time.Now().UTC()

	validIssuer := "step-cli"
	validAudience := []string{"https://test.ca.smallstep.com/sign"}

	type authorizeTest struct {
		auth      *Authority
		ott       string
		audiences []string
		err       *apiError
		res       []interface{}
	}
	tests := map[string]func(t *testing.T) *authorizeTest{
		"fail invalid ott": func(t *testing.T) *authorizeTest {
			return &authorizeTest{
				auth:      a,
				ott:       "foo",
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: error parsing token"),
					http.StatusUnauthorized, context{"ott": "foo"}},
			}
		},
		"fail empty key id": func(t *testing.T) *authorizeTest {
			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT"))
			assert.FatalError(t, err)
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: token KeyID cannot be empty"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail provisioner not found": func(t *testing.T) *authorizeTest {
			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "foo"))
			assert.FatalError(t, err)

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: provisioner with id step-cli:foo not found"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail invalid provisioner": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)

			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "foo"))
			assert.FatalError(t, err)

			_a.provisionerIDIndex.Store(validIssuer+":foo", "42")

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      _a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: invalid provisioner type"),
					http.StatusInternalServerError, context{"ott": raw}},
			}
		},
		"fail token claims": func(t *testing.T) *authorizeTest {
			_a := testAuthority(t)

			_jwk, err := stepJOSE.ParseKey("testdata/secrets/max_priv.jwk",
				stepJOSE.WithPassword([]byte("pass")))
			assert.FatalError(t, err)

			_sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: _jwk.Key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
			assert.FatalError(t, err)

			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(_sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      _a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("provisioner public key cannot parse claims"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail ValidateWithLeeway": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Hour)),
				Expiry:    jwt.NewNumericDate(now.Add(-3 * time.Hour)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: invalid token: square/go-jose/jwt: validation failed, token is expired (exp)"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail token issued before start of CA": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-1 * time.Hour)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("token issued before the bootstrap of certificate authority"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail invalid audience": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.revokeAudiences,
				err: &apiError{errors.New("authorize: token audience invalid"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail empty subject": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("authorize: token subject cannot be empty"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"fail token-already-used": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "42",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			_, err = a.Authorize(raw)
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				err: &apiError{errors.New("token already used"),
					http.StatusUnauthorized, context{"ott": raw}},
			}
		},
		"ok": func(t *testing.T) *authorizeTest {
			cl := jwt.Claims{
				Subject:   "test.smallstep.com",
				Issuer:    validIssuer,
				NotBefore: jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
				Audience:  validAudience,
				ID:        "43",
			}
			raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
			assert.FatalError(t, err)
			return &authorizeTest{
				auth:      a,
				ott:       raw,
				audiences: a.audiences,
				res:       []interface{}{"1", "2", "3", "4"},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)
			assert.FatalError(t, err)

			claims := Claims{}

			p, err := tc.auth.authorizeToken(tc.ott, &claims, tc.audiences)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, claims.Issuer, "step-cli")
					assert.Equals(t, p.Name, "step-cli")
				}
			}
		})
	}
}
