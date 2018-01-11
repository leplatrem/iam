package doorman

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// OpenIDConfiguration is the OpenID provider metadata about endpoints etc.
type OpenIDConfiguration struct {
	JWKSUri string `json:"jwks_uri"`
}

// JWKS are the JWT public keys
type JWKS struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type jwtGenericValidator struct {
	Issuer         string
	ClaimExtractor ClaimExtractor
	_jwks          *JWKS
	_config        *OpenIDConfiguration
}

func (v *jwtGenericValidator) config() (*OpenIDConfiguration, error) {
	// XXX: store in cache.
	if v._config == nil {
		config, err := fetchOpenIDConfiguration(v.Issuer)
		if err != nil {
			return nil, err
		}
		v._config = config
	}
	return v._config, nil
}

func (v *jwtGenericValidator) jwks() (*JWKS, error) {
	// XXX: store in cache.
	if v._jwks == nil {
		config, err := v.config()
		if err != nil {
			return nil, err
		}
		jwks, err := downloadKeys(config.JWKSUri)
		if err != nil {
			return nil, err
		}
		v._jwks = jwks
	}
	return v._jwks, nil
}

func (v *jwtGenericValidator) ValidateRequest(r *http.Request) (*Claims, error) {
	// 1. Extract JWT from request headers
	token, err := fromHeader(r)
	if err != nil {
		return nil, err
	}

	// 2. Read JWT headers
	if len(token.Headers) < 1 {
		return nil, fmt.Errorf("No headers in the token")
	}
	header := token.Headers[0]
	if header.Algorithm != string(jose.RS256) {
		return nil, fmt.Errorf("Invalid algorithm")
	}

	// 3. Get public key with specified ID
	keys, err := v.jwks()
	if err != nil {
		return nil, err
	}
	var key *jose.JSONWebKey
	for _, k := range keys.Keys {
		if k.KeyID == header.KeyID {
			key = &k
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("No JWT key with id %q", header.KeyID)
	}

	// 4. Parse and verify signature.
	jwtClaims := jwt.Claims{}
	err = token.Claims(key, &jwtClaims)
	if err != nil {
		return nil, err
	}

	// 5. Validate issuer, claims and expiration.
	// Will check audience only when request comes in, leave empty for now.
	audience := []string{}
	expected := jwt.Expected{Issuer: v.Issuer, Audience: audience}
	expected = expected.WithTime(time.Now())
	err = jwtClaims.Validate(expected)
	if err != nil {
		return nil, err
	}

	// 6. Extract relevant claims for Doorman.
	claims, err := v.ClaimExtractor.Extract(token, key)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// fromHeader reads the authorization header value and parses it as JSON Web Token.
func fromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		raw := []byte(authorizationHeader[7:])
		return jwt.ParseSigned(string(raw))
	}
	return nil, fmt.Errorf("Token not found")
}

func fetchOpenIDConfiguration(issuer string) (*OpenIDConfiguration, error) {
	uri := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	log.Debugf("Fetch OpenID configuration from %s", uri)
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	config := &OpenIDConfiguration{}
	err = json.NewDecoder(response.Body).Decode(config)
	if err != nil {
		return nil, err
	}
	if config.JWKSUri == "" {
		return nil, fmt.Errorf("No jwks_uri attribute in OpenID configuration")
	}
	return config, nil
}

func downloadKeys(uri string) (*JWKS, error) {
	log.Debugf("Fetch public keys from %s", uri)

	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if contentHeader := response.Header.Get("Content-Type"); !strings.HasPrefix(contentHeader, "application/json") {
		return nil, fmt.Errorf("JWKS endpoint has not JSON content-type")
	}

	var jwks = &JWKS{}
	err = json.NewDecoder(response.Body).Decode(jwks)
	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) < 1 {
		return nil, fmt.Errorf("No key found at %q", uri)
	}

	return jwks, nil
}
