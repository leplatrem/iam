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
}

func (v *jwtGenericValidator) ValidateRequest(r *http.Request) (*Claims, error) {
	token, key, err := validateJWT(v.Issuer, r)
	if err != nil {
		return nil, err
	}
	claims, err := v.ClaimExtractor.Extract(token, key)
	if err != nil {
		return nil, err
	}
	return claims, nil
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

// getJSONWebKey downloads the key with the specified ID from this issuer.
func getJSONWebKey(issuer string, id string) (*jose.JSONWebKey, error) {
	// XXX: store in cache.
	config, err := fetchOpenIDConfiguration(issuer)
	if err != nil {
		return nil, err
	}

	jwks, err := downloadKeys(config.JWKSUri)
	if err != nil {
		return nil, err
	}

	for _, k := range jwks.Keys {
		if k.KeyID == id {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("No JWT key with id %q", id)
}

// fromHeader reads the authorization header value and parses it as JSON Web Token.
func fromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		raw := []byte(authorizationHeader[7:])
		return jwt.ParseSigned(string(raw))
	}
	return nil, fmt.Errorf("Token not found")
}

// validateJWT verifies the JWT signature and claims.
func validateJWT(issuer string, r *http.Request) (*jwt.JSONWebToken, *jose.JSONWebKey, error) {
	// 1. Extract JWT from request headers

	token, err := fromHeader(r)
	if err != nil {
		return nil, nil, err
	}

	// 2. Read JWT headers

	if len(token.Headers) < 1 {
		return nil, nil, fmt.Errorf("No headers in the token")
	}
	header := token.Headers[0]
	if header.Algorithm != string(jose.RS256) {
		return nil, nil, fmt.Errorf("Invalid algorithm")
	}

	// 3. Get public key with specified ID

	key, err := getJSONWebKey(issuer, header.KeyID)
	if err != nil {
		return nil, nil, err
	}

	// 4. Parse and verify signature.

	jwtClaims := jwt.Claims{}
	err = token.Claims(key, &jwtClaims)
	if err != nil {
		return nil, nil, err
	}

	// 5. Validate issuer, claims and expiration.

	// Will check audience only when request comes in, leave empty for now.
	audience := []string{}
	expected := jwt.Expected{Issuer: issuer, Audience: audience}
	expected = expected.WithTime(time.Now())
	err = jwtClaims.Validate(expected)
	return token, key, err
}
