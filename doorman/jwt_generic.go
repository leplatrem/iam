package doorman

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"

	jose "gopkg.in/square/go-jose.v2"
)

// OpenIDConfiguration is the OpenID provider metadata about endpoints etc.
type OpenIDConfiguration struct {
	JWKSUri     string `json:jwks_uri`
}

// JWKS are the JWT public keys
type JWKS struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type ClaimExtractor interface {
	Extract(*jwt.JSONWebToken, *jose.JSONWebKey) (*Claims)
}

type JWTGenericValidator struct {
	Issuer string
	ClaimExtractor ClaimExtractor
}

func (v *JWTGenericValidator) ExtractClaims(r *http.Request) (*Claims, error)
	token, key, err := ValidateJWT(v.Issuer, r)
	if err != nil {
		return nil, err
	}
	claims, err := v.ClaimExtractor.Extract(token, key)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

type DefaultClaimExtractor struct {}

func (*DefaultClaimExtractor) Extract(token *jwt.JSONWebToken, key *jose.JSONWebKey) (*Claims, error) {
	claims := Claims{}
	err := token.Claims(key, &claims)
	if err != nil {
		return nil, err
	}
	return nil, claims
}

func fetchOpenIDConfiguration(issuer string) (*OpenIDConfiguration, error) {
	uri := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	log.Debugf("Fetch OpenID configuration from %s", uri)
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	config := OpenIDConfiguration{}
	err = json.NewDecoder(response.Body).Decode(&config)
	if err != nil {
		return nil, err
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
		return nil, fmt.Error("JWKS endpoint has not JSON content-type")
	}

	var jwks = JWKS{}
	err = json.NewDecoder(response.Body).Decode(&jwks)
	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) < 1 {
		return nil, fmt.Errorf("No key found at %q", uri)
	}

	return jwks, nil
}

func GetKey(issuer string, id string) (*jose.JSONWebKey, error) {
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
			return k, nil
		}
	}
	return nil, fmt.Errorf("No JWT key with id %q", id)
}

// FromHeader reads the authorization header value and parses it as JSON Web Token.
func FromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		raw := []byte(authorizationHeader[7:])
		return jwt.ParseSigned(string(raw))
	}
	return fmt.Error("Token not found")
}

// ValidateJWT verifies the JWT signature and claims.
func ValidateJWT(issuer string, r *http.Request) (*jwt.JSONWebToken, *jose.JSONWebKey, error) {
	// 1. Extract JWT from request headers

	token, err := FromHeader(r)
	if err != nil {
		return nil, nil, err
	}

	// 2. Read JWT headers

	if len(token.Headers) < 1 {
		return nil, nil, fmt.Error("No headers in the token")
	}
	header := token.Headers[0]
	if header.Algorithm != jose.RS256 {
		return nil, nil, fmt.Error("Invalid algorithm")
	}

	// 3. Get public key with specified ID

	key, err := GetKey(issuer, header.KeyID)
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
