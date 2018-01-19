package authn

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/allegro/bigcache"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// openIDConfiguration is the OpenID provider metadata about URIs, endpoints etc.
type openIDConfiguration struct {
	JWKSUri string `json:"jwks_uri"`
}

// publicKeys are the JWT public keys
type publicKeys struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type jwtGenericValidator struct {
	Issuer             string
	SignatureAlgorithm jose.SignatureAlgorithm
	ClaimExtractor     claimExtractor
	cache              *bigcache.BigCache
}

// newJWTGenericValidator returns a new instance of a generic JWT validator
// for the specified issuer.
func newJWTGenericValidator(issuer string) *jwtGenericValidator {
	cache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(1 * time.Hour))

	var extractor claimExtractor = defaultExtractor
	if strings.Contains(issuer, "mozilla.auth0.com") {
		extractor = mozillaExtractor
	}
	return &jwtGenericValidator{
		Issuer:             issuer,
		SignatureAlgorithm: jose.RS256,
		ClaimExtractor:     extractor,
		cache:              cache,
	}
}

func (v *jwtGenericValidator) config() (*openIDConfiguration, error) {
	cacheKey := "config:" + v.Issuer
	data, err := v.cache.Get(cacheKey)

	// Cache is empty or expired: fetch again.
	if err != nil {
		uri := strings.TrimRight(v.Issuer, "/") + "/.well-known/openid-configuration"
		log.Debugf("Fetch OpenID configuration from %s", uri)
		data, err = downloadJSON(uri)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch OpenID configuration")
		}
		v.cache.Set(cacheKey, data)
	}

	// Since cache stores bytes, we parse it again at every usage :( ?
	config := &openIDConfiguration{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse OpenID configuration")
	}
	if config.JWKSUri == "" {
		return nil, fmt.Errorf("no jwks_uri attribute in OpenID configuration")
	}
	return config, nil
}

func (v *jwtGenericValidator) jwks() (*publicKeys, error) {
	cacheKey := "jwks:" + v.Issuer
	data, err := v.cache.Get(cacheKey)

	// Cache is empty or expired: fetch again.
	if err != nil {
		config, err := v.config()
		if err != nil {
			return nil, err
		}
		uri := config.JWKSUri
		log.Debugf("Fetch public keys from %s", uri)
		data, err = downloadJSON(uri)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch JWKS")
		}
		v.cache.Set(cacheKey, data)
	}

	var jwks = &publicKeys{}
	err = json.Unmarshal(data, jwks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse JWKS")
	}

	if len(jwks.Keys) < 1 {
		return nil, fmt.Errorf("no JWKS found")
	}
	return jwks, nil
}

func (v *jwtGenericValidator) ValidateRequest(r *http.Request) (*Claims, error) {
	// 1. Extract JWT from request headers
	token, err := fromHeader(r)
	if err != nil {
		return nil, err
	}

	// 2. Read JWT headers
	if len(token.Headers) < 1 {
		return nil, fmt.Errorf("no headers in the token")
	}
	header := token.Headers[0]
	if header.Algorithm != string(v.SignatureAlgorithm) {
		return nil, fmt.Errorf("invalid algorithm")
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
		return nil, fmt.Errorf("no JWT key with id %q", header.KeyID)
	}

	// 4. Parse and verify signature.
	jwtClaims := jwt.Claims{}
	err = token.Claims(key, &jwtClaims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read JWT payload")
	}

	// 5. Validate issuer, audience, claims and expiration.
	origin := r.Header.Get("Origin")
	expected := jwt.Expected{
		Issuer:   v.Issuer,
		Audience: jwt.Audience{origin},
	}
	expected = expected.WithTime(time.Now())
	err = jwtClaims.Validate(expected)
	if err != nil {
		return nil, errors.Wrap(err, "invalid JWT claims")
	}

	// 6. Extract relevant claims for Doorman.
	claims, err := v.ClaimExtractor.Extract(token, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract JWT claims")
	}
	return claims, nil
}

// fromHeader reads the authorization header value and parses it as JSON Web Token.
func fromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		raw := []byte(authorizationHeader[7:])
		return jwt.ParseSigned(string(raw))
	}
	return nil, fmt.Errorf("token not found")
}

func downloadJSON(uri string) ([]byte, error) {
	response, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if contentHeader := response.Header.Get("Content-Type"); !strings.HasPrefix(contentHeader, "application/json") {
		return nil, fmt.Errorf("%s has not a JSON content-type", uri)
	}
	defer response.Body.Close()
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not download JSON")
	}
	return data, nil
}
