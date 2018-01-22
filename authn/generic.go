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

// CacheTTL is the cache duration for remote info like OpenID config or keys.
const CacheTTL = 1 * time.Hour

// openIDConfiguration is the OpenID provider metadata about URIs, endpoints etc.
type openIDConfiguration struct {
	JWKSUri          string `json:"jwks_uri"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
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
	cache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(CacheTTL))

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
		data, err = downloadJSON(uri, nil)
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
		data, err = downloadJSON(uri, nil)
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

func (v *jwtGenericValidator) FetchUserInfo(r *http.Request) (*UserInfo, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if len(authorizationHeader) <= 7 || !strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		return nil, fmt.Errorf("Missing Authorization header")
	}
	if strings.Count(authorizationHeader, ".") == 3 {
		return nil, fmt.Errorf("Looks like JWT ID Token")
	}

	accessToken := authorizationHeader[7:]
	cacheKey := "userinfo:" + accessToken

	data, err := v.cache.Get(cacheKey)
	// Cache is empty or expired: fetch again.
	if err != nil {
		config, err := v.config()
		if err != nil {
			return nil, err
		}
		uri := config.UserInfoEndpoint
		log.Debugf("Fetch user info from %s", uri)
		data, err = downloadJSON(uri, http.Header{
			"Authorization": []string{authorizationHeader},
		})
		v.cache.Set(cacheKey, data)
	}

	userinfo, err := v.ClaimExtractor.Extract(data)
	if err != nil {
		return nil, err
	}

	return userinfo, nil
}

func (v *jwtGenericValidator) ValidateRequest(r *http.Request) (*UserInfo, error) {
	// Mega-WIP
	userinfo, err := v.FetchUserInfo(r)
	if err == nil {
		return userinfo, nil
	}

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

	// 6. Decrypt/verify JWT payload to basic JSON.
	var payload map[string]interface{}
	err = token.Claims(key, &payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt/verify JWT claims")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert JWT payload to JSON")
	}

	// 6. Extract relevant claims for Doorman.
	userinfo, err = v.ClaimExtractor.Extract(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract userinfo from JWT payload")
	}
	return userinfo, nil
}

// fromHeader reads the authorization header value and parses it as JSON Web Token.
func fromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		raw := []byte(authorizationHeader[7:])
		return jwt.ParseSigned(string(raw))
	}
	return nil, fmt.Errorf("token not found")
}

func downloadJSON(uri string, header http.Header) ([]byte, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", uri, nil)
	if header != nil {
		req.Header = header
	}
	req.Header.Add("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not read JSON")
	}
	if contentHeader := response.Header.Get("Content-Type"); !strings.HasPrefix(contentHeader, "application/json") {
		return nil, fmt.Errorf("%s has not a JSON content-type", uri)
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Wrap(err, fmt.Sprintf("server response error (%s)", response.Status))
	}
	defer response.Body.Close()
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not read JSON response")
	}
	return data, nil
}
