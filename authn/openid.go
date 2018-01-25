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

type openIDAuthenticator struct {
	Issuer             string
	SignatureAlgorithm jose.SignatureAlgorithm
	ClaimExtractor     claimExtractor
	cache              *bigcache.BigCache
	envTest            bool
}

// newOpenIDAuthenticator returns a new instance of a generic JWT validator
// for the specified issuer.
func newOpenIDAuthenticator(issuer string) *openIDAuthenticator {
	cache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(CacheTTL))

	var extractor claimExtractor = defaultExtractor
	if strings.Contains(issuer, "mozilla.auth0.com") {
		extractor = mozillaExtractor
	}
	return &openIDAuthenticator{
		Issuer:             issuer,
		SignatureAlgorithm: jose.RS256,
		ClaimExtractor:     extractor,
		cache:              cache,
		envTest:            false,
	}
}

func (v *openIDAuthenticator) config() (*openIDConfiguration, error) {
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

func (v *openIDAuthenticator) jwks() (*publicKeys, error) {
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

func (v *openIDAuthenticator) ValidateRequest(r *http.Request) (*UserInfo, error) {
	headerValue, err := fromHeader(r)
	if err != nil {
		return nil, err
	}

	if strings.Count(headerValue, ".") == 0 {
		// No dots, could be an access token! Try to fetch user infos.
		userinfo, err := v.FetchUserInfo(headerValue)
		if err == nil {
			return userinfo, nil
		}
	}

	// Consider it an ID Token. It will fail if invalid.
	audience := r.Header.Get("Origin")
	userinfo, err := v.FromJWTPayload(headerValue, audience)
	if err != nil {
		return nil, err
	}
	return userinfo, nil
}

// FetchUserInfo fetches the user profile infos using the specified access token.
// The obtained data is cached using the access token as the cache key.
func (v *openIDAuthenticator) FetchUserInfo(accessToken string) (*UserInfo, error) {
	cacheKey := "userinfo:" + accessToken

	data, err := v.cache.Get(cacheKey)
	// Cache is empty or expired: fetch again.
	if err != nil {
		config, err := v.config()
		if err != nil {
			return nil, err
		}
		uri := config.UserInfoEndpoint
		data, err = downloadJSON(uri, http.Header{
			"Authorization": []string{"Bearer " + accessToken},
		})
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("could not fetch userinfo from %s", uri))
		}
		v.cache.Set(cacheKey, data)
	}

	userinfo, err := v.ClaimExtractor.Extract(data)
	if err != nil {
		return nil, err
	}

	return userinfo, nil
}

func (v *openIDAuthenticator) FromJWTPayload(idToken string, audience string) (*UserInfo, error) {
	// 1. Instanciate JSON Web Token
	token, err := jwt.ParseSigned(idToken)
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
	expected := jwt.Expected{
		Issuer:   v.Issuer,
		Audience: jwt.Audience{audience},
	}
	expected = expected.WithTime(time.Now())
	err = jwtClaims.Validate(expected)
	if err != nil && !v.envTest { // flag for unit tests.
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
	userinfo, err := v.ClaimExtractor.Extract(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract userinfo from JWT payload")
	}
	return userinfo, nil
}

// fromHeader reads the authorization header value.
func fromHeader(r *http.Request) (string, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		return authorizationHeader[7:], nil
	}
	return "", fmt.Errorf("token not found")
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
		return nil, fmt.Errorf("server response error (%s)", response.Status)
	}
	defer response.Body.Close()
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not read JSON response")
	}
	return data, nil
}
