package authn

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchOpenIDConfiguration(t *testing.T) {
	// Not available
	validator := newOpenIDAuthenticator("https://missing.com")
	_, err := validator.config()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	// Bad content-type
	validator = newOpenIDAuthenticator("https://mozilla.org")
	_, err = validator.config()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "has not a JSON content-type")
	// Bad JSON
	validator = newOpenIDAuthenticator("https://mozilla.org")
	validator.cache.Set("config:https://mozilla.org", []byte("<html>"))
	_, err = validator.config()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid character '<'")
	// Missing jwks_uri
	validator = newOpenIDAuthenticator("https://mozilla.org")
	validator.cache.Set("config:https://mozilla.org", []byte("{}"))
	_, err = validator.config()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "no jwks_uri attribute in OpenID configuration")
	// Good one
	validator = newOpenIDAuthenticator("https://auth.mozilla.auth0.com/")
	config, err := validator.config()
	require.Nil(t, err)
	assert.Contains(t, config.JWKSUri, ".well-known/jwks.json")
}

func TestDownloadKeys(t *testing.T) {
	validator := newOpenIDAuthenticator("https://fake.com")
	// Bad URL
	validator.cache.Set("config:https://fake.com",
		[]byte("{\"jwks_uri\":\"http://z\"}"))
	_, err := validator.jwks()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "no such host")
	// Bad content-type
	validator.cache.Set("config:https://fake.com",
		[]byte("{\"jwks_uri\":\"https://httpbin.org/image/png\"}"))
	_, err = validator.jwks()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "has not a JSON content-type")
	// Bad status
	validator.cache.Set("config:https://fake.com",
		[]byte("{\"jwks_uri\":\"https://httpbin.org/image\"}"))
	_, err = validator.jwks()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "server response error")
	// Bad JSON
	validator.cache.Set("jwks:https://fake.com", []byte("<html>"))
	_, err = validator.jwks()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid character '<'")
	// Missing Keys attribute
	validator.cache.Set("jwks:https://fake.com", []byte("{}"))
	_, err = validator.jwks()
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "no JWKS found")
	// Good one
	validator = newOpenIDAuthenticator("https://auth.mozilla.auth0.com")
	keys, err := validator.jwks()
	require.Nil(t, err)
	assert.Equal(t, 1, len(keys.Keys))
}

func TestFromHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)

	_, err := fromHeader(r)
	require.NotNil(t, err)
	assert.Equal(t, "token not found", err.Error())

	r.Header.Set("Authorization", "Basic abc")
	_, err = fromHeader(r)
	require.NotNil(t, err)
	assert.Equal(t, "token not found", err.Error())

	r.Header.Set("Authorization", "Bearer abc zy")
	v, err := fromHeader(r)
	require.Nil(t, err)
	assert.Equal(t, v, "abc zy")
}

func TestValidateRequestAccessToken(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)

	validator := newOpenIDAuthenticator("https://stub")

	// No header.
	_, err := validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "token not found")
	// Bad config.
	validator.cache.Set("config:https://stub", []byte("<>"))
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "token not found")
	// Good one from cache
	r.Header.Set("Authorization", "Bearer abc")
	validator.cache.Set("userinfo:abc", []byte("{\"sub\":\"mary\"}"))
	info, err := validator.ValidateRequest(r)
	require.Nil(t, err)
	assert.Equal(t, info.ID, "mary")
}

func TestValidateRequestIDToken(t *testing.T) {
	goodJWT := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1rWkRORGN5UmtOR1JURkROamxCTmpaRk9FSkJOMFpCTnpKQlFUTkVNRGhDTUVFd05rRkdPQSJ9.eyJuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsImdpdmVuX25hbWUiOiJNYXRoaWV1IiwiZmFtaWx5X25hbWUiOiJMZXBsYXRyZSIsIm5pY2tuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci85NzE5N2YwMTFhM2Q5ZDQ5NGFlODEzNTY2ZjI0Njc5YT9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRm1sLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDE3LTEyLTA0VDE1OjUyOjMzLjc2MVoiLCJpc3MiOiJodHRwczovL2F1dGgubW96aWxsYS5hdXRoMC5jb20vIiwic3ViIjoiYWR8TW96aWxsYS1MREFQfG1sZXBsYXRyZSIsImF1ZCI6IlNMb2NmN1NhMWliZDVHTkpNTXFPNTM5ZzdjS3ZXQk9JIiwiZXhwIjoxNTEzMDA3NTcwLCJpYXQiOjE1MTI0MDI3NzAsImFtciI6WyJtZmEiXSwiYWNyIjoiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9wYXBlL3BvbGljaWVzLzIwMDcvMDYvbXVsdGktZmFjdG9yIiwibm9uY2UiOiJQRkxyLmxtYWhCQWRYaEVSWm0zYVFxc2ZuWjhwcWt0VSIsImF0X2hhc2giOiJTN0Rha1BrZVA0Tnk4SWpTOGxnMHJBIiwiaHR0cHM6Ly9zc28ubW96aWxsYS5jb20vY2xhaW0vZ3JvdXBzIjpbIkludHJhbmV0V2lraSIsIlN0YXRzRGFzaGJvYXJkIiwicGhvbmVib29rX2FjY2VzcyIsImNvcnAtdnBuIiwidnBuX2NvcnAiLCJ2cG5fZGVmYXVsdCIsIkNsb3Vkc2VydmljZXNXaWtpIiwidGVhbV9tb2NvIiwiaXJjY2xvdWQiLCJva3RhX21mYSIsImNsb3Vkc2VydmljZXNfZGV2IiwidnBuX2tpbnRvMV9zdGFnZSIsInZwbl9raW50bzFfcHJvZCIsImVnZW5jaWFfZGUiLCJhY3RpdmVfc2NtX2xldmVsXzEiLCJhbGxfc2NtX2xldmVsXzEiLCJzZXJ2aWNlX3NhZmFyaWJvb2tzIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL2VtYWlscyI6WyJtbGVwbGF0cmVAbW96aWxsYS5jb20iLCJtYXRoaWV1QG1vemlsbGEuY29tIiwibWF0aGlldS5sZXBsYXRyZUBtb3ppbGxhLmNvbSJdLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9kbiI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9vcmdhbml6YXRpb25Vbml0cyI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9lbWFpbF9hbGlhc2VzIjpbIm1hdGhpZXVAbW96aWxsYS5jb20iLCJtYXRoaWV1LmxlcGxhdHJlQG1vemlsbGEuY29tIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL19IUkRhdGEiOnsicGxhY2Vob2xkZXIiOiJlbXB0eSJ9fQ.MK3Z1Nj15MfbM2TcO4FWVTTYPqAbUhL26pYOFa92mPnEUR2W_oJhwoZ8Vwq7dJcvTZfPq-aZKBnqHoPHHYlQbtaqfflhHmY9iRH0aPlxLQed_WVem4YqMn9xw0az4xHnf0UlzLU58kI97bqUFvvzs0fg_OTdDdO3owVUcaZrG8-xalCqQGQqwTfiH514gxeZ_Ki6610HSVDvpPvmODWPz87IDdgS6WkyM-SyAc3aYukP38aqRo-PUjEdpGbOtV_T_W2x8A3yQDxu0Bcq0WJz-FUEu2BHq1Vn6rmLm7BVYjDD6rYseusp8M0bvTfvXA-9OhJWGAAh6KrN9fnw7r30LQ"
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+goodJWT)

	// Fail to fetch JWKS
	validator := newOpenIDAuthenticator("https://perlinpimpin.com")

	_, err := validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "no such host")

	validator = newOpenIDAuthenticator("https://auth.mozilla.auth0.com/")

	// Cannot extract JWT
	r.Header.Set("Authorization", "Bearer abc")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "compact JWS format must have three parts")

	// Unknown public key
	r.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9.abc.123")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "no JWT key with id \"abc\"")

	// // Invalid algorithm
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")

	// Bad signature
	r.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1rWkRORGN5UmtOR1JURkROamxCTmpaRk9FSkJOMFpCTnpKQlFUTkVNRGhDTUVFd05rRkdPQSJ9.eyJuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsImdpdmVuX25hbWUiOiJNYXRoaWV1IiwiZmFtaWx5X25hbWUiOiJMZXBsYXRyZSIsIm5pY2tuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci85NzE5N2YwMTFhM2Q5ZDQ5NGFlODEzNTY2ZjI0Njc5YT9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRm1sLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDE3LTEyLTA0VDE1OjUyOjMzLjc2MVoiLCJpc3MiOiJodHRwczovL2F1dGgubW96aWxsYS5hdXRoMC5jb20vIiwic3ViIjoiYWR8TW96aWxsYS1MREFQfG1sZXBsYXRyZSIsImF1ZCI6IlNMb2NmN1NhMWliZDVHTkpNTXFPNTM5ZzdjS3ZXQk9JIiwiZXhwIjoxNTEzMDA3NTcwLCJpYXQiOjE1MTI0MDI3NzAsImFtciI6WyJtZmEiXSwiYWNyIjoiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9wYXBlL3BvbGljaWVzLzIwMDcvMDYvbXVsdGktZmFjdG9yIiwibm9uY2UiOiJQRkxyLmxtYWhCQWRYaEVSWm0zYVFxc2ZuWjhwcWt0VSIsImF0X2hhc2giOiJTN0Rha1BrZVA0Tnk4SWpTOGxnMHJBIiwiaHR0cHM6Ly9zc28ubW96aWxsYS5jb20vY2xhaW0vZ3JvdXBzIjpbIkludHJhbmV0V2lraSIsIlN0YXRzRGFzaGJvYXJkIiwicGhvbmVib29rX2FjY2VzcyIsImNvcnAtdnBuIiwidnBuX2NvcnAiLCJ2cG5fZGVmYXVsdCIsIkNsb3Vkc2VydmljZXNXaWtpIiwidGVhbV9tb2NvIiwiaXJjY2xvdWQiLCJva3RhX21mYSIsImNsb3Vkc2VydmljZXNfZGV2IiwidnBuX2tpbnRvMV9zdGFnZSIsInZwbl9raW50bzFfcHJvZCIsImVnZW5jaWFfZGUiLCJhY3RpdmVfc2NtX2xldmVsXzEiLCJhbGxfc2NtX2xldmVsXzEiLCJzZXJ2aWNlX3NhZmFyaWJvb2tzIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL2VtYWlscyI6WyJtbGVwbGF0cmVAbW96aWxsYS5jb20iLCJtYXRoaWV1QG1vemlsbGEuY29tIiwibWF0aGlldS5sZXBsYXRyZUBtb3ppbGxhLmNvbSJdLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9kbiI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9vcmdhbml6YXRpb25Vbml0cyI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9lbWFpbF9hbGlhc2VzIjpbIm1hdGhpZXVAbW96aWxsYS5jb20iLCJtYXRoaWV1LmxlcGxhdHJlQG1vemlsbGEuY29tIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL19IUkRhdGEiOnsicGxhY2Vob2xkZXIiOiJlbXB0eSJ9fQ.123")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "error in cryptographic primitive")

	// Invalid audience
	r.Header.Set("Authorization", "Bearer "+goodJWT)
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "validation failed, invalid audience claim")

	// Valid claims, expired token.
	r.Header.Set("Origin", "SLocf7Sa1ibd5GNJMMqO539g7cKvWBOI")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "validation failed, token is expired")

	// Disable expiration verification.
	validator.envTest = true
	info, err := validator.ValidateRequest(r)
	require.Nil(t, err)
	assert.Equal(t, info.ID, "ad|Mozilla-LDAP|mleplatre")
	assert.Contains(t, info.Groups, "irccloud")
}

func BenchmarkParseKeys(b *testing.B) {
	// Warm cache.
	validator := newOpenIDAuthenticator("https://auth.mozilla.auth0.com")
	validator.jwks()
	b.ResetTimer()
	// Bench parsing of cache bytes into keys objects.
	for i := 0; i < b.N; i++ {
		validator.jwks()
	}
}
