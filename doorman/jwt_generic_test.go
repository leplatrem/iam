package doorman

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchOpenIDConfiguration(t *testing.T) {
	// Not available
	_, err := fetchOpenIDConfiguration("https://missing.com")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	// Bad JSON
	_, err = fetchOpenIDConfiguration("https://mozilla.org")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid character '<'")
	// Good one
	config, err := fetchOpenIDConfiguration("https://auth.mozilla.auth0.com/")
	require.Nil(t, err)
	assert.Contains(t, config.JWKSUri, ".well-known/jwks.json")
}

func TestDownloadKeys(t *testing.T) {
	// Bad URL
	_, err := downloadKeys("https://missing.com")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	// Bad content-type
	_, err = downloadKeys("https://mozilla.org")
	require.NotNil(t, err)
	assert.Equal(t, err.Error(), "JWKS endpoint has not JSON content-type")

	// Missing Keys attribute
	_, err = downloadKeys("https://auth.mozilla.auth0.com/.well-known/openid-configuration")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "No key found at")

	// Good one
	keys, err := downloadKeys("https://auth.mozilla.auth0.com/.well-known/jwks.json")
	require.Nil(t, err)
	assert.Equal(t, 1, len(keys.Keys))
}

func TestFromHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)

	_, err := fromHeader(r)
	require.NotNil(t, err)
	assert.Equal(t, "Token not found", err.Error())

	r.Header.Set("Authorization", "Basic abc")
	_, err = fromHeader(r)
	require.NotNil(t, err)
	assert.Equal(t, "Token not found", err.Error())

	r.Header.Set("Authorization", "Bearer abc zy")
	_, err = fromHeader(r)
	require.NotNil(t, err)
	assert.Equal(t, "square/go-jose: compact JWS format must have three parts", err.Error())
}

func TestValidateRequest(t *testing.T) {
	goodJWT := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1rWkRORGN5UmtOR1JURkROamxCTmpaRk9FSkJOMFpCTnpKQlFUTkVNRGhDTUVFd05rRkdPQSJ9.eyJuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsImdpdmVuX25hbWUiOiJNYXRoaWV1IiwiZmFtaWx5X25hbWUiOiJMZXBsYXRyZSIsIm5pY2tuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci85NzE5N2YwMTFhM2Q5ZDQ5NGFlODEzNTY2ZjI0Njc5YT9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRm1sLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDE3LTEyLTA0VDE1OjUyOjMzLjc2MVoiLCJpc3MiOiJodHRwczovL2F1dGgubW96aWxsYS5hdXRoMC5jb20vIiwic3ViIjoiYWR8TW96aWxsYS1MREFQfG1sZXBsYXRyZSIsImF1ZCI6IlNMb2NmN1NhMWliZDVHTkpNTXFPNTM5ZzdjS3ZXQk9JIiwiZXhwIjoxNTEzMDA3NTcwLCJpYXQiOjE1MTI0MDI3NzAsImFtciI6WyJtZmEiXSwiYWNyIjoiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9wYXBlL3BvbGljaWVzLzIwMDcvMDYvbXVsdGktZmFjdG9yIiwibm9uY2UiOiJQRkxyLmxtYWhCQWRYaEVSWm0zYVFxc2ZuWjhwcWt0VSIsImF0X2hhc2giOiJTN0Rha1BrZVA0Tnk4SWpTOGxnMHJBIiwiaHR0cHM6Ly9zc28ubW96aWxsYS5jb20vY2xhaW0vZ3JvdXBzIjpbIkludHJhbmV0V2lraSIsIlN0YXRzRGFzaGJvYXJkIiwicGhvbmVib29rX2FjY2VzcyIsImNvcnAtdnBuIiwidnBuX2NvcnAiLCJ2cG5fZGVmYXVsdCIsIkNsb3Vkc2VydmljZXNXaWtpIiwidGVhbV9tb2NvIiwiaXJjY2xvdWQiLCJva3RhX21mYSIsImNsb3Vkc2VydmljZXNfZGV2IiwidnBuX2tpbnRvMV9zdGFnZSIsInZwbl9raW50bzFfcHJvZCIsImVnZW5jaWFfZGUiLCJhY3RpdmVfc2NtX2xldmVsXzEiLCJhbGxfc2NtX2xldmVsXzEiLCJzZXJ2aWNlX3NhZmFyaWJvb2tzIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL2VtYWlscyI6WyJtbGVwbGF0cmVAbW96aWxsYS5jb20iLCJtYXRoaWV1QG1vemlsbGEuY29tIiwibWF0aGlldS5sZXBsYXRyZUBtb3ppbGxhLmNvbSJdLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9kbiI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9vcmdhbml6YXRpb25Vbml0cyI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9lbWFpbF9hbGlhc2VzIjpbIm1hdGhpZXVAbW96aWxsYS5jb20iLCJtYXRoaWV1LmxlcGxhdHJlQG1vemlsbGEuY29tIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL19IUkRhdGEiOnsicGxhY2Vob2xkZXIiOiJlbXB0eSJ9fQ.MK3Z1Nj15MfbM2TcO4FWVTTYPqAbUhL26pYOFa92mPnEUR2W_oJhwoZ8Vwq7dJcvTZfPq-aZKBnqHoPHHYlQbtaqfflhHmY9iRH0aPlxLQed_WVem4YqMn9xw0az4xHnf0UlzLU58kI97bqUFvvzs0fg_OTdDdO3owVUcaZrG8-xalCqQGQqwTfiH514gxeZ_Ki6610HSVDvpPvmODWPz87IDdgS6WkyM-SyAc3aYukP38aqRo-PUjEdpGbOtV_T_W2x8A3yQDxu0Bcq0WJz-FUEu2BHq1Vn6rmLm7BVYjDD6rYseusp8M0bvTfvXA-9OhJWGAAh6KrN9fnw7r30LQ"
	extractor := &mozillaClaimExtractor{}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+goodJWT)

	// Fail to fetch JWKS
	validator := jwtGenericValidator{
		Issuer:         "https://perlinpimpin.com",
		ClaimExtractor: extractor,
	}
	_, err := validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "no such host")

	validator = jwtGenericValidator{
		Issuer:         "https://auth.mozilla.auth0.com/",
		ClaimExtractor: extractor,
	}

	// Cannot extract JWT
	r.Header.Set("Authorization", "Bearer abc")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "compact JWS format must have three parts")

	// Unknown public key
	r.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9.abc.123")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "No JWT key with id \"abc\"")

	// Bad signature
	r.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1rWkRORGN5UmtOR1JURkROamxCTmpaRk9FSkJOMFpCTnpKQlFUTkVNRGhDTUVFd05rRkdPQSJ9.eyJuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsImdpdmVuX25hbWUiOiJNYXRoaWV1IiwiZmFtaWx5X25hbWUiOiJMZXBsYXRyZSIsIm5pY2tuYW1lIjoiTWF0aGlldSBMZXBsYXRyZSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci85NzE5N2YwMTFhM2Q5ZDQ5NGFlODEzNTY2ZjI0Njc5YT9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRm1sLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDE3LTEyLTA0VDE1OjUyOjMzLjc2MVoiLCJpc3MiOiJodHRwczovL2F1dGgubW96aWxsYS5hdXRoMC5jb20vIiwic3ViIjoiYWR8TW96aWxsYS1MREFQfG1sZXBsYXRyZSIsImF1ZCI6IlNMb2NmN1NhMWliZDVHTkpNTXFPNTM5ZzdjS3ZXQk9JIiwiZXhwIjoxNTEzMDA3NTcwLCJpYXQiOjE1MTI0MDI3NzAsImFtciI6WyJtZmEiXSwiYWNyIjoiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9wYXBlL3BvbGljaWVzLzIwMDcvMDYvbXVsdGktZmFjdG9yIiwibm9uY2UiOiJQRkxyLmxtYWhCQWRYaEVSWm0zYVFxc2ZuWjhwcWt0VSIsImF0X2hhc2giOiJTN0Rha1BrZVA0Tnk4SWpTOGxnMHJBIiwiaHR0cHM6Ly9zc28ubW96aWxsYS5jb20vY2xhaW0vZ3JvdXBzIjpbIkludHJhbmV0V2lraSIsIlN0YXRzRGFzaGJvYXJkIiwicGhvbmVib29rX2FjY2VzcyIsImNvcnAtdnBuIiwidnBuX2NvcnAiLCJ2cG5fZGVmYXVsdCIsIkNsb3Vkc2VydmljZXNXaWtpIiwidGVhbV9tb2NvIiwiaXJjY2xvdWQiLCJva3RhX21mYSIsImNsb3Vkc2VydmljZXNfZGV2IiwidnBuX2tpbnRvMV9zdGFnZSIsInZwbl9raW50bzFfcHJvZCIsImVnZW5jaWFfZGUiLCJhY3RpdmVfc2NtX2xldmVsXzEiLCJhbGxfc2NtX2xldmVsXzEiLCJzZXJ2aWNlX3NhZmFyaWJvb2tzIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL2VtYWlscyI6WyJtbGVwbGF0cmVAbW96aWxsYS5jb20iLCJtYXRoaWV1QG1vemlsbGEuY29tIiwibWF0aGlldS5sZXBsYXRyZUBtb3ppbGxhLmNvbSJdLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9kbiI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9vcmdhbml6YXRpb25Vbml0cyI6Im1haWw9bWxlcGxhdHJlQG1vemlsbGEuY29tLG89Y29tLGRjPW1vemlsbGEiLCJodHRwczovL3Nzby5tb3ppbGxhLmNvbS9jbGFpbS9lbWFpbF9hbGlhc2VzIjpbIm1hdGhpZXVAbW96aWxsYS5jb20iLCJtYXRoaWV1LmxlcGxhdHJlQG1vemlsbGEuY29tIl0sImh0dHBzOi8vc3NvLm1vemlsbGEuY29tL2NsYWltL19IUkRhdGEiOnsicGxhY2Vob2xkZXIiOiJlbXB0eSJ9fQ.123")
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "error in cryptographic primitive")

	// Invalid claims
	r.Header.Set("Authorization", "Bearer "+goodJWT)
	_, err = validator.ValidateRequest(r)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "validation failed, token is expired")
}
