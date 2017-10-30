package doorman

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	jwt "gopkg.in/square/go-jose.v2/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// TestMain defined in doorman_test.go
// func TestMain(m *testing.M) {}

func TestExtractClaims(t *testing.T) {
	var err error

	validator := Auth0Validator{"https://minimal-demo-iam.auth0.com/", nil}
	validator.Initialize()

	r, _ := http.NewRequest("GET", "/", nil)

	_, err = validator.ExtractClaims(r)
	require.NotNil(t, err)
	assert.Equal(t, "Token not found", err.Error())

	r.Header.Set("Authorization", "Basic abc")
	_, err = validator.ExtractClaims(r)
	require.NotNil(t, err)
	assert.Equal(t, "Token not found", err.Error())

	r.Header.Set("Authorization", "Bearer abc zy")
	_, err = validator.ExtractClaims(r)
	require.NotNil(t, err)
	assert.Equal(t, "square/go-jose: compact JWS format must have three parts", err.Error())

	r.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5EZzFOemczTlRFeVEwVTFNMEZCTnpCQlFqa3hOVVk1UTBVMU9USXpOalEzUXpVek5UWkRNQSJ9.eyJpc3MiOiJodHRwczovL21pbmltYWwtZGVtby1pYW0uYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTA0MTAyMzA2MTExMzUwNTc2NjI4IiwiYXVkIjpbImh0dHA6Ly9taW5pbWFsLWRlbW8taWFtLmxvY2FsaG9zdDo4MDAwIiwiaHR0cHM6Ly9taW5pbWFsLWRlbW8taWFtLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJpYXQiOjE1MDY2MDQzMTMsImV4cCI6MTUwNjYxMTUxMywiYXpwIjoiV1lSWXBKeVM1RG5EeXhMVFJWR0NRR0NXR28yS05RTE4iLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIn0.JmfQajLJ6UMU8sGwv-4FyN0hAPjlLnixoVXAJwn9-985Y4jnMNiG22RWAk5qsdhxVKjIsyQFGA2oHuKELfcrI-LEHX3dxePxx9jSGUdC1wzk3p2q3YCRwIV3DUFEtBVeml8gdB9V7tVBE6XDivfq7RphiC8c5zz28_vlB2iPPaAwfucJLc1d5t83xlBaSYU9-hWDet3HbgjQg4zvFat6C2-CuKkCuQEG92tsOdoD8RIJtlWmLiMVUhCFgr3pGa7_ZNiKmMFkgZiDsX2qqD107CfOLG3IutcLGCqlpHxOuVltGZNp3QCXwtjIoZSV-5IXssXKLYuz-75GpfEAmUB5fg")
	claims, err := validator.ExtractClaims(r)
	require.Nil(t, err)
	assert.Equal(t, "google-oauth2|104102306111350576628", claims.Subject)
}


type TestValidator struct {
  mock.Mock
}
func (v *TestValidator) Initialize() error {
	args := v.Called()
	return args.Error(0)
}
func (v *TestValidator) ExtractClaims(request *http.Request) (*jwt.Claims, error) {
	args := v.Called(request)
	return args.Get(0).(*jwt.Claims), args.Error(1)
}

func TestJWTMiddleware(t *testing.T) {
	v := &TestValidator{}
	v.On("Initialize").Return(nil)
	handler := VerifyJWTMiddleware(v)

	// Initialize() is called on server startup.
	v.AssertCalled(t, "Initialize")

	// Extract claims is ran on every request.
	claims := &jwt.Claims{
		Subject: "ldap|user",
	}
	v.On("ExtractClaims", mock.Anything).Return(claims, nil)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("GET", "/get", nil)

	handler(c)

	v.AssertCalled(t, "ExtractClaims", c.Request)

	// JWT claims are set in context.
	payloadJWT, ok := c.Get("JWT")
	require.True(t, ok)
	assert.Equal(t, "ldap|user", payloadJWT.(*jwt.Claims).Subject)
}
