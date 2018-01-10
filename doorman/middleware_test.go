package doorman

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestMain defined in doorman_test.go
// func TestMain(m *testing.M) {}

type TestValidator struct {
	mock.Mock
}

func (v *TestValidator) Initialize() error {
	args := v.Called()
	return args.Error(0)
}
func (v *TestValidator) ValidateRequest(request *http.Request) (*Claims, error) {
	args := v.Called(request)
	return args.Get(0).(*Claims), args.Error(1)
}

func TestJWTMiddleware(t *testing.T) {
	doorman := NewDefaultLadon()
	handler := VerifyJWTMiddleware(doorman)

	audience := "https://some.api.com"

	// Associate a fake JWT validator to this issuer.
	v := &TestValidator{}
	doorman.jwtValidators[audience] = v

	// Extract claims is ran on every request.
	claims := &Claims{
		Subject:  "ldap|user",
		Audience: []string{audience},
		Email:    "user@corp.com",
		Groups:   []string{"Employee", "Admins"},
	}
	v.On("ValidateRequest", mock.Anything).Return(claims, nil)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("GET", "/get", nil)
	c.Request.Header.Set("Origin", audience)

	handler(c)

	v.AssertCalled(t, "ValidateRequest", c.Request)

	// Principals are set in context.
	principals, ok := c.Get(PrincipalsContextKey)
	require.True(t, ok)
	assert.Equal(t, principals, Principals{
		"userid:ldap|user",
		"email:user@corp.com",
		"group:Employee",
		"group:Admins",
	})

	c, _ = gin.CreateTestContext(httptest.NewRecorder())

	// Missing origin.
	c.Request, _ = http.NewRequest("GET", "/get", nil)
	handler(c)
	_, ok = c.Get(PrincipalsContextKey)
	assert.False(t, ok)

	// Wrong origin.
	c.Request, _ = http.NewRequest("GET", "/get", nil)
	c.Request.Header.Set("Origin", "https://wrong.com")
	handler(c)
	_, ok = c.Get(PrincipalsContextKey)
	assert.False(t, ok)

	// JWT not configured for this origin.
	doorman.jwtValidators["https://open"] = nil

	c.Request, _ = http.NewRequest("GET", "/get", nil)
	c.Request.Header.Set("Origin", "https://open")
	handler(c)
	_, ok = c.Get(PrincipalsContextKey)
	assert.False(t, ok)

	// Missing attributes in JWT Payload
	claims = &Claims{
		Subject:  "ldap|user",
		Audience: []string{audience},
	}
	v = &TestValidator{}
	v.On("ValidateRequest", mock.Anything).Return(claims, nil)
	doorman.jwtValidators[audience] = v
	c, _ = gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("GET", "/get", nil)
	c.Request.Header.Set("Origin", audience)
	handler(c)
	principals, _ = c.Get(PrincipalsContextKey)
	assert.Equal(t, Principals{"userid:ldap|user"}, principals)

	// Audience mismatch origin
	claims = &Claims{
		Subject:  "ldap|user",
		Audience: []string{"http://some.other.api"},
	}
	v = &TestValidator{}
	v.On("ValidateRequest", mock.Anything).Return(claims, nil)
	doorman.jwtValidators[audience] = v
	c, _ = gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("GET", "/get", nil)
	c.Request.Header.Set("Origin", audience)
	handler(c)
	_, ok = c.Get(PrincipalsContextKey)
	assert.False(t, ok)
}
