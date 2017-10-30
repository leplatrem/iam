package doorman

import (
	"fmt"
	"net/http"

	auth0 "github.com/auth0-community/go-auth0"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// JWTValidator is the interface in charge of extracting JWT claims from request.
type JWTValidator interface {
	Initialize() error
	ExtractClaims(*http.Request) (*jwt.Claims, error)
}

// Auth0Validator is the implementation of JWTValidator for Auth0.
type Auth0Validator struct {
	Issuer    string
	validator *auth0.JWTValidator
}

// Initialize will fetch Auth0 public keys and instantiate a validator.
func (v *Auth0Validator) Initialize() error {
	jwksURI := fmt.Sprintf("%s.well-known/jwks.json", v.Issuer)
	log.Infof("JWT keys: %s", jwksURI)

	// Will check audience only when request comes in, leave empty for now.
	audience := []string{}

	client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: jwksURI})
	config := auth0.NewConfiguration(client, audience, v.Issuer, jose.RS256)
	v.validator = auth0.NewValidator(config)
	return nil
}

// ExtractClaims validates the token from request, and returns the JWT claims.
func (v *Auth0Validator) ExtractClaims(request *http.Request) (*jwt.Claims, error) {
	token, err := v.validator.ValidateRequest(request)
	claims := jwt.Claims{}
	err = v.validator.Claims(request, token, &claims)
	if err != nil {
		return nil, err
	}
	// XXX: verify API ID / audience here.
	//if !claims.Audience.Contains(v) {
	// 	return ErrInvalidAudience
	// }
	return &claims, nil
}

// VerifyJWTMiddleware makes sure a valid JWT is provided.
func VerifyJWTMiddleware(validator JWTValidator) gin.HandlerFunc {
	validator.Initialize()

	return func(c *gin.Context) {
		claims, err := validator.ExtractClaims(c.Request)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": err.Error(),
			})
			return
		}

		c.Set("JWT", claims)

		c.Next()
	}
}
