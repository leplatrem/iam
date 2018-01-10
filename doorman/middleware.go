package doorman

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DoormanContextKey is the Gin context key to obtain the *Doorman instance.
const DoormanContextKey string = "doorman"

// PrincipalsContextKey is the Gin context key to obtain the current user principals.
const PrincipalsContextKey string = "principals"

// ContextMiddleware adds the Doorman instance to the Gin context.
func ContextMiddleware(doorman Doorman) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(DoormanContextKey, doorman)
		c.Next()
	}
}

// VerifyJWTMiddleware makes sure a valid JWT is provided.
func VerifyJWTMiddleware(doorman Doorman) gin.HandlerFunc {
	return func(c *gin.Context) {
		// The service requesting must send its location. It will be compared
		// with the services defined in policies files.
		// XXX: The Origin request header might not be the best choice.
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Missing `Origin` request header",
			})
			return
		}

		// Check if JWT verification was configured for this service.
		validator, err := doorman.JWTValidator(origin)
		if err != nil {
			// Unknown service
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Unknown service specified in `Origin`",
			})
			return
		}
		// No JWT validator configured for this service.
		if validator == nil {
			// Do nothing. The principals list will be empty.
			c.Next()
			return
		}

		// Verify the JWT
		claims, err := validator.ValidateRequest(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": err.Error(),
			})
			return
		}

		// Check that origin matches audiences from JWT token .
		if !claims.Audience.Contains(origin) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "Invalid audience claim",
			})
			return
		}

		principals := extractPrincipals(claims)

		c.Set(PrincipalsContextKey, principals)

		c.Next()
	}
}

func extractPrincipals(claims *Claims) Principals {
	// Extract principals from JWT
	var principals Principals
	userid := fmt.Sprintf("userid:%s", claims.Subject)
	principals = append(principals, userid)

	// Main email (no alias)
	if claims.Email != "" {
		email := fmt.Sprintf("email:%s", claims.Email)
		principals = append(principals, email)
	}

	// Groups
	for _, group := range claims.Groups {
		prefixed := fmt.Sprintf("group:%s", group)
		principals = append(principals, prefixed)
	}
	return principals
}
