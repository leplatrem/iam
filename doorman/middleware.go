package doorman

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mozilla/doorman/authn"
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

// AuthnMiddleware relies on the authenticator if authentication was enabled
// for the origin.
func AuthnMiddleware(doorman Doorman) gin.HandlerFunc {
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

		// Check if authentication was configured for this service.
		authenticator, err := doorman.Authenticator(origin)
		if err != nil {
			// Unknown service
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "Unknown service specified in `Origin`",
			})
			return
		}
		// No authenticator configured for this service.
		if authenticator == nil {
			// Do nothing. The principals list will be empty.
			c.Next()
			return
		}

		// Validate authentication.
		userInfo, err := authenticator.ValidateRequest(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": err.Error(),
			})
			return
		}

		principals := buildPrincipals(userInfo)

		c.Set(PrincipalsContextKey, principals)

		c.Next()
	}
}

func buildPrincipals(userInfo *authn.UserInfo) Principals {
	// Extract principals from JWT
	var principals Principals
	userid := fmt.Sprintf("userid:%s", userInfo.ID)
	principals = append(principals, userid)

	// Main email (no alias)
	if userInfo.Email != "" {
		email := fmt.Sprintf("email:%s", userInfo.Email)
		principals = append(principals, email)
	}

	// Groups
	for _, group := range userInfo.Groups {
		prefixed := fmt.Sprintf("group:%s", group)
		principals = append(principals, prefixed)
	}
	return principals
}
