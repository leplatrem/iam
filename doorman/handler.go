package doorman

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupRoutes adds doorman views to query the policies.
func SetupRoutes(r *gin.Engine, doorman Doorman) {
	r.Use(ContextMiddleware(doorman))

	a := r.Group("")
	a.Use(AuthnMiddleware(doorman))
	a.POST("/allowed", allowedHandler)
}

func allowedHandler(c *gin.Context) {
	if c.Request.ContentLength == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Missing body",
		})
		return
	}

	var r Request
	if err := c.BindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
		return
	}

	// Is authentication verification enable for this service?
	// If disabled (like in tests), principals can be posted in JSON.
	principals, ok := c.Get(PrincipalsContextKey)
	if ok {
		if len(r.Principals) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "cannot submit principals with authentication enabled",
			})
			return
		}
		r.Principals = principals.(Principals)
	} else {
		if len(r.Principals) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "missing principals",
			})
			return
		}
	}

	doorman := c.MustGet(DoormanContextKey).(Doorman)
	service := c.Request.Header.Get("Origin")

	// Expand principals with local ones.
	r.Principals = doorman.ExpandPrincipals(service, r.Principals)
	// Expand principals with specified roles.
	r.Principals = append(r.Principals, r.Roles()...)

	// Force some context values (for Audit logger mainly)
	// XXX: using the context field to pass custom values on *ladon.Request
	// for audit logging is not very elegant.
	if r.Context == nil {
		r.Context = Context{}
	}
	r.Context["remoteIP"] = c.Request.RemoteAddr
	r.Context["_service"] = service
	r.Context["_principals"] = r.Principals

	allowed := doorman.IsAllowed(service, &r)

	c.JSON(http.StatusOK, gin.H{
		"allowed":    allowed,
		"principals": r.Principals,
	})
}
