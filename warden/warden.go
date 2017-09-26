package warden

import (
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/ory/ladon"
	manager "github.com/ory/ladon/manager/memory"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// ContextKey is the Gin context key to obtain the *ladon.Ladon instance.
const ContextKey string = "warden"

// LadonMiddleware adds the ladon.Ladon instance to the Gin context.
func LadonMiddleware(warden *ladon.Ladon) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ContextKey, warden)
		c.Next()
	}
}

// LoadPolicies reads policies from the YAML file.
func LoadPolicies(warden *ladon.Ladon, filename string) error {
	yamlData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var policies []*ladon.DefaultPolicy

	if err := yaml.Unmarshal(yamlData, &policies); err != nil {
		return err
	}

	if len(policies) == 0 {
		log.Warning("No policies found.")
	}

	for _, pol := range policies {
		log.Info("Load policy ", pol.GetID()+": ", pol.GetDescription())
		err := warden.Manager.Create(pol)
		if err != nil {
			return err
		}
	}

	return nil
}

// SetupRoutes adds warden views to query the policies.
func SetupRoutes(r *gin.Engine) {
	warden := &ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}

	policiesFile := os.Getenv("POLICIES_FILE")
	if policiesFile == "" {
		// Look in current working directory.
		here, _ := os.Getwd()
		policiesFile = filepath.Join(here, "policies.yaml")
	}
	if err := LoadPolicies(warden, policiesFile); err != nil {
		log.Fatal(err.Error())
	}

	r.Use(LadonMiddleware(warden))
	r.POST("/allowed", allowedHandler)
}

func allowedHandler(c *gin.Context) {
	if c.Request.ContentLength == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Missing body",
		})
		return
	}

	warden := c.MustGet(ContextKey).(*ladon.Ladon)

	var accessRequest ladon.Request
	if err := c.BindJSON(&accessRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
		return
	}

	err := warden.IsAllowed(&accessRequest)
	allowed := (err == nil)

	// Show some debug information about matched policy.
	if allowed && gin.Mode() != gin.ReleaseMode {
		policies, _ := warden.Manager.FindRequestCandidates(&accessRequest)
		matched := policies[0]
		log.Debug("Policy matched ", matched.GetID()+": ", matched.GetDescription())
	}

	c.JSON(http.StatusOK, gin.H{
		"allowed": allowed,
	})
}
