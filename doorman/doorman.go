package doorman

import (
	"fmt"

	"github.com/mozilla/doorman/authn"
)

// Tags map tag names to principals.
type Tags map[string]Principals

// Condition either do or do not fulfill an access request.
type Condition struct {
	Type    string
	Options map[string]interface{}
}

// Conditions is a collection of conditions.
type Conditions map[string]Condition

// Policy represents an access control.
type Policy struct {
	ID          string
	Description string
	Principals  []string
	Effect      string
	Resources   []string
	Actions     []string
	Conditions  Conditions
}

// Policies is a collection of policies.
type Policies []Policy

// ServiceConfig represents the policies file content.
type ServiceConfig struct {
	Source    string
	Service   string
	JWTIssuer string `yaml:"jwtIssuer"`
	Tags      Tags
	Policies  Policies
}

// GetTags returns the tags principals for the ones specified.
func (c *ServiceConfig) GetTags(principals Principals) Principals {
	result := Principals{}
	for tag, members := range c.Tags {
		for _, member := range members {
			for _, principal := range principals {
				if principal == member {
					prefixed := fmt.Sprintf("tag:%s", tag)
					result = append(result, prefixed)
				}
			}
		}
	}
	return result
}

// ServicesConfig is the whole set of policies files.
type ServicesConfig []ServiceConfig

// Context is used as request's context.
type Context map[string]interface{}

// Principals represent a user (userid, email, tags, ...)
type Principals []string

// Request is the authorization request.
type Request struct {
	// Principals are strings that identify the user.
	Principals Principals
	// Resource is the resource that access is requested to.
	Resource string
	// Action is the action that is requested on the resource.
	Action string
	// Context is the request's environmental context.
	Context Context
}

// Roles reads the roles from request context and returns the principals.
func (r *Request) Roles() Principals {
	p := Principals{}
	if roles, ok := r.Context["roles"]; ok {
		if rolesI, ok := roles.([]interface{}); ok {
			for _, roleI := range rolesI {
				if role, ok := roleI.(string); ok {
					prefixed := fmt.Sprintf("role:%s", role)
					p = append(p, prefixed)
				}
			}
		}
	}
	return p
}

// Doorman is the backend in charge of checking requests against policies.
type Doorman interface {
	// LoadPolicies is responsible for loading the services configuration into memory.
	LoadPolicies(configs ServicesConfig) error
	// JWTValidator
	JWTValidator(service string) (authn.JWTValidator, error)
	// ExpandPrincipals looks up and add extra principals to the ones specified.
	ExpandPrincipals(service string, principals Principals) Principals
	// IsAllowed is responsible for deciding if the specified authorization is allowed for the specified service.
	IsAllowed(service string, request *Request) bool
}
