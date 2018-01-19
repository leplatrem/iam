package doorman

import (
	"encoding/json"
	"fmt"

	"github.com/ory/ladon"
	manager "github.com/ory/ladon/manager/memory"
	log "github.com/sirupsen/logrus"

	"github.com/mozilla/doorman/authn"
)

const maxInt int64 = 1<<63 - 1

// LadonDoorman is the backend in charge of checking requests against policies.
type LadonDoorman struct {
	_auditLogger *auditLogger

	services      map[string]ServiceConfig
	ladons        map[string]*ladon.Ladon
	jwtValidators map[string]authn.JWTValidator
}

// NewDefaultLadon instantiates a new doorman.
func NewDefaultLadon() *LadonDoorman {
	w := &LadonDoorman{
		services:      map[string]ServiceConfig{},
		ladons:        map[string]*ladon.Ladon{},
		jwtValidators: map[string]authn.JWTValidator{},
	}
	return w
}

func (doorman *LadonDoorman) auditLogger() *auditLogger {
	if doorman._auditLogger == nil {
		doorman._auditLogger = newAuditLogger()
	}
	return doorman._auditLogger
}

// LoadPolicies instantiates Ladon objects from doorman's.
func (doorman *LadonDoorman) LoadPolicies(configs ServicesConfig) error {
	// First, load each configuration file.
	newLadons := map[string]*ladon.Ladon{}
	newJWTValidators := map[string]authn.JWTValidator{}
	newConfigs := map[string]ServiceConfig{}

	for _, config := range configs {
		_, exists := newConfigs[config.Service]
		if exists {
			return fmt.Errorf("duplicated service %q (source %q)", config.Service, config.Source)
		}

		if config.JWTIssuer != "" {
			log.Infof("Enable JWT validation from %q", config.JWTIssuer)
			v, err := authn.NewJWTValidator(config.JWTIssuer)
			if err != nil {
				return err
			}
			newJWTValidators[config.Service] = v
		} else {
			log.Warningf("No JWT verification for %q.", config.Service)
		}

		newLadons[config.Service] = &ladon.Ladon{
			Manager:     manager.NewMemoryManager(),
			AuditLogger: doorman.auditLogger(),
		}
		for _, pol := range config.Policies {
			log.Debugf("Load policy %q: %s", pol.ID, pol.Description)

			var conditions = ladon.Conditions{}
			for field, cond := range pol.Conditions {
				factory, found := ladon.ConditionFactories[cond.Type]
				if !found {
					return fmt.Errorf("unknown condition type %s", cond.Type)
				}
				c := factory()
				if len(cond.Options) > 0 {
					// Leverage Ladon JSON unmarshall code to instantiate conditions.
					str, _ := json.Marshal(cond.Options)
					if err := json.Unmarshal(str, c); err != nil {
						return err
					}
				}
				conditions.AddCondition(field, c)
			}

			policy := &ladon.DefaultPolicy{
				ID:          pol.ID,
				Description: pol.Description,
				Subjects:    pol.Principals,
				Effect:      pol.Effect,
				Resources:   pol.Resources,
				Actions:     pol.Actions,
				Conditions:  conditions,
			}
			err := newLadons[config.Service].Manager.Create(policy)
			if err != nil {
				return err
			}
		}
		newConfigs[config.Service] = config
	}
	// Only if everything went well, replace existing services with new ones.
	doorman.services = newConfigs
	doorman.ladons = newLadons
	doorman.jwtValidators = newJWTValidators
	return nil
}

// JWTValidator returns the JWT validator for the specified service.
func (doorman *LadonDoorman) JWTValidator(service string) (authn.JWTValidator, error) {
	v, ok := doorman.jwtValidators[service]
	if !ok {
		return nil, fmt.Errorf("unknown service %q", service)
	}
	return v, nil
}

// IsAllowed is responsible for deciding if subject can perform action on a resource with a context.
func (doorman *LadonDoorman) IsAllowed(service string, request *Request) bool {
	// Instantiate objects from the ladon API.
	context := ladon.Context{}
	for key, value := range request.Context {
		context[key] = value
	}

	r := &ladon.Request{
		Resource: request.Resource,
		Action:   request.Action,
		Context:  context,
	}

	l, ok := doorman.ladons[service]
	if !ok {
		// Explicitly log denied request using audit logger.
		doorman.auditLogger().logRequest(false, r, ladon.Policies{})
		return false
	}

	// For each principal, use it as the subject and query ladon backend.
	for _, principal := range request.Principals {
		r.Subject = principal
		if err := l.IsAllowed(r); err == nil {
			return true
		}
	}
	return false
}

// ExpandPrincipals will match the tags defined in the configuration for this service
// against each of the specified principals.
func (doorman *LadonDoorman) ExpandPrincipals(service string, principals Principals) Principals {
	c, ok := doorman.services[service]
	if !ok {
		return principals
	}

	return append(principals, c.GetTags(principals)...)
}
