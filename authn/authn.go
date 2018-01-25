// Package authn is in charge authenticating requests.

// Authenticators will be instantiated per identity provider URI.
// Currently only OpenID is supported.
//
// OpenID configuration and keys will be cached.

package authn

import (
	"fmt"
	"net/http"
	"strings"
)

// UserInfo contains the necessary attributes used in Doorman policies.
type UserInfo struct {
	ID     string
	Email  string
	Groups []string
}

// Authenticator is in charge of authenticating requests.
type Authenticator interface {
	ValidateRequest(*http.Request) (*UserInfo, error)
}

var authenticators map[string]Authenticator

func init() {
	authenticators = map[string]Authenticator{}
}

// NewAuthenticator instantiates or reuses an existing one for the specified
// identity provider.
func NewAuthenticator(idP string) (Authenticator, error) {
	if !strings.HasPrefix(idP, "https://") {
		return nil, fmt.Errorf("identify provider %q does not use the https:// scheme", idP)
	}
	// Reuse authenticator instances.
	v, ok := authenticators[idP]
	if !ok {
		// Only OpenID is currently supported.
		v = newOpenIDAuthenticator(idP)
		authenticators[idP] = v
	}
	return v, nil
}
