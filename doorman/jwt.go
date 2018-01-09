package doorman

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Claims is the set of information we extract from the JWT payload.
type Claims struct {
	Subject  string       `json:"sub,omitempty"`
	Audience jwt.Audience `json:"aud,omitempty"`
	Email    string       `json:"email,omitempty"`
	Groups   []string     `json:"groups,omitempty"`
}

// JWTValidator is the interface in charge of extracting JWT claims from request.
type JWTValidator interface {
	ExtractClaims(*http.Request) (*Claims, error)
}

var jwtValidators map[string]JWTValidator

func init() {
	jwtValidators = map[string]JWTValidator{}
}

// NewJWTValidator instantiates a JWT validator for the specified issuer.
func NewJWTValidator(issuer string) (JWTValidator, error) {
	if !strings.HasPrefix(issuer, "https://") {
		return nil, fmt.Errorf("issuer %q not supported or has bad format", issuer)
	}

	// Reuse JWT validators instances among configs if they are for the same issuer.
	v, ok := jwtValidators[issuer]
	if !ok {
		extractor := DefaultClaimExtractor{}
		if strings.Contains(issuer, "mozilla.auth0.com") {
			extractor = MozillaClaimExtractor{}
		}

		v = &JWTGenericValidator{
			Issuer:         issuer,
			ClaimExtractor: extractor,
		}

		jwtValidators[issuer] = v
	}
	return v, nil
}
